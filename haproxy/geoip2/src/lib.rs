use std::net::IpAddr;

use haproxy_api::Core;
use mlua::prelude::{IntoLua, Lua, LuaFunction, LuaResult, LuaTable, LuaValue};
use mlua::{ExternalError, Variadic};

#[derive(Debug, Clone)]
pub(crate) enum GeoValue<'a> {
    Str(&'a str),
    String(String),
    Float(f64),
    UInt(u32),
    Bool(bool),
}

impl IntoLua for GeoValue<'_> {
    fn into_lua(self, lua: &Lua) -> LuaResult<LuaValue> {
        match self {
            GeoValue::Str(s) => s.into_lua(lua),
            GeoValue::String(s) => s.into_lua(lua),
            GeoValue::Float(f) => f.into_lua(lua),
            GeoValue::UInt(u) => u.into_lua(lua),
            GeoValue::Bool(b) => b.into_lua(lua),
        }
    }
}

/// Register GeoIP2 lookups in the haproxy
///
/// This function registers the GeoIP2 lookups converters in the haproxy Lua environment,
/// including task to reload the databases at a given interval.
///
/// The following Lua options are supported:
///
/// - `reload_interval`: Interval in seconds to reload the databases. Default is 0.
/// - `db.city`: Path to the MaxMind GeoIP2 City database.
/// - `db.asn`: Path to the MaxMind GeoIP2 ASN database.
///
/// # Example
/// ```lua
/// geoip2.register({
///    reload_interval = 86400, -- 1 day
///    db = {
///        city = "/path/to/GeoLite2-City.mmdb",
///         asn = "/path/to/GeoLite2-ASN.mmdb",
///     },
/// })
/// ```
pub fn register(lua: &Lua, options: LuaTable) -> LuaResult<()> {
    let core = Core::new(lua)?;

    // Parse options
    let reload_interval: u64 = options.get("reload_interval").unwrap_or(0);

    // Register databases
    if let Ok(db) = options.get::<LuaTable>("db") {
        if let Ok(path) = db.get::<String>("city") {
            city::DB.configure(path.into(), reload_interval);
            register_converter(&core, &city::DB, "city", city::lookup)?;
        }

        if let Ok(asn_path) = db.get::<String>("asn") {
            asn::DB.configure(asn_path.into(), reload_interval);
            register_converter(&core, &asn::DB, "asn", asn::lookup)?;
        }
    }

    Ok(())
}

// `F` is zero-sized, so it's safe to send it across threads
fn register_converter<F>(
    core: &Core,
    db: &'static db::Database,
    prefix: &str,
    lookup: F,
) -> LuaResult<()>
where
    F: Fn(&Lua, IpAddr, &[String]) -> Option<LuaValue> + Send + Copy + 'static,
{
    // Trigger dummy lookup within a worker to load the database
    core.register_task(move |lua| {
        lookup(lua, "0.0.0.0".parse()?, &[]);
        Ok(())
    })?;

    // Register reload task
    let interval = db.reload_interval();
    if interval > 0 {
        let trigger_reload = LuaFunction::wrap(|| {
            db.trigger_reload();
            Ok(())
        });
        core.register_lua_task(mlua::chunk! {
            if core.thread <= 1 then
                while true do
                    core.sleep($interval)
                    $trigger_reload()
                end
            end
        })?;
    }

    core.register_converters(
        &format!("geoip2-lookup-{prefix}"),
        move |lua, (ip, props): (LuaValue, Variadic<LuaValue>)| {
            // HAProxy passes IP-typed samples (from `src`, `ci`, etc.) as non-string
            // Lua values. Coerce to string so both literal strings and IP samples work.
            let ip_str = lua.coerce_string(ip)
                .map_err(|e| e.into_lua_err())?
                .ok_or_else(|| "geoip2: input is not coercible to string".into_lua_err())?;
            let ip = ip_str.to_str()?.parse::<IpAddr>()?;
            // HAProxy may pass converter args with literal surrounding quotes
            // (e.g. "country" instead of country). Strip them so lookups match.
            let props: Vec<String> = props
                .into_iter()
                .filter_map(|v| lua.coerce_string(v).ok().flatten())
                .filter_map(|s| s.to_str().ok().map(|v| {
                    let v = v.trim();
                    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                        v[1..v.len() - 1].to_owned()
                    } else {
                        v.to_owned()
                    }
                }))
                .collect();
            lookup(lua, ip, &props).map_or_else(|| "".into_lua(lua), Ok)
        },
    )
}

mod asn;
mod city;
mod db;
