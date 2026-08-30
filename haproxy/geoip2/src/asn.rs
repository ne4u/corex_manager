use std::net::IpAddr;

use maxminddb::geoip2::Asn;
use mlua::prelude::{IntoLua, Lua, LuaValue};

use crate::db::Database;
use crate::GeoValue;

// Global maxmind ASN database shared between all workers
pub(crate) static DB: Database = Database::new();

pub(crate) fn lookup<'a>(lua: &'a Lua, ip: IpAddr, props: &[String]) -> Option<LuaValue> {
    DB.check_status(lua);

    let db = DB.load();
    let reader = db.as_ref()?;
    let asn = reader.lookup::<Asn>(ip).ok().flatten()?;
    lookup_asn(&asn, props).and_then(|v| v.into_lua(lua).ok())
}

fn lookup_asn<'a>(asn: &'a Asn, props: &[String]) -> Option<GeoValue<'a>> {
    match props.get(0)?.as_str() {
        "autonomous_system_number" | "asn" => {
            if let Some(number) = asn.autonomous_system_number {
                // Return ASN with the conventional "AS" prefix (e.g. AS17858)
                // so it matches the format used by dynamic ASN feeds and the
                // Security Lists ASN validation/normalization.
                return Some(GeoValue::String(format!("AS{number}")));
            }
        }
        "autonomous_system_organization" => {
            if let Some(org) = asn.autonomous_system_organization {
                return Some(GeoValue::Str(org));
            }
        }
        _ => {}
    }
    None
}
