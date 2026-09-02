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

    // Use lookup_prefix instead of lookup so we can return the network CIDR
    // (derived from the matched prefix length) when "network" is requested.
    let (asn_opt, prefix_len) = reader.lookup_prefix::<Asn>(ip).ok()?;
    let asn = asn_opt?;

    // "network" is derived from the lookup prefix, not the ASN record itself.
    if props.get(0).map(|s| s.as_str()) == Some("network") {
        return compute_network(ip, prefix_len).and_then(|v| v.into_lua(lua).ok());
    }

    lookup_asn(&asn, props).and_then(|v| v.into_lua(lua).ok())
}

/// Compute the network CIDR (e.g. "74.7.242.0/24") from the looked-up IP and
/// the prefix length returned by `lookup_prefix`. The MaxMind ASN database
/// doesn't store the network in the record — it's the IP prefix that matched
/// during the tree traversal.
fn compute_network(ip: IpAddr, prefix_len: usize) -> Option<GeoValue<'static>> {
    let prefix = prefix_len.min(128) as u8;
    let network = ipnetwork::IpNetwork::new(ip, prefix).ok()?;
    Some(GeoValue::String(network.to_string()))
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
