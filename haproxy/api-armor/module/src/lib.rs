//! HAProxy API Armor module — combined cdylib entry point.
//!
//! This crate produces the `haproxy_api_armor_module.so` cdylib that is
//! loaded by the combined modules.lua loader. It re-exports the `register`
//! functions from all four API Armor sub-crates (body_parser, schema_validator,
//! jwt_validator) so they can be called from a single Lua state.

use mlua::prelude::*;

/// Lua module entry point.
/// Returns a table with a `register` function that the combined loader calls.
#[mlua::lua_module(skip_memory_check)]
fn haproxy_api_armor_module(lua: &Lua) -> LuaResult<LuaTable> {
    let table = lua.create_table()?;

    // The register function is called from modules.lua after require().
    // It registers all API Armor Lua functions (api_body_parse, etc.) into
    // the global scope.
    table.set(
        "register",
        lua.create_function(|lua, _: ()| {
            // Register body_parser (includes GraphQL analysis via api-armor-graphql)
            // The body_parser also calls schema_validator and jwt_validator
            // internally for each request.
            api_armor_body_parser::register(lua)?;
            // Register jwt_validator (Phase 4 — currently a no-op)
            api_armor_jwt_validator::register(lua)?;
            Ok(())
        })?,
    )?;

    Ok(table)
}
