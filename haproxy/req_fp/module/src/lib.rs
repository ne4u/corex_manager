use mlua::prelude::*;

#[mlua::lua_module(skip_memory_check)]
fn haproxy_req_fp_module(lua: &Lua) -> LuaResult<LuaTable> {
    let table = lua.create_table()?;
    table.set(
        "register",
        lua.create_function(|lua, _: ()| haproxy_req_fp::register(lua))?,
    )?;
    Ok(table)
}
