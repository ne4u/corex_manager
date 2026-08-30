use mlua::prelude::*;

#[mlua::lua_module(skip_memory_check)]
fn haproxy_resp_transform_module(lua: &Lua) -> LuaResult<LuaTable> {
    let table = lua.create_table()?;
    table.set("register", lua.create_function(haproxy_resp_transform::register)?)?;
    Ok(table)
}
