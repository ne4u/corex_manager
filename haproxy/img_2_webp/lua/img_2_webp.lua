-- Loader for the haproxy-img-2-webp Rust Lua module.
-- Loaded via the combined modules.lua loader (lua-load-per-thread) when
-- image conversion is enabled in Global Options. Registers the
-- `lua.img_2_webp` filter.
local ok, img_2_webp = pcall(require, "haproxy_img_2_webp_module")
if not ok then
    core.Alert("img_2_webp.lua: failed to load Rust module: " .. tostring(img_2_webp))
    return false
end

local rok, rerr = pcall(img_2_webp.register)
if not rok then
    core.Alert("img_2_webp.lua: filter register failed: " .. tostring(rerr))
    return false
end

return true
