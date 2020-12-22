local core = require("apisix.core")
 
local plugin_name = "test-plugin"
 
local schema = {
    type = "object",
    properties = {
        content = {
            type = "string"
        }
    }
}
 
local _M = {
    version = 0.2,
    priority = 5000,
    name = plugin_name,
    schema = schema,
}
 
function _M.access(conf, ctx)
    -- 打印日志
    core.log.warn(conf.content)
end
 
return _M