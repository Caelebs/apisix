--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

local core                    = require("apisix.core")
local http                    = require "resty.http"
local sub_str                 = string.sub
local url                     = require "net.url"
local tostring                = tostring
local ngx                     = ngx
local plugin_name             = "auth-aams"
local err_msg_miss_user_id    = "user id does not exist in the header"
local err_msg_miss_tenant_id  = "tenant id does not exist in the header"
local err_msg_miss_auth_token = "authorization token does not exist in the header"
local err_msg_miss_method     = "The request method was not obtained in the request"
local err_msg_miss_uri        = "The request URI was not obtained in the request"

local schema = {
    type = "object",
    properties = {
        http_timeout = {type = "integer", minimum = 1000, default = 3000},
        aams_authentication_address = {
            type      = "string",
            default   = "http://10.10.17.16:30517/itps/aams/userManage/checkSecurityPermission",
            minLength = 1,
            maxLength = 4096
        },
    },
    required = {"aams_authentication_address"}
}

local _M = {
    version  = 1.0,
    priority = 2510, -- 优先级（ priority 属性 ）不能与现有插件的优先级相同。另外，优先级( priority )值大的插件，会优先执行
    name     = plugin_name,
    schema   = schema,
}

-- 配置参数的合法性校验
-- 项目已经提供了 core.schema.check 公共方法，直接使用即可完成配置参数校验
function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

local function authority_authentication(conf, userId, Tenant, Token, req_method, req_uri)
    local url_decoded = url.parse(conf.aams_authentication_address)
    local host = url_decoded.host
    local port = url_decoded.port
    core.log.debug("4A authentication_address -> ", url_decoded, 
                    " && request_uri -> ", req_uri,
                    " && request_method -> ", req_method,
                    " && TenantID -> ", Tenant, 
                    " && userId -> ", userId,
                    " && authToken -> ", Token)
    if not port then
        if url_decoded.scheme == "https" then
            port = 443
        else
            port = 80
        end
    end
    local httpc = http.new()
    httpc:set_timeout(conf.timeout)
    local params = {
        method = "POST",
        headers = {
            ["Content-Type"]  = "application/json",
            ["Authorization"] = Token,
            ["s-user-id"]     = userId,
            ["s-tenant-id"]   = Tenant,
            ["url"]           = req_uri,
            ["method"]        = req_method
        }
    }
    local aams_response, aams_err = httpc:request_uri(conf.aams_authentication_address, params)
    if not aams_response then
        core.log.error("Error while sending 4A request to [", host ,"] port[", tostring(port), "] ", aams_err)
        return 500, aams_err
    end
    if aams_response.status >= 400 then
        core.log.error("4A response.status.code -> ", aams_response.status, " | msg -> ", aams_response.body)
        if aams_response.status == 500 then
            return 503, aams_response.body
        else
            return aams_response.status, aams_response.body
        end
    end
    if aams_response.status == 200 then
        core.log.info("4A authentication service call successfully, response.status.code = 200")
        return aams_response.status, aams_response.body
    end

end

local function parsing_header(ctx)
    local userId     = core.request.header(ctx, "s-user-id")
    local Tenant     = core.request.header(ctx, "s-tenant-id")
    local authToken  = core.request.header(ctx, "Authorization")
    local req_method = ctx.var.request_method
    local req_uri    = ctx.var.request_uri
    return userId, Tenant, authToken, req_method, req_uri
end

local function is_path_protected(conf)
    if conf.permissions == nil then
        return false
    end
    return true
end

function _M.access(conf, ctx)
    core.log.debug("Enter the aams-auth process")
    local userId, Tenant, Token, req_method, req_uri, err = parsing_header(ctx)
    if not userId then
        core.log.error(err_msg_miss_user_id)
        return 401, { message = err_msg_miss_user_id }
    end
    if not Tenant then
        core.log.error(err_msg_miss_tenant_id)
        return 401, { message = err_msg_miss_tenant_id }
    end
    if not Token then
        core.log.error(err_msg_miss_auth_token)
        return 401, { message = err_msg_miss_auth_token }
    end
    if not req_method then
        core.log.error(err_msg_miss_method)
        return 500, { message = err_msg_miss_method }
    end
    if not req_uri then
        core.log.error(err_msg_miss_uri)
        return 500, { message = err_msg_miss_uri }
    end
    core.log.debug("All parameters are normal, Call 4A authority authentication")
    local status, body = authority_authentication(conf, userId, Tenant, Token, req_method, req_uri)
    if status then
        core.log.debug("4A authentication service response status code -> ", status)
        if status >= 400 then
            return status, { message = "4A service is not available." }
        end
        local aams_rt = core.json.decode(body)
        if aams_rt.code == 201 then
            core.log.warn("4A Authentication failed, apisix routing failed")
            return status, aams_rt
        end
        if aams_rt.code >= 400 then
            core.log.error("4A Authentication failed, apisix routing failed")
            return status, aams_rt
        end
        if aams_rt.code == 200 then
            core.log.info("4A Authentication passed, apisix routing allowed")
        end
    end

end

return _M
