local decs = require "kong.plugins.ice-grpc-gateway.dec"
local ngx = ngx
local kong = kong
local ngx_arg = ngx.arg
local kong_request_get_path = kong.request.get_path
local kong_request_get_method = kong.request.get_method
local kong_request_get_raw_body = kong.request.get_raw_body
local kong_response_exit = kong.response.exit
local kong_response_set_header = kong.response.set_header
local kong_service_request_set_header = kong.service.request.set_header
local kong_service_request_set_method = kong.service.request.set_method
local kong_service_request_set_raw_body = kong.service.request.set_raw_body


local ice_grpc_gateway = {
  PRIORITY = 999,
  VERSION = '0.0.1',
}


local CORS_HEADERS = {
  ["Content-Type"] = "application/json",
  ["Access-Control-Allow-Origin"] = "*",
  ["Access-Control-Allow-Methods"] = "GET,POST,PATCH,DELETE",
  ["Access-Control-Allow-Headers"] = "content-type",
}

function ice_grpc_gateway:access(conf)
  kong_response_set_header("Access-Control-Allow-Origin", "*")

  if kong_request_get_method() == "OPTIONS" then
    return kong_response_exit(200, "OK", CORS_HEADERS)
  end

  local dec, err = decs.new(
    kong_request_get_method():lower(),
    kong_request_get_path(),
    conf.md5,
    conf.proto)

  if not dec then
    kong.log.err(err)
    return kong_response_exit(400, err)
  end
  kong.ctx.plugin.dec = dec

  kong_service_request_set_header("Content-Type", "application/grpc")
  kong_service_request_set_header("TE", "trailers")
  local body, err = dec:upstream(kong_request_get_raw_body())
  if err then
    kong.log.err(err)
    return kong_response_exit(400, err)
  end
  kong_service_request_set_raw_body(body)
  ngx.req.set_uri(dec.rewrite_path)
  kong_service_request_set_method("POST")
end


function ice_grpc_gateway:header_filter(conf)
  if kong_request_get_method() == "OPTIONS" then
    return
  end
  local dec = kong.ctx.plugin.dec
  if dec then
    kong_response_set_header("Content-Type", "application/json")
  end
end


function ice_grpc_gateway:body_filter(conf)
  local dec = kong.ctx.plugin.dec
  if not dec then
    return
  end
  local ret = dec:downstream(ngx_arg[1])
  if not ret or #ret == 0 then
    return
  end
  ngx_arg[1] = ret
end

return ice_grpc_gateway
