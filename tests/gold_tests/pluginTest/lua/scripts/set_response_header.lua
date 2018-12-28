function do_global_send_response()
  local cc = ts.client_response.header['Cache-Control']
  cc = string.gsub(cc, "60", "120")
  ts.client_response.header['Cache-Control'] = cc
  return 0
end
