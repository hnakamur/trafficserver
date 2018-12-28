function do_global_send_response()
  ts.client_response.header['X-Get-Header'] = ts.client_response.header['Cache-Control']
  return 0
end
