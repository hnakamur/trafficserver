'''
Test negative cache 201 empty response with negative_caching_enabled=1, in list and allow_empty_doc=0
'''
#  Licensed to the Apache Software Createdation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
Test.Summary = '''
Test negative cache 201 empty response with negative_caching_enabled=1, in list and allow_empty_doc=0
'''

# Needs Curl
Test.SkipUnless(
    Condition.HasProgram("curl", "curl needs to be installed on system for this test to work"),
)
Test.ContinueOnFail = True

# Define default ATS
ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")

#**testname is required**
testName = ""
request_header1 = {"headers": "GET /201 HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header1 = {"headers": "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
server.addResponse("sessionlog.json", request_header1, response_header1)

# ATS Configuration
ts.Disk.plugin_config.AddLine('xdebug.so')
ts.Disk.records_config.update({
    'proxy.config.cache.ram_cache.algorithm': 1,
    'proxy.config.cache.ram_cache.use_seen_filter': 1,
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'http_trans',
    'proxy.config.diags.output.debug': 'L',
    'proxy.config.http.cache.allow_empty_doc': 0,
    'proxy.config.http.cache.http': 1,
    'proxy.config.http.negative_caching_enabled': 1,
    'proxy.config.http.negative_caching_list': '201',
    'proxy.config.http.response_via_str': 'ApacheTrafficServer',
    'proxy.config.http.wait_for_cache': 1,
    'proxy.config.http.insert_age_in_response': 0,
})

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}'.format(server.Variables.Port)
)

# Test 1 - 201 empty response and cache miss
tr = Test.AddTestRun()
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(Test.Processes.ts, ready=1)
tr.Processes.Default.Command = 'curl -s -D - -v --ipv4 --http1.1 -H "x-debug: x-cache,via" -H "Host: www.example.com" http://localhost:{port}/201'.format(port=ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = "gold/non_empty-cache_fill-content_length_0.gold"
tr.StillRunningAfter = ts

# Test 2 - 201 empty response and cache miss
tr = Test.AddTestRun()
tr.Processes.Default.Command = 'curl -s -D - -v --ipv4 --http1.1 -H "x-debug: x-cache,via" -H "Host: www.example.com" http://localhost:{port}/201'.format(port=ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = "gold/non_empty-cache_fill-content_length_0.gold"
tr.StillRunningAfter = ts

# Test 3 - 201 empty response and cache miss
tr = Test.AddTestRun()
tr.Processes.Default.Command = 'curl -s -D - -v --ipv4 --http1.1 -H "x-debug: x-cache,via" -H "Host: www.example.com" http://localhost:{port}/201'.format(port=ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = "gold/non_empty-cache_fill-content_length_0.gold"
tr.StillRunningAfter = ts
