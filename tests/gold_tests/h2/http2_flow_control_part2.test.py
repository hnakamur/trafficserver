"""Verify HTTP/2 flow control behavior."""

#  Licensed to the Apache Software Foundation (ASF) under one
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

from http2_flow_control_common import Http2FlowControlTest

Test.Summary = __doc__

Http2FlowControlTest.Test = Test
Http2FlowControlTest.Testers = Testers

test = Http2FlowControlTest(
    description="Flow control policy 0 (default): small initial_window_size",
    initial_window_size=500,  # The default is 65 KB.
    flow_control_policy=0)
test.run()
test = Http2FlowControlTest(
    description="Flow control policy 1: 100 byte session, 10 byte streams",
    max_concurrent_streams=10,
    initial_window_size=10,
    flow_control_policy=1)
test.run()
test = Http2FlowControlTest(
    description="Flow control policy 2: 100 byte session, dynamic streams",
    max_concurrent_streams=10,
    initial_window_size=10,
    flow_control_policy=2)
test.run()
