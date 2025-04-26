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

#
# Default configuration.
#
test = Http2FlowControlTest("Default Configurations")
test.run()

#
# Configuring max_concurrent_streams_(in|out).
#
test = Http2FlowControlTest(description="Configure max_concurrent_streams", max_concurrent_streams=53)
test.run()

#
# Configuring initial_window_size.
#
test = Http2FlowControlTest(description="Configure a larger initial_window_size_(in|out)", initial_window_size=100123)
test.run()

#
# Configuring flow_control_policy.
#
test = Http2FlowControlTest(description="Configure an unrecognized flow_control.in.policy", flow_control_policy=23)
test.run()
