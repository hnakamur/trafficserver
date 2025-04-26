'''
Verify remap.config acl behavior.
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
# #      http://www.apache.org/licenses/LICENSE-2.0 #
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
import re
import sys
from collections import defaultdict
from typing import List, Mapping, Tuple, TypedDict

Test.Summary = '''
Verify remap.config acl behavior.
'''

TS_PID_SCRIPT = 'ts_process_handler.py'
Test.Setup.CopyAs(os.path.join("../logging", TS_PID_SCRIPT), Test.RunDirectory)


class Remap_acl_play(TypedDict):
    """Test play attributes

    Attributes:
        play_id: The id of the play.
        name: The name of the test case.
        replay_file: The replay file to be used.
        deactivate_ip_allow: Whether to deactivate the ip_allow filter.
        acl_configuration: The ACL configuration to be used.
        named_acls: The set of named ACLs to configure and use.
        expect_responses: The in-order expected responses from the proxy.
        get_proxy_response_status: The proxy response status code of the GET request (only set for base.replay.yaml).
        post_proxy_response_status: The proxy response status code of the POST request (only set for base.replay.yaml).
    """
    play_id: int
    name: str
    replay_file: str
    deactivate_ip_allow: bool
    acl_configuration: str
    named_acls: List[Tuple[str, str]]
    expected_responses: List[int]
    get_proxy_response_status: int
    post_proxy_response_status: int


class Test_remap_acl_multi:
    """Configure a test to verify remap.config acl behavior with multiple mappings."""

    _test_counter: int = -1
    _max_requests_in_replay_file: int = 10
    _log_flush_seconds: int = 1

    def __init__(self, name: str, acl_behavior_policy: int, ip_allow_content: str, play_list: List[Remap_acl_play]):
        """Initialize the test.

        :param name: The name of the test.
        :param name: The acl behavior policy.
        :param ip_allow_content: The ip_allow configuration to be used.
        :param play_list: The list of test plays.
        """
        self._acl_behavior_policy = acl_behavior_policy
        self._ip_allow_content = ip_allow_content
        self._play_list = play_list
        Test_remap_acl_multi._test_counter += 1

        self._uuids_list = self._generate_client_request_uuids_list(play_list)
        tr = Test.AddTestRun(name)
        self._configure_server(tr)
        self._configure_traffic_server(tr)
        self._configure_client(tr)

    def _generate_client_request_uuids_list(self, play_list: int) -> List[Mapping[str, str]]:
        return [
            {
                "client_request_uuid_get": f"{play['play_id']}-get",
                "client_request_uuid_head": f"{play['play_id']}-head",
                "client_request_uuid_post": f"{play['play_id']}-post",
                "client_request_uuid_put": f"{play['play_id']}-put",
                "client_request_uuid_delete": f"{play['play_id']}-delete",
                "client_request_uuid_push": f"{play['play_id']}-push",
            } for play in play_list
        ]

    def _configure_server(self, tr: 'TestRun') -> None:
        """Configure the server.

        :param tr: The TestRun object to associate the server process with.
        """
        name = f"server-{Test_remap_acl_multi._test_counter}"
        replay_path_with_context_list = [
            {
                "replay_file": play["replay_file"],
                "context":
                    {
                        **uuids, "url_prefix": "",
                        "play_id": play["play_id"],
                        "get_proxy_response_status": play.get("get_proxy_response_status"),
                        "post_proxy_response_status": play.get("post_proxy_response_status")
                    }
            } for uuids, play in zip(self._uuids_list, self._play_list)
        ]
        server = tr.AddVerifierServerProcess(name, None, replay_path_with_context_list=replay_path_with_context_list)
        self._server = server

    def _configure_traffic_server(self, tr: 'TestRun') -> None:
        """Configure Traffic Server.

        :param tr: The TestRun object to associate the Traffic Server process with.
        """

        name = f"ts-{Test_remap_acl_multi._test_counter}"
        ts = tr.MakeATSProcess(name, enable_cache=False, enable_tls=True)
        self._ts = ts
        self._ts_name = name

        ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http|url|remap|ip_allow',
                'proxy.config.http.push_method_enabled': 1,
                'proxy.config.http.connect_ports': self._server.Variables.http_port,
                'proxy.config.url_remap.acl_behavior_policy': self._acl_behavior_policy,
                # flush log files every second.
                'proxy.config.log.max_secs_per_buffer': Test_remap_acl_multi._log_flush_seconds,
                'proxy.config.log.periodic_tasks_interval': Test_remap_acl_multi._log_flush_seconds,
            })

        self.diags_log = self._ts.Disk.diags_log.AbsPath
        self.traffic_out = self._ts.Disk.traffic_out.AbsPath

        remap_config_lines = []
        for i, play in enumerate(self._play_list):
            if play["deactivate_ip_allow"]:
                remap_config_lines.append('.deactivatefilter ip_allow')

            # First, define the name ACLs (filters).
            for name, definition in play["named_acls"]:
                remap_config_lines.append(f'.definefilter {name} {definition}')
            # Now activate them.
            for name, _ in play["named_acls"]:
                remap_config_lines.append(f'.activatefilter {name}')

            play_id = play["play_id"]
            url_prefix = f"/{play_id}"
            remap_config_lines.append(
                f'map http://example.com{url_prefix}/ http://127.0.0.1:{self._server.Variables.http_port} {play["acl_configuration"]}'
            )

            if i < len(self._play_list) - 1:
                for name, _ in play["named_acls"]:
                    remap_config_lines.append(f'.deactivatefilter {name}')
                if play["deactivate_ip_allow"]:
                    remap_config_lines.append('.activatefilter ip_allow')

        ts.Disk.remap_config.AddLines(remap_config_lines)
        ts.Disk.ip_allow_yaml.AddLines(self._ip_allow_content.split("\n"))

    def _configure_client(self, tr: 'TestRun') -> None:
        """Run the test.

        :param tr: The TestRun object to associate the client process with.
        """

        client_ready = None
        for i, uuids in enumerate(self._uuids_list):
            send_pkill_ready = None
            if i > 0:
                # Configure our rotation processes.
                rotated_diags_log = self.diags_log + f".{i - 1}"
                rotate_diags_log = tr.Processes.Process(
                    f"rotate_diags_log_{Test_remap_acl_multi._test_counter}_{i}",
                    "mv {} {}".format(self.diags_log, rotated_diags_log))
                rotate_diags_log.ReturnCode = 0
                rotate_diags_log.StartBefore(client_ready, ready=Test_remap_acl_multi._log_flush_seconds + 0.1)

                send_pkill = tr.Processes.Process(
                    f"Send_SIGUSR2-{Test_remap_acl_multi._test_counter}-{i}", self.get_sigusr2_signal_command())
                send_pkill.StartBefore(rotate_diags_log)

                send_pkill_ready = tr.Processes.Process(f"send_pkill_ready-{Test_remap_acl_multi._test_counter}-{i}", 'sleep 30')
                send_pkill_ready.StartupTimeout = 30
                send_pkill_ready.Ready = When.FileExists(self.diags_log)
                send_pkill_ready.StartBefore(send_pkill)

            name = f"client-{Test_remap_acl_multi._test_counter}-{i}"
            play = self._play_list[i]
            play_id = play["play_id"]
            url_prefix = f"/{play_id}"
            context = {
                **uuids, "url_prefix": url_prefix,
                "play_id": play_id,
                "get_proxy_response_status": play.get("get_proxy_response_status"),
                "post_proxy_response_status": play.get("post_proxy_response_status")
            }
            replay_path = play["replay_file"]
            p = tr.AddVerifierClientProcess(name, replay_path, http_ports=[self._ts.Variables.port], context=context, default=False)
            if i == 0:
                p.StartBefore(self._server)
                p.StartBefore(self._ts)
            else:
                p.StartBefore(send_pkill_ready)

            client_ready = tr.Processes.Process(f"client_ready-{Test_remap_acl_multi._test_counter}-{i}", 'sleep 30')
            client_ready.StartBefore(p)
            # In the autest environment, it can take more than 10 seconds for the log file to be created.
            client_ready.StartupTimeout = 30

            expected_responses = play["expected_responses"]
            if expected_responses == [None, None]:
                # If there are no expected responses, expect the Warning about the rejected ip.
                self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
                    "client '127.0.0.1' prohibited by ip-allow policy", "Verify the client rejection warning message.")

                # Also, the client will complain about the broken connections.
                p.ReturnCode = 1

                client_ready.Ready = When.FileContains(self.diags_log, "client '127.0.0.1' prohibited by ip-allow policy")
            else:
                codes = [str(code) for code in expected_responses]
                p.Streams.stdout += Testers.ContainsExpression(
                    '.*'.join(codes), "Verifying the expected order of responses", reflags=re.DOTALL | re.MULTILINE)
                client_ready.Ready = When.FileContains(self.traffic_out, f"{url_prefix}/test/ip_allow/")

        tr.Processes.Default.Command = "echo waiting for test processes to be done"
        tr.Processes.Default.Return = 0
        tr.Processes.Default.StartBefore(client_ready)

    def get_sigusr2_signal_command(self):
        """
        Return the command that will send a USR2 signal to the traffic server
        process.
        """
        return (f"{sys.executable} {TS_PID_SCRIPT} "
                f"--signal SIGUSR2 {self._ts_name}")


class Test_old_action:
    _ts_counter: int = 0

    def __init__(self, name: str, acl_filter: str, ip_allow_content: str) -> None:
        '''Test that ATS fails with a FATAL message if an old action is used with modern ACL filter policy.

        :param name: The name of the test run.
        :param acl_filter: The ACL filter to use.
        :param ip_allow_content: The ip_allow configuration to use.
        '''

        tr = Test.AddTestRun(name)
        ts = self._configure_traffic_server(tr, acl_filter, ip_allow_content)

    def _configure_traffic_server(self, tr: 'TestRun', acl_filter: str, ip_allow_content: str) -> 'Process':
        '''Configure Traffic Server process

        :param tr: The TestRun object to associate the Traffic Server process with.
        :param acl_filter: The ACL filter to configure in remap.config.
        :param ip_allow_content: The ip_allow configuration to use.
        :return: The Traffic Server process.
        '''
        name = f"ts-old-action-{Test_old_action._ts_counter}"
        Test_old_action._ts_counter += 1
        ts = tr.MakeATSProcess(name)
        self._ts = ts

        ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http|url|remap|ip_allow',
                'proxy.config.url_remap.acl_behavior_policy': 1,
            })

        ts.Disk.remap_config.AddLine(f'map / http://127.0.0.1:8080 {acl_filter}')
        if ip_allow_content:
            ts.Disk.ip_allow_yaml.AddLines(ip_allow_content.split("\n"))

        if acl_filter != '':
            expected_error = '"allow" and "deny" are no longer valid.'
        else:
            expected_error = 'Legacy action name of'

        # We have to wait upon TS to emit the expected log message, but it cannot be
        # the ts Ready criteria because autest might detect the process going away
        # before it detects the log message. So we add a separate process that waits
        # upon the log message.
        watcher = tr.Processes.Process("watcher")
        watcher.Command = "sleep 10"
        watcher.Ready = When.FileContains(ts.Disk.diags_log.Name, expected_error)
        watcher.StartBefore(ts)

        tr.Processes.Default.Command = 'printf "Fatal Shutdown Test"'
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.StartBefore(watcher)

        tr.Timeout = 5
        ts.ReturnCode = Any(33, 70)
        ts.Ready = 0
        ts.Disk.diags_log.Content = Testers.IncludesExpression(expected_error, 'ATS should fatal with the old actions.')

        return ts


IP_ALLOW_OLD_ACTION = f'''
ip_categories:
  - name: ACME_LOCAL
    ip_addrs: 127.0.0.1
  - name: ACME_EXTERNAL
    ip_addrs: 5.6.7.8

ip_allow:
  - apply: in
    ip_addrs: 0/0
    action: allow
    methods:
      - GET
'''

IP_ALLOW_CONTENT = f'''
ip_categories:
  - name: ACME_LOCAL
    ip_addrs: 127.0.0.1
  - name: ACME_EXTERNAL
    ip_addrs: 5.6.7.8

ip_allow:
  - apply: in
    ip_addrs: 0/0
    action: set_allow
    methods:
      - GET
'''

Test_old_action("Verify allow is reject in modern policy", "@action=allow @method=GET", IP_ALLOW_CONTENT)
Test_old_action("Verify deny is reject in modern policy", "@action=deny @method=GET", IP_ALLOW_CONTENT)
Test_old_action("Verify deny is reject in modern policy", "", IP_ALLOW_OLD_ACTION)

Test_remap_acl_multi(
    "test_ip_allow_optional_methods",
    acl_behavior_policy=1,
    ip_allow_content=IP_ALLOW_CONTENT,
    play_list=[
        {
            "play_id": 0,
            "name": "Verify non-allowed methods are blocked.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip=127.0.0.1 @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 1,
            "name": "Verify add_allow adds an allowed method.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=add_allow @src_ip=127.0.0.1 @method=POST',
            "named_acls": [],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 2,
            "name": "Verify add_allow adds allowed methods.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=add_allow @src_ip=127.0.0.1 @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 3,
            "name": "Verify if no ACLs match, ip_allow.yaml is used.",
            "replay_file": 'remap_acl_get_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip=1.2.3.4 @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [200, 403, 403, 403, 403]
        },
        {
            "play_id": 4,
            "name": "Verify @src_ip=all works.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip=all @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 5,
            "name": "Verify @src_ip_category works.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip_category=ACME_LOCAL @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 6,
            "name": "Verify no @src_ip implies all IP addresses.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 7,
            "name": "Verify denied methods are blocked.",
            "replay_file": 'remap_acl_get_post_denied.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_deny @src_ip=127.0.0.1 @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [403, 403, 200, 200, 400]
        },
        {
            "play_id": 8,
            "name": "Verify add_deny adds blocked methods.",
            "replay_file": 'remap_acl_all_denied.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=add_deny @src_ip=127.0.0.1 @method=GET',
            "named_acls": [],
            "expected_responses": [403, 403, 403, 403, 403]
        },
        {
            "play_id": 9,
            "name": "Verify a default deny filter rule works.",
            "replay_file": 'remap_acl_all_denied.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip=1.2.3.4 @method=GET @method=POST',
            "named_acls": [('deny9', '@action=set_deny')],
            "expected_responses": [403, 403, 403, 403, 403]
        },
        {
            "play_id": 10,
            "name": "Verify inverting @src_ip works.",
            "replay_file": 'remap_acl_all_denied.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip=~127.0.0.1 @method=GET @method=POST',
            "named_acls": [('deny10', '@action=set_deny')],
            "expected_responses": [403, 403, 403, 403, 403]
        },
        {
            "play_id": 11,
            "name": "Verify inverting @src_ip works with the rule matching.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip=~3.4.5.6 @method=GET @method=POST',
            "named_acls": [('deny11', '@action=set_deny')],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 12,
            "name": "Verify inverting @src_ip_category works.",
            "replay_file": 'remap_acl_all_denied.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip_category=~ACME_LOCAL @method=GET @method=POST',
            "named_acls": [('deny12', '@action=set_deny')],
            "expected_responses": [403, 403, 403, 403, 403]
        },
        {
            "play_id": 13,
            "name": "Verify inverting @src_ip_category works with the rule matching.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip_category=~ACME_EXTERNAL @method=GET @method=POST',
            "named_acls": [('deny13', '@action=set_deny')],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 14,
            "name": "Verify @src_ip and @src_ip_category AND together.",
            "replay_file": 'remap_acl_all_denied.replay.yaml',
            "deactivate_ip_allow": False,
            # The rule will not match because, while @src_ip matches, @src_ip_category does not.
            "acl_configuration": '@action=set_allow @src_ip=127.0.0.1 @src_ip_category=ACME_EXTERNAL @method=GET @method=POST',
            # Therefore, this named deny filter will block.
            "named_acls": [('deny14', '@action=set_deny')],
            "expected_responses": [403, 403, 403, 403, 403]
        },
        {
            "play_id": 15,
            "name": "Verify defined in-line ACLS are evaluated before named ones.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip=127.0.0.1 @method=GET @method=POST',
            "named_acls": [('deny15', '@action=set_deny')],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 16,
            "name": "Verify remap.config line overrides ip_allow rule.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip=127.0.0.1 @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 17,
            "name": "Verify in_ip matches on IP as expected.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @in_ip=127.0.0.1 @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [200, 200, 403, 403, 403]
        },
        {
            "play_id": 18,
            "name": "Verify we can deactivate the ip_allow filter.",
            "replay_file": 'remap_acl_all_allowed.replay.yaml',
            "deactivate_ip_allow": True,
            # This won't match, so nothing will match since ip_allow.yaml is off.
            "acl_configuration": '@action=set_allow @src_ip=1.2.3.4 @method=GET @method=POST',
            "named_acls": [],
            # Nothing will block the request since ip_allow.yaml is off.
            "expected_responses": [200, 200, 200, 200, 400]
        },
        {
            "play_id": 19,
            "name": "Verify in_ip rules do not match on other IPs.",
            "replay_file": 'remap_acl_get_allowed.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @in_ip=3.4.5.6 @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [200, 403, 403, 403, 403]
        },
        {
            "play_id": 20,
            "name": "Verify a named ACL is applied if an in-line ACL is absent.",
            "replay_file": 'deny_head_post.replay.yaml',
            "deactivate_ip_allow": False,
            "acl_configuration": '',
            "named_acls": [('deny20', '@action=set_deny @method=HEAD @method=POST')],
            "expected_responses": [200, 403, 403, 403]
        }
    ])

from all_acl_combinations import all_acl_combination_tests
"""
Test all acl combinations
"""
grouped_all_acl_combination_tests = defaultdict(list)
for test in all_acl_combination_tests:
    key = (test["ip_allow"], test["policy"])
    grouped_all_acl_combination_tests[key].append(test)

for (ip_allow, policy), group in grouped_all_acl_combination_tests.items():
    play_list = [
        {
            "play_id": test["index"],
            "name": f"play{test['index']}",
            "replay_file": "base.replay.yaml",
            "deactivate_ip_allow": False,
            "acl_configuration": test["inline"],
            "named_acls": [(f"acl{test['index']}", test["named_acl"])] if test["named_acl"] != "" else [],
            "expected_responses": [test["GET response"], test["POST response"]],
            "get_proxy_response_status": 403 if test["GET response"] == None else test["GET response"],
            "post_proxy_response_status": 403 if test["POST response"] == None else test["POST response"],
        } for test in group
    ]
    Test_remap_acl_multi(
        f"allcombo-group-{policy} {ip_allow}",
        acl_behavior_policy=0 if policy == "legacy" else 1,
        ip_allow_content=ip_allow,
        play_list=play_list)

from deactivate_ip_allow import all_deactivate_ip_allow_tests
"""
Test all ACL combinations
"""
grouped_all_deactivate_ip_allow_tests = defaultdict(list)
for test in all_deactivate_ip_allow_tests:
    key = (test["ip_allow"], test["policy"])
    grouped_all_deactivate_ip_allow_tests[key].append(test)

for (ip_allow, policy), group in grouped_all_deactivate_ip_allow_tests.items():
    play_list = [
        {
            "play_id": test["index"],
            "name": f"play{test['index']}",
            "replay_file": "base.replay.yaml",
            "deactivate_ip_allow": test["deactivate_ip_allow"],
            "acl_configuration": test["inline"],
            "named_acls": [(f"acl{test['index']}", test["named_acl"])] if test["named_acl"] != "" else [],
            "expected_responses": [test["GET response"], test["POST response"]],
            "get_proxy_response_status": 403 if test["GET response"] == None else test["GET response"],
            "post_proxy_response_status": 403 if test["POST response"] == None else test["POST response"],
        } for test in group
    ]

    play_list_with_acl = [play for play in play_list if play["expected_responses"] != [None, None]]
    Test_remap_acl_multi(
        f"ipallow-group-{policy} {ip_allow} with acl",
        acl_behavior_policy=0 if policy == "legacy" else 1,
        ip_allow_content=ip_allow,
        play_list=play_list_with_acl)

    play_list_without_acl = [play for play in play_list if play["expected_responses"] == [None, None]]
    for i, play in enumerate(play_list_without_acl):
        Test_remap_acl_multi(
            f"ipallow-group-{policy} {ip_allow} without acl {i}",
            acl_behavior_policy=0 if policy == "legacy" else 1,
            ip_allow_content=ip_allow,
            play_list=[play])
