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
import io
import re
import inspect
import tempfile
import uuid
import sys
from yaml import load, dump
from yaml import CLoader as Loader
from typing import List, Mapping, Tuple, TypedDict

import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

Test.Summary = '''
Verify remap.config acl behavior.
'''

TS_PID_SCRIPT = 'ts_process_handler.py'
Test.Setup.CopyAs(os.path.join("../logging", TS_PID_SCRIPT), Test.RunDirectory)


class Remap_acl_test_case(TypedDict):
    """Test case config

    Attributes:
        name: The name of the test case.
        replay_file: The replay file to be used.
        ip_allow_content: The ip_allow configuration to be used.
        deactivate_ip_allow: Whether to deactivate the ip_allow filter.
        acl_configuration: The ACL configuration to be used.
        named_acls: The set of named ACLs to configure and use.
        expect_responses: The in-order expected responses from the proxy.        
    """
    name: str
    replay_file: str
    ip_allow_content: str
    deactivate_ip_allow: bool
    acl_configuration: str
    named_acls: List[Tuple[str, str]]
    expected_responses: List[int]


class Test_remap_acl_multi_map:
    """Configure a test to verify remap.config acl behavior with multiple mappings."""

    _test_counter: int = -1
    _max_requests_in_replay_file: int = 10

    def __init__(self, name: str, acl_behavior_policy: int, test_cases: List[Remap_acl_test_case]):
        """Initialize the test.

        :param name: The name of the test.
        :param name: The acl behavior policy.
        :param test_cases: The test cases.
        """
        self._test_cases = test_cases
        self._acl_behavior_policy = acl_behavior_policy
        Test_remap_acl_multi_map._test_counter += 1

        self._uuids_list = self._generate_client_request_uuids_list(len(test_cases))
        logging.debug(f"test_cases={self._test_cases}")
        logging.debug(f"uuids_list={self._uuids_list}")
        tr = Test.AddTestRun(name)
        self._configure_server(tr)
        self._configure_traffic_server(tr)
        self._configure_client(tr)

    def _generate_client_request_uuids_list(self, length: int) -> List[Mapping[str, str]]:
        return [self._generate_client_request_uuids() for i in range(length)]

    def _generate_client_request_uuids(self) -> Mapping[str, str]:
        return {f'client_request_uuid_{i}': uuid.uuid4() for i in range(Test_remap_acl_multi_map._max_requests_in_replay_file)}

    def _configure_server(self, tr: 'TestRun') -> None:
        """Configure the server.

        :param tr: The TestRun object to associate the server process with.
        """
        name = f"server-{Test_remap_acl_multi_map._test_counter}"
        replay_path_with_context_list = [
            {
                "replay_file": self._test_cases[i]["replay_file"],
                "context": {
                    **uuids, "url_prefix": ""
                }
            } for i, uuids in enumerate(self._uuids_list)
        ]
        logging.debug(f"_configure_server replay_path_with_context_list={replay_path_with_context_list}")
        server = tr.AddVerifierServerProcess(name, None, replay_path_with_context_list=replay_path_with_context_list)
        self._server = server

    def _configure_traffic_server(self, tr: 'TestRun') -> None:
        """Configure Traffic Server.

        :param tr: The TestRun object to associate the Traffic Server process with.
        """

        name = f"ts-{Test_remap_acl_multi_map._test_counter}"
        logging.debug(f'_configure_traffic_server name={name}')
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
            })

        self.diags_log = self._ts.Disk.diags_log.AbsPath
        self.log_dir = os.path.dirname(self.diags_log)
        self.traffic_out = self._ts.Disk.traffic_out.AbsPath

        remap_config_lines = []
        for i, item in enumerate(self._test_cases):
            if item["deactivate_ip_allow"]:
                remap_config_lines.append('.deactivatefilter ip_allow')

            # First, define the name ACLs (filters).
            for name, definition in item["named_acls"]:
                remap_config_lines.append(f'.definefilter {name} {definition}')
            # Now activate them.
            for name, _ in item["named_acls"]:
                remap_config_lines.append(f'.activatefilter {name}')

            url_prefix = f"/{i}"
            remap_config_lines.append(
                f'map http://example.com{url_prefix}/ http://127.0.0.1:{self._server.Variables.http_port} {item["acl_configuration"]}'
            )
        ts.Disk.remap_config.AddLines(remap_config_lines)
        ts.Disk.ip_allow_yaml.AddLines(item["ip_allow_content"].split("\n"))

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
                    f"rotate_diags_log_{Test_remap_acl_multi_map._test_counter}_{i}",
                    "mv {} {}".format(self.diags_log, rotated_diags_log))
                logging.debug(f"rotate_diags.log mv {self.diags_log} {rotated_diags_log}")
                rotate_diags_log.ReturnCode = 0
                rotate_diags_log.StartBefore(client_ready)

                send_pkill = tr.Processes.Process(
                    f"Send_SIGUSR2-{Test_remap_acl_multi_map._test_counter}-{i}", self.get_sigusr2_signal_command())
                logging.debug(f"process Send_SIGUSR2-{Test_remap_acl_multi_map._test_counter}-{i}")
                send_pkill.StartBefore(rotate_diags_log)

                send_pkill_ready = tr.Processes.Process(
                    f"send_pkill_ready-{Test_remap_acl_multi_map._test_counter}-{i}", 'sleep 30')
                logging.debug(f"process send_pkill_ready-{Test_remap_acl_multi_map._test_counter}-{i}")
                send_pkill_ready.StartupTimeout = 30
                send_pkill_ready.Ready = When.FileExists(self.diags_log)
                send_pkill_ready.StartBefore(send_pkill)

            name = f"client-{Test_remap_acl_multi_map._test_counter}-{i}"
            replay_path = self._test_cases[i]["replay_file"]
            context = {**uuids, "url_prefix": f"/{i}"}
            logging.debug(f"_configure_client replay_path={replay_path}, context={context}, i={i}, len={len(self._uuids_list)}")
            p = tr.AddVerifierClientProcess(name, replay_path, http_ports=[self._ts.Variables.port], context=context, default=False)
            if i == 0:
                p.StartBefore(self._server)
                p.StartBefore(self._ts)
            else:
                p.StartBefore(send_pkill_ready)

            expected_responses = self._test_cases[i]["expected_responses"]
            if expected_responses == [None, None]:
                # If there are no expected responses, expect the Warning about the rejected ip.
                self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
                    "client '127.0.0.1' prohibited by ip-allow policy", "Verify the client rejection warning message.")

                # Also, the client will complain about the broken connections.
                p.ReturnCode = 1

            else:
                codes = [str(code) for code in expected_responses]
                p.Streams.stdout += Testers.ContainsExpression(
                    '.*'.join(codes), "Verifying the expected order of responses", reflags=re.DOTALL | re.MULTILINE)

            client_ready = tr.Processes.Process(f"client_ready-{Test_remap_acl_multi_map._test_counter}-{i}", 'sleep 30')
            logging.debug(f"process client_ready-{Test_remap_acl_multi_map._test_counter}-{i}")
            client_ready.StartBefore(p)
            # In the autest environment, it can take more than 10 seconds for the log file to be created.
            client_ready.StartupTimeout = 30
            client_ready.Ready = When.FileContains(self.traffic_out, f"/{i}/test/ip_allow/")

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


class Test_remap_acl:
    """Configure a test to verify remap.config acl behavior."""

    _ts_counter: int = 0
    _server_counter: int = 0
    _client_counter: int = 0

    def __init__(
            self, name: str, replay_file: str, ip_allow_content: str, deactivate_ip_allow: bool, acl_behavior_policy: int,
            acl_configuration: str, named_acls: List[Tuple[str, str]], expected_responses: List[int]):
        """Initialize the test.

        :param name: The name of the test.
        :param replay_file: The replay file to be used.
        :param ip_allow_content: The ip_allow configuration to be used.
        :param deactivate_ip_allow: Whether to deactivate the ip_allow filter.
        :param acl_configuration: The ACL configuration to be used.
        :param named_acls: The set of named ACLs to configure and use.
        :param expect_responses: The in-order expected responses from the proxy.
        """
        self._replay_file = replay_file
        self._ip_allow_content = ip_allow_content
        self._deactivate_ip_allow = deactivate_ip_allow
        self._acl_behavior_policy = acl_behavior_policy
        self._acl_configuration = acl_configuration
        self._named_acls = named_acls
        self._expected_responses = expected_responses

        tr = Test.AddTestRun(name)
        self._configure_server(tr)
        self._configure_traffic_server(tr)
        self._configure_client(tr)

    def _configure_server(self, tr: 'TestRun') -> None:
        """Configure the server.

        :param tr: The TestRun object to associate the server process with.
        """
        name = f"server-{Test_remap_acl._server_counter}"
        logging.debug(f'_configure_server name={name}')
        context = {"url_prefix": ""}
        server = tr.AddVerifierServerProcess(name, self._replay_file, context=context)
        Test_remap_acl._server_counter += 1
        self._server = server

    def _configure_traffic_server(self, tr: 'TestRun') -> None:
        """Configure Traffic Server.

        :param tr: The TestRun object to associate the Traffic Server process with.
        """

        name = f"ts-{Test_remap_acl._ts_counter}"
        logging.debug(f'_configure_traffic_server name={name}')
        url_prefix = f"/{Test_remap_acl._ts_counter}"
        ts = tr.MakeATSProcess(name, enable_cache=False, enable_tls=True)
        Test_remap_acl._ts_counter += 1
        self._ts = ts

        ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http|url|remap|ip_allow',
                'proxy.config.http.push_method_enabled': 1,
                'proxy.config.http.connect_ports': self._server.Variables.http_port,
                'proxy.config.url_remap.acl_behavior_policy': self._acl_behavior_policy,
            })

        remap_config_lines = []
        if self._deactivate_ip_allow:
            remap_config_lines.append('.deactivatefilter ip_allow')

        # First, define the name ACLs (filters).
        for name, definition in self._named_acls:
            remap_config_lines.append(f'.definefilter {name} {definition}')
        # Now activate them.
        for name, _ in self._named_acls:
            remap_config_lines.append(f'.activatefilter {name}')

        remap_config_lines.append(
            f'map http://example.com{url_prefix}/ http://127.0.0.1:{self._server.Variables.http_port} {self._acl_configuration}')
        ts.Disk.remap_config.AddLines(remap_config_lines)
        ts.Disk.ip_allow_yaml.AddLines(self._ip_allow_content.split("\n"))

    def _configure_client(self, tr: 'TestRun') -> None:
        """Run the test.

        :param tr: The TestRun object to associate the client process with.
        """

        name = f"client-{Test_remap_acl._client_counter}"
        context = {"url_prefix": f"/{Test_remap_acl._client_counter}"}
        p = tr.AddVerifierClientProcess(name, self._replay_file, http_ports=[self._ts.Variables.port], context=context)
        logging.debug(f'_configure_client name={name}, command={p.Command}')
        Test_remap_acl._client_counter += 1
        p.StartBefore(self._server)
        p.StartBefore(self._ts)

        if self._expected_responses == [None, None]:
            # If there are no expected responses, expect the Warning about the rejected ip.
            self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
                "client '127.0.0.1' prohibited by ip-allow policy", "Verify the client rejection warning message.")

            # Also, the client will complain about the broken connections.
            p.ReturnCode = 1

        else:
            codes = [str(code) for code in self._expected_responses]
            p.Streams.stdout += Testers.ContainsExpression(
                '.*'.join(codes), "Verifying the expected order of responses", reflags=re.DOTALL | re.MULTILINE)


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

#Test_old_action("Verify allow is reject in modern policy", "@action=allow @method=GET", IP_ALLOW_CONTENT)
#Test_old_action("Verify deny is reject in modern policy", "@action=deny @method=GET", IP_ALLOW_CONTENT)
#Test_old_action("Verify deny is reject in modern policy", "", IP_ALLOW_OLD_ACTION)

Test_remap_acl_multi_map(
    "test_ip_allow_optional_methods",
    acl_behavior_policy=1,
    test_cases=[
        {
            "name": "Verify non-allowed methods are blocked.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "ip_allow_content": IP_ALLOW_CONTENT,
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=set_allow @src_ip=127.0.0.1 @method=GET @method=POST',
            "named_acls": [],
            "expected_responses": [200, 200, 403, 403, 403]
        }, {
            "name": "Verify add_allow adds an allowed method.",
            "replay_file": 'remap_acl_get_post_allowed.replay.yaml',
            "ip_allow_content": IP_ALLOW_CONTENT,
            "deactivate_ip_allow": False,
            "acl_configuration": '@action=add_allow @src_ip=127.0.0.1 @method=POST',
            "named_acls": [],
            "expected_responses": [200, 200, 403, 403, 403]
        }
    ])

#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify non-allowed methods are blocked.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip=127.0.0.1 @method=GET @method=POST',
#    named_acls=[],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify add_allow adds an allowed method.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=add_allow @src_ip=127.0.0.1 @method=POST',
#    named_acls=[],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify add_allow adds allowed methods.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=add_allow @src_ip=127.0.0.1 @method=GET @method=POST',
#    named_acls=[],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify if no ACLs match, ip_allow.yaml is used.",
#    replay_file='remap_acl_get_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip=1.2.3.4 @method=GET @method=POST',
#    named_acls=[],
#    expected_responses=[200, 403, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify @src_ip=all works.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip=all @method=GET @method=POST',
#    named_acls=[],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify @src_ip_category works.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip_category=ACME_LOCAL @method=GET @method=POST',
#    named_acls=[],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify no @src_ip implies all IP addresses.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @method=GET @method=POST',
#    named_acls=[],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify denied methods are blocked.",
#    replay_file='remap_acl_get_post_denied.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_deny @src_ip=127.0.0.1 @method=GET @method=POST',
#    named_acls=[],
#    expected_responses=[403, 403, 200, 200, 400])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify add_deny adds blocked methods.",
#    replay_file='remap_acl_all_denied.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=add_deny @src_ip=127.0.0.1 @method=GET',
#    named_acls=[],
#    expected_responses=[403, 403, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify a default deny filter rule works.",
#    replay_file='remap_acl_all_denied.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip=1.2.3.4 @method=GET @method=POST',
#    named_acls=[('deny', '@action=set_deny')],
#    expected_responses=[403, 403, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify inverting @src_ip works.",
#    replay_file='remap_acl_all_denied.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip=~127.0.0.1 @method=GET @method=POST',
#    named_acls=[('deny', '@action=set_deny')],
#    expected_responses=[403, 403, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify inverting @src_ip works with the rule matching.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip=~3.4.5.6 @method=GET @method=POST',
#    named_acls=[('deny', '@action=set_deny')],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify inverting @src_ip_category works.",
#    replay_file='remap_acl_all_denied.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip_category=~ACME_LOCAL @method=GET @method=POST',
#    named_acls=[('deny', '@action=set_deny')],
#    expected_responses=[403, 403, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify inverting @src_ip_category works with the rule matching.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip_category=~ACME_EXTERNAL @method=GET @method=POST',
#    named_acls=[('deny', '@action=set_deny')],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify @src_ip and @src_ip_category AND together.",
#    replay_file='remap_acl_all_denied.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    # The rule will not match because, while @src_ip matches, @src_ip_category does not.
#    acl_configuration='@action=set_allow @src_ip=127.0.0.1 @src_ip_category=ACME_EXTERNAL @method=GET @method=POST',
#    # Therefore, this named deny filter will block.
#    named_acls=[('deny', '@action=set_deny')],
#    expected_responses=[403, 403, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify defined in-line ACLS are evaluated before named ones.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip=127.0.0.1 @method=GET @method=POST',
#    named_acls=[('deny', '@action=set_deny')],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify remap.config line overrides ip_allow rule.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @src_ip=127.0.0.1 @method=GET @method=POST',
#    named_acls=[],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify we can deactivate the ip_allow filter.",
#    replay_file='remap_acl_all_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=True,
#    acl_behavior_policy=1,
#    # This won't match, so nothing will match since ip_allow.yaml is off.
#    acl_configuration='@action=set_allow @src_ip=1.2.3.4 @method=GET @method=POST',
#    named_acls=[],
#    # Nothing will block the request since ip_allow.yaml is off.
#    expected_responses=[200, 200, 200, 200, 400])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify in_ip matches on IP as expected.",
#    replay_file='remap_acl_get_post_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @in_ip=127.0.0.1 @method=GET @method=POST',
#    named_acls=[],
#    expected_responses=[200, 200, 403, 403, 403])
#
#test_ip_allow_optional_methods = Test_remap_acl(
#    "Verify in_ip rules do not match on other IPs.",
#    replay_file='remap_acl_get_allowed.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='@action=set_allow @in_ip=3.4.5.6 @method=GET @method=POST',
#    named_acls=[],
#    expected_responses=[200, 403, 403, 403, 403])
#
#test_named_acl_deny = Test_remap_acl(
#    "Verify a named ACL is applied if an in-line ACL is absent.",
#    replay_file='deny_head_post.replay.yaml',
#    ip_allow_content=IP_ALLOW_CONTENT,
#    deactivate_ip_allow=False,
#    acl_behavior_policy=1,
#    acl_configuration='',
#    named_acls=[('deny', '@action=set_deny @method=HEAD @method=POST')],
#    expected_responses=[200, 403, 403, 403])
#
#
#def replay_proxy_response(filename, replay_file, get_proxy_response, post_proxy_response):
#    """
#    replay_proxy_response writes the given replay file (which expects a single GET & POST client-request)
#    with the given proxy_response value. This is only used to support the tests in the combination table.
#    """
#
#    current_dir = os.path.dirname(inspect.getfile(inspect.currentframe()))
#    path = os.path.join(current_dir, filename)
#    data = None
#    with open(path) as f:
#        data = load(f, Loader=Loader)
#        for session in data["sessions"]:
#            for transaction in session["transactions"]:
#                method = transaction["client-request"]["method"]
#                if method == "GET":
#                    transaction["proxy-response"]["status"] = 403 if get_proxy_response == None else get_proxy_response
#                elif method == "POST":
#                    transaction["proxy-response"]["status"] = 403 if post_proxy_response == None else post_proxy_response
#                else:
#                    raise Exception("Expected to find GET or POST request, found %s", method)
#    with open(replay_file, "w") as f:
#        f.write(dump(data))
#
#
#from deactivate_ip_allow import all_deactivate_ip_allow_tests
#from all_acl_combinations import all_acl_combination_tests
#"""
#Test all acl combinations
#"""
#for idx, test in enumerate(all_acl_combination_tests):
#    (_, replay_file_name) = tempfile.mkstemp(suffix="acl_table_test_{}.replay".format(idx))
#    replay_proxy_response(
#        "base.replay.yaml",
#        replay_file_name,
#        test["GET response"],
#        test["POST response"],
#    )
#    Test_remap_acl(
#        "allcombo-{0} {1} {2} {3}".format(idx, test["inline"], test["named_acl"], test["ip_allow"]),
#        replay_file=replay_file_name,
#        ip_allow_content=test["ip_allow"],
#        deactivate_ip_allow=False,
#        acl_behavior_policy=0 if test["policy"] == "legacy" else 1,
#        acl_configuration=test["inline"],
#        named_acls=[("acl", test["named_acl"])] if test["named_acl"] != "" else [],
#        expected_responses=[test["GET response"], test["POST response"]],
#    )
#"""
#Test all ACL combinations
#"""
#for idx, test in enumerate(all_deactivate_ip_allow_tests):
#    try:
#        test["deactivate_ip_allow"]
#    except:
#        print(test)
#    (_, replay_file_name) = tempfile.mkstemp(suffix="deactivate_ip_allow_table_test_{}.replay".format(idx))
#    replay_proxy_response(
#        "base.replay.yaml",
#        replay_file_name,
#        test["GET response"],
#        test["POST response"],
#    )
#    Test_remap_acl(
#        "ipallow-{0} {1} {2} {3}".format(idx, test["inline"], test["named_acl"], test["ip_allow"]),
#        replay_file=replay_file_name,
#        ip_allow_content=test["ip_allow"],
#        deactivate_ip_allow=test["deactivate_ip_allow"],
#        acl_behavior_policy=0 if test["policy"] == "legacy" else 1,
#        acl_configuration=test["inline"],
#        named_acls=[("acl", test["named_acl"])] if test["named_acl"] != "" else [],
#        expected_responses=[test["GET response"], test["POST response"]])
