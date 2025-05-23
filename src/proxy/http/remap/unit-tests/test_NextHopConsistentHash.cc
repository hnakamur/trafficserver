/** @file

  Unit tests for the NextHopConsistentHash.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  @section details Details

  Unit testing the NextHopConsistentHash class.

 */

#define CATCH_CONFIG_MAIN /* include main function */

#include <catch.hpp> /* catch unit-test framework */
#include <yaml-cpp/yaml.h>

#include "proxy/http/HttpSM.h"
#include "nexthop_test_stubs.h"
#include "proxy/http/remap/NextHopSelectionStrategy.h"
#include "proxy/http/remap/NextHopStrategyFactory.h"
#include "proxy/http/remap/NextHopConsistentHash.h"

#include "proxy/hdrs/HTTP.h"
extern int cmd_disable_pfreelist;

SCENARIO("Testing NextHopConsistentHash class, using policy 'consistent_hash'", "[NextHopConsistentHash]")
{
  // We need this to build a HdrHeap object in build_request();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  GIVEN("Loading the consistent-hash-tests.yaml config for 'consistent_hash' tests.")
  {
    // load the configuration strtegies.
    std::shared_ptr<NextHopSelectionStrategy> strategy;
    NextHopStrategyFactory                    nhf(TS_SRC_DIR "/consistent-hash-tests.yaml");
    strategy = nhf.strategyInstance("consistent-hash-1");

    WHEN("the config is loaded.")
    {
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 3);
      }
    }

    WHEN("requests are received.")
    {
      // need to run these checks in succession so there
      // are no host status state changes.
      //
      // These tests simulate failed requests using a selected host.
      // markNextHop() is called by the state machine when
      // there is a request failure due to a connection error or
      // timeout.  the 'result' struct has the information on the
      // host used in the failed request and when called, marks the
      // host indicated in the 'request' struct as unavailable.
      //
      // Here we walk through making requests then marking the selected
      // host down until all are down and the origin is finally chosen.
      //
      THEN("when making requests and taking nodes down.")
      {
        HttpSM        sm;
        ParentResult *result = &sm.t_state.parent_result;
        TSHttpTxn     txnp   = reinterpret_cast<TSHttpTxn>(&sm);

        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);

        // first request.
        build_request(10001, &sm, nullptr, "rabbit.net", nullptr);
        result->reset();
        strategy->findNextHop(txnp);

        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "p1.foo.com") == 0);

        // mark down p1.foo.com.  markNextHop looks at the 'result'
        // and uses the host index there mark down the host selected
        // from a
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        // second request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        build_request(10002, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp);

        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "p2.foo.com") == 0);

        // mark down p2.foo.com
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        // third request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        build_request(10003, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp);

        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "s2.bar.com") == 0);

        // mark down s2.bar.com
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        // fourth request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        build_request(10004, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp);

        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "s1.bar.com") == 0);

        // mark down s1.bar.com.
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        // fifth request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        build_request(10005, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp);

        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "q1.bar.com") == 0);

        // mark down q1.bar.com
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);
        // sixth request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        build_request(10006, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp);

        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "q2.bar.com") == 0);

        // mark down q2.bar.com
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);
        // seventh request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        build_request(10007, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp);

        CHECK(result->result == ParentResultType::DIRECT);
        CHECK(result->hostname == nullptr);

        // sleep and test that q2 is becomes retryable;
        time_t now = time(nullptr) + 5;

        // eighth request - reusing the ParentResult from the last request
        // simulating a failure triggers a search for another parent, not firstcall.
        build_request(10008, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp, nullptr, now);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "q2.bar.com") == 0);

        // free up request resources.
        br_destroy(sm);
      }
    }
  }
}

SCENARIO("Testing NextHopConsistentHash class (all firstcalls), using policy 'consistent_hash'", "[NextHopConsistentHash]")
{
  // We need this to build a HdrHeap object in build_request();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  GIVEN("Loading the consistent-hash-tests.yaml config for 'consistent_hash' tests.")
  {
    std::shared_ptr<NextHopSelectionStrategy> strategy;
    NextHopStrategyFactory                    nhf(TS_SRC_DIR "/consistent-hash-tests.yaml");
    strategy = nhf.strategyInstance("consistent-hash-1");

    WHEN("the config is loaded.")
    {
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 3);
      }
    }

    // Same test procedure as the first scenario but we clear the 'result' struct
    // so that we are making initial requests and simulating that hosts were
    // removed by different transactions.
    //
    // these checks need to be run in sequence so that there are no host status
    // state changes induced by using multiple WHEN() and THEN()
    WHEN("initial requests are made and hosts are unavailable .")
    {
      HttpSM        sm;
      ParentResult *result = &sm.t_state.parent_result;
      TSHttpTxn     txnp   = reinterpret_cast<TSHttpTxn>(&sm);

      THEN("when making requests and taking nodes down.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);

        // first request.
        build_request(20001, &sm, nullptr, "rabbit.net", nullptr);
        result->reset();
        strategy->findNextHop(txnp);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "p1.foo.com") == 0);

        // mark down p1.foo.com
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);
        // second request
        build_request(20002, &sm, nullptr, "rabbit.net", nullptr);
        result->reset();
        strategy->findNextHop(txnp);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "p2.foo.com") == 0);

        // mark down p2.foo.com
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        // third request
        result->reset();
        build_request(20003, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "s2.bar.com") == 0);

        // mark down s2.bar.com
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        // fourth request
        {
          time_t now = time(nullptr) - 1; ///< make sure down hosts are not retryable
          result->reset();
          build_request(20004, &sm, nullptr, "rabbit.net", nullptr);
          strategy->findNextHop(txnp, nullptr, now);
          REQUIRE(result->result == ParentResultType::SPECIFIED);
          CHECK(strcmp(result->hostname, "s1.bar.com") == 0);
        }

        // mark down s1.bar.com
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        // fifth request
        {
          time_t now = time(nullptr) - 1; ///< make sure down hosts are not retryable
          result->reset();
          build_request(20005, &sm, nullptr, "rabbit.net/asset1", nullptr);
          strategy->findNextHop(txnp, nullptr, now);
          REQUIRE(result->result == ParentResultType::SPECIFIED);
          CHECK(strcmp(result->hostname, "q1.bar.com") == 0);
        }

        // sixth request - wait and p1 should now become available
        {
          time_t now = time(nullptr) + 5;
          result->reset();
          build_request(20006, &sm, nullptr, "rabbit.net", nullptr);
          strategy->findNextHop(txnp, nullptr, now);
          REQUIRE(result->result == ParentResultType::SPECIFIED);
          CHECK(strcmp(result->hostname, "p1.foo.com") == 0);
        }
      }
      // free up request resources.
      br_destroy(sm);
    }
  }
}

SCENARIO("Testing NextHop ignore_self_detect false", "[NextHopConsistentHash]")
{
  // We need this to build a HdrHeap object in build_request();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  GIVEN("Loading the consistent-hash-tests.yaml config for 'consistent_hash' tests.")
  {
    // load the configuration strtegies.
    std::shared_ptr<NextHopSelectionStrategy> strategy;
    NextHopStrategyFactory                    nhf(TS_SRC_DIR "/consistent-hash-tests.yaml");
    strategy = nhf.strategyInstance("ignore-self-detect-false");

    HostStatus &hs = HostStatus::instance();
    hs.setHostStatus("localhost", TSHostStatus::TS_HOST_STATUS_DOWN, 0, Reason::SELF_DETECT);

    WHEN("the config is loaded.")
    {
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 2);
      }
    }

    WHEN("requests are received.")
    {
      THEN("when making requests to localhost.")
      {
        HttpSM        sm;
        ParentResult *result = &sm.t_state.parent_result;
        TSHttpTxn     txnp   = reinterpret_cast<TSHttpTxn>(&sm);

        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);

        build_request(10001, &sm, nullptr, "rabbit.net", nullptr);
        result->reset();
        strategy->findNextHop(txnp);
        CHECK(result->result == ParentResultType::DIRECT);
        CHECK(result->hostname == nullptr);
        br_destroy(sm);
      }
    }
  }
}

SCENARIO("Testing NextHop ignore_self_detect true", "[NextHopConsistentHash]")
{
  // We need this to build a HdrHeap object in build_request();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  GIVEN("Loading the consistent-hash-tests.yaml config for 'consistent_hash' tests.")
  {
    // load the configuration strtegies.
    std::shared_ptr<NextHopSelectionStrategy> strategy;
    NextHopStrategyFactory                    nhf(TS_SRC_DIR "/consistent-hash-tests.yaml");
    strategy = nhf.strategyInstance("ignore-self-detect-true");

    HostStatus &hs = HostStatus::instance();
    hs.setHostStatus("localhost", TSHostStatus::TS_HOST_STATUS_DOWN, 0, Reason::SELF_DETECT);

    WHEN("the config is loaded.")
    {
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 2);
      }
    }

    WHEN("requests are received.")
    {
      THEN("when making requests to localhost.")
      {
        HttpSM        sm;
        ParentResult *result = &sm.t_state.parent_result;
        TSHttpTxn     txnp   = reinterpret_cast<TSHttpTxn>(&sm);

        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        build_request(10001, &sm, nullptr, "rabbit.net", nullptr);
        result->reset();
        strategy->findNextHop(txnp);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "localhost") == 0);
        CHECK(result->port == 8000);
        br_destroy(sm);
      }
    }
  }
}

SCENARIO("Testing NextHopConsistentHash same host different port markdown", "[NextHopConsistentHash]")
{
  // We need this to build a HdrHeap object in build_request();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  GIVEN("Loading the consistent-hash-tests.yaml config for 'consistent_hash' tests.")
  {
    // load the configuration strtegies.
    std::shared_ptr<NextHopSelectionStrategy> strategy;
    NextHopStrategyFactory                    nhf(TS_SRC_DIR "/consistent-hash-tests.yaml");
    strategy = nhf.strategyInstance("same-host-different-port");

    WHEN("the config is loaded.")
    {
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 3);
      }
    }

    WHEN("requests are received.")
    {
      THEN("when making requests and taking nodes down.")
      {
        HttpSM        sm;
        ParentResult *result = &sm.t_state.parent_result;
        TSHttpTxn     txnp   = reinterpret_cast<TSHttpTxn>(&sm);

        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);

        // first request.
        build_request(10001, &sm, nullptr, "rabbit.net", nullptr);
        result->reset();
        strategy->findNextHop(txnp);

        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "localhost") == 0);
        CHECK(result->port == 8000);

        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        build_request(10002, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp);

        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "localhost") == 0);
        CHECK(result->port == 8002);

        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        build_request(10003, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp);

        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "localhost") == 0);
        CHECK(result->port == 8004);
        br_destroy(sm);
      }
    }
  }
}

SCENARIO("Testing NextHopConsistentHash hash_string override", "[NextHopConsistentHash]")
{
  // We need this to build a HdrHeap object in build_request();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  GIVEN("Loading the consistent-hash-tests.yaml config for 'consistent_hash' tests.")
  {
    // load the configuration strtegies.
    std::shared_ptr<NextHopSelectionStrategy> strategy;
    NextHopStrategyFactory                    nhf(TS_SRC_DIR "/consistent-hash-tests.yaml");
    strategy = nhf.strategyInstance("hash-string-override");

    WHEN("the config is loaded.")
    {
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 2);
      }
    }

    WHEN("requests are received.")
    {
      THEN("when making requests and taking nodes down.")
      {
        HttpSM        sm;
        ParentResult *result = &sm.t_state.parent_result;
        TSHttpTxn     txnp   = reinterpret_cast<TSHttpTxn>(&sm);

        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);

        build_request(10001, &sm, nullptr, "rabbit.net", nullptr);
        result->reset();
        strategy->findNextHop(txnp);

        // We happen to know that 'foo.test' will be first if the hostname is the hash
        // and foo.test will be first for the hash 'first' and the bar.test hash 'second'.
        // So, if the hash_string override isn't getting applied, this will fail.
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "bar.test") == 0);
        CHECK(result->port == 80);

        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        build_request(10002, &sm, nullptr, "rabbit.net", nullptr);
        strategy->findNextHop(txnp);

        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "foo.test") == 0);
        CHECK(result->port == 80);
        br_destroy(sm);
      }
    }
  }
}

SCENARIO("Testing NextHopConsistentHash class (alternating rings), using policy 'consistent_hash'", "[NextHopConsistentHash]")
{
  // We need this to build a HdrHeap object in build_request();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  GIVEN("Loading the consistent-hash-tests.yaml config for 'consistent_hash' tests.")
  {
    std::shared_ptr<NextHopSelectionStrategy> strategy;
    NextHopStrategyFactory                    nhf(TS_SRC_DIR "/consistent-hash-tests.yaml");
    strategy = nhf.strategyInstance("consistent-hash-2");

    WHEN("the config is loaded.")
    {
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 3);
      }
    }

    // making requests and marking down hosts with a config set for alternating ring mode.
    WHEN("requests are made in a config set for alternating rings and hosts are marked down.")
    {
      HttpSM        sm;
      ParentResult *result = &sm.t_state.parent_result;
      TSHttpTxn     txnp   = reinterpret_cast<TSHttpTxn>(&sm);

      THEN("expect the following results when making requests and marking hosts down.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);

        // first request.
        result->reset();
        build_request(30001, &sm, nullptr, "bunny.net/asset1", nullptr);
        result->reset();
        strategy->findNextHop(txnp);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "c2.foo.com") == 0);

        // simulated failure, mark c2 down and retry request
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        // second request
        build_request(30002, &sm, nullptr, "bunny.net.net/asset1", nullptr);
        strategy->findNextHop(txnp);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "c3.bar.com") == 0);

        // mark down c3.bar.com
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);

        // third request
        build_request(30003, &sm, nullptr, "bunny.net/asset2", nullptr);
        result->reset();
        strategy->findNextHop(txnp);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "c6.bar.com") == 0);

        // just mark it down and retry request
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);
        // fourth request
        build_request(30004, &sm, nullptr, "bunny.net/asset2", nullptr);
        strategy->findNextHop(txnp);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "c1.foo.com") == 0);

        // mark it down
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);
        // fifth request - new request
        build_request(30005, &sm, nullptr, "bunny.net/asset3", nullptr);
        result->reset();
        strategy->findNextHop(txnp);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "c4.bar.com") == 0);

        // mark it down and retry
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);
        // sixth request
        result->reset();
        build_request(30006, &sm, nullptr, "bunny.net/asset3", nullptr);
        strategy->findNextHop(txnp);
        REQUIRE(result->result == ParentResultType::SPECIFIED);
        CHECK(strcmp(result->hostname, "c5.bar.com") == 0);

        // mark it down
        strategy->markNextHop(txnp, result->hostname, result->port, NHCmd::MARK_DOWN);
        // seventh request - new request with all hosts down and go_direct is false.
        {
          time_t now = time(nullptr) - 1; ///< make sure down hosts are not retryable
          result->reset();
          build_request(30007, &sm, nullptr, "bunny.net/asset4", nullptr);
          strategy->findNextHop(txnp, nullptr, now);
          REQUIRE(result->result == ParentResultType::FAIL);
          CHECK(result->hostname == nullptr);
        }

        // eighth request - retry after waiting for the retry window to expire.
        {
          time_t now = time(nullptr) + 5;
          result->reset();
          build_request(30008, &sm, nullptr, "bunny.net/asset4", nullptr);
          strategy->findNextHop(txnp, nullptr, now);
          REQUIRE(result->result == ParentResultType::SPECIFIED);
          CHECK(strcmp(result->hostname, "c2.foo.com") == 0);
        }
      }
      // free up request resources.
      br_destroy(sm);
    }
  }
}

// jjr
//
SCENARIO("Testing NextHopConsistentHash using a peering ring_mode.")
{
  // We need this to build a HdrHeap object in build_request();
  // No thread setup, forbid use of thread local allocators.
  cmd_disable_pfreelist = true;
  // Get all of the HTTP WKS items populated.
  http_init();

  GIVEN("Loading the peering.yaml config for 'consistent_hash' tests.")
  {
    std::shared_ptr<NextHopSelectionStrategy> strategy;
    NextHopStrategyFactory                    nhf(TS_SRC_DIR "/peering.yaml");
    strategy = nhf.strategyInstance("peering-group-1");

    WHEN("the config is loaded.")
    {
      THEN("then testing consistent hash.")
      {
        REQUIRE(nhf.strategies_loaded == true);
        REQUIRE(strategy != nullptr);
        REQUIRE(strategy->groups == 2);
        REQUIRE(strategy->ring_mode == NHRingMode::PEERING_RING);
        REQUIRE(strategy->policy_type == NHPolicyType::CONSISTENT_HASH);
        for (std::size_t i = 0; i < strategy->host_groups.size(); ++i) {
          for (auto const &elem : strategy->host_groups[i]) {
            bool should_be_self = elem.get()->hostname == "p3.bar.com" && i == 0;
            REQUIRE(elem.get()->self == should_be_self);
          }
        }
      }
    }
  }
}
