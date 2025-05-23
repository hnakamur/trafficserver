/** @file

  Implementation of nexthop consistent hash selections strategies.

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
 */

#pragma once

#include <map>
#include <vector>
#include "tscore/HashSip.h"
#include "proxy/http/remap/NextHopSelectionStrategy.h"

enum class NHHashKeyType {
  URL_HASH_KEY = 0,
  HOSTNAME_HASH_KEY,
  PATH_HASH_KEY, // default, consistent hash uses the request url path
  PATH_QUERY_HASH_KEY,
  PATH_FRAGMENT_HASH_KEY,
  CACHE_HASH_KEY // ToDo: Deprecated in 10.0.0, remove in 11.0.0
};

enum class NHHashUrlType { REQUEST = 0, CACHE, PARENT };

class NextHopConsistentHash : public NextHopSelectionStrategy
{
  std::vector<std::shared_ptr<ATSConsistentHash>> rings;

  uint64_t getHashKey(uint64_t sm_id, const HttpRequestData &hrdata, ATSHash64 *h);

public:
  NHHashKeyType hash_key = NHHashKeyType::PATH_HASH_KEY;
  NHHashUrlType hash_url = NHHashUrlType::REQUEST;

  NextHopConsistentHash() = delete;
  NextHopConsistentHash(const std::string_view name, const NHPolicyType &policy, ts::Yaml::Map &n);
  ~NextHopConsistentHash();

  void                        findNextHop(TSHttpTxn txnp, void *ih = nullptr, time_t now = 0) override;
  std::shared_ptr<HostRecord> chashLookup(const std::shared_ptr<ATSConsistentHash> &ring, uint32_t cur_ring, ParentResult &result,
                                          HttpRequestData &request_info, bool *wrapped, uint64_t sm_id);
};
