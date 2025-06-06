/*
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

//////////////////////////////////////////////////////////////////////////////////////////////
//
// Implement the classes for the various types of hash keys we support.
//
#pragma once

#include <string>

#include "tscore/ink_defs.h"
#include "tscore/ink_platform.h"

#include "proxy/http/remap/PluginFactory.h"

#define TS_REMAP_PSEUDO_HOOK TS_HTTP_LAST_HOOK // Ugly, but use the "last hook" for remap instances.
const int OVECCOUNT = 30;                      // We support $1 - $9 only, and this needs to be 3x that

template <typename T> constexpr bool ALWAYS_FALSE_V = false;

std::string getIP(sockaddr const *s_sockaddr);
char       *getIP(sockaddr const *s_sockaddr, char res[INET6_ADDRSTRLEN]);
uint16_t    getPort(sockaddr const *s_sockaddr);

namespace header_rewrite_ns
{
extern const char PLUGIN_NAME[];
extern const char PLUGIN_NAME_DBG[];

extern DbgCtl        dbg_ctl;
extern DbgCtl        pi_dbg_ctl;
extern PluginFactory plugin_factory;
} // namespace header_rewrite_ns

using namespace header_rewrite_ns;
