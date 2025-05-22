/** @file

  Traffic Server SDK API - HTTP related enumerations

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

  @section developers Developers

  Developers, when adding a new element to an enum, append it. DO NOT
  insert it.  Otherwise, binary compatibility of plugins will be broken!

 */

#pragma once

/// Server session sharing values - match
enum class TSServerSessionSharingMatchType {
  IP,
  HOSTONLY,
  HOSTSNISYNC,
  SNI,
  CERT,
  NONE,
  BOTH,
  HOST,
};

enum class TSServerSessionSharingMatchMask : MgmtByte {
  NONE        = 0,
  IP          = 0x1,
  HOSTONLY    = 0x2,
  HOSTSNISYNC = 0x4,
  SNI         = 0x8,
  CERT        = 0x10,
};

inline TSServerSessionSharingMatchMask
operator&(TSServerSessionSharingMatchMask a, TSServerSessionSharingMatchMask b)
{
  return static_cast<TSServerSessionSharingMatchMask>(static_cast<MgmtByte>(a) & static_cast<MgmtByte>(b));
}

inline TSServerSessionSharingMatchMask
operator|(TSServerSessionSharingMatchMask a, TSServerSessionSharingMatchMask b)
{
  return static_cast<TSServerSessionSharingMatchMask>(static_cast<MgmtByte>(a) | static_cast<MgmtByte>(b));
}

inline TSServerSessionSharingMatchMask
operator~(TSServerSessionSharingMatchMask a)
{
  return static_cast<TSServerSessionSharingMatchMask>(~static_cast<MgmtByte>(a));
}

/// Server session sharing values - pool
enum class TSServerSessionSharingPoolType {
  GLOBAL,
  THREAD,
  HYBRID,
  GLOBAL_LOCKED,
};
