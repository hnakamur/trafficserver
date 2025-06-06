/** @file

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

#include "P_SSLUtils.h"
#include "P_OCSPStapling.h"
#include "SSLStats.h"
#include "P_SSLNetProcessor.h"
#include "P_SSLNetAccept.h"
#include "P_SSLNetVConnection.h"
#include "P_SSLClientCoordinator.h"

//
// Global Data
//

SSLNetProcessor ssl_NetProcessor;
NetProcessor   &sslNetProcessor = ssl_NetProcessor;

struct OCSPContinuation : public Continuation {
  int
  mainEvent(int /* event ATS_UNUSED */, Event * /* e ATS_UNUSED */)
  {
    if (ocsp_update() == OCSPStatus::OCSP_FETCHSM_NOT_INITIALIZED) {
      Note("Delaying OCSP fetching until FetchSM is initialized.");
      this_ethread()->schedule_in(this, HRTIME_SECONDS(1));
      return EVENT_CONT;
    }
    return EVENT_CONT;
  }

  OCSPContinuation() : Continuation(new_ProxyMutex()) { SET_HANDLER(&OCSPContinuation::mainEvent); }
};

int
SSLNetProcessor::start(int, size_t stacksize)
{
  // This initialization order matters ...
  SSLInitializeLibrary();
  SSLClientCoordinator::startup();
  SSLPostConfigInitialize();

  if (!SSLCertificateConfig::startup()) {
    return -1;
  }
  SSLTicketKeyConfig::startup();

  // Initialize SSL statistics. This depends on an initial set of certificates being loaded above.
  SSLInitializeStatistics();

  if (SSLConfigParams::ssl_ocsp_enabled) {
    EventType     ET_OCSP = eventProcessor.spawn_event_threads("ET_OCSP", 1, stacksize);
    Continuation *cont    = new OCSPContinuation();
    // schedule the update initially to get things populated
    eventProcessor.schedule_imm(cont, ET_OCSP);
    eventProcessor.schedule_every(cont, HRTIME_SECONDS(SSLConfigParams::ssl_ocsp_update_period), ET_OCSP);
  }

  // We have removed the difference between ET_SSL threads and ET_NET threads,
  // So just keep on chugging
  return 0;
}

NetAccept *
SSLNetProcessor::createNetAccept(const NetProcessor::AcceptOptions &opt)
{
  return new SSLNetAccept(opt);
}

NetVConnection *
SSLNetProcessor::allocate_vc(EThread *t)
{
  SSLNetVConnection *vc;

  if (t) {
    vc = THREAD_ALLOC_INIT(sslNetVCAllocator, t);
  } else {
    if (likely(vc = sslNetVCAllocator.alloc())) {
      vc->from_accept_thread = true;
    }
  }

  return vc;
}

SSLNetProcessor::SSLNetProcessor() {}

SSLNetProcessor::~SSLNetProcessor() {}
