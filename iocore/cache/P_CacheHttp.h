/** @file

  A brief file description

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

#include "P_CacheArray.h"
#include "HTTP.h"
#include "URL.h"

typedef URL CacheURL;
typedef HTTPHdr CacheHTTPHdr;
typedef HTTPInfo CacheHTTPInfo;

#define OFFSET_BITS 24
enum {
  OWNER_NONE  = 0,
  OWNER_CACHE = 1,
  OWNER_HTTP  = 2,
};

// This class is a wrapper for CacheHTTPInfo, which is HTTPInfo
// and HTTPInfo has a pointer to HTTPCacheAlt.
struct vec_info {
  CacheHTTPInfo alternate;
};

// This is an array of HTTPInfo objects and serves as the repository of information about alternates of an object.
// It is marshaled as part of the metadata for an object in the cache.
// The CacheHTTPInfoVector is stored only in the first Doc. Subsequent Doc instances for the object,
// including the earliest Doc, should have an hlen of zero and if not, it is ignored.
struct CacheHTTPInfoVector {
  void *magic = nullptr;

  CacheHTTPInfoVector();
  ~CacheHTTPInfoVector();

  int
  count()
  {
    return xcount;
  }
  int insert(CacheHTTPInfo *info, int id = -1);
  CacheHTTPInfo *get(int idx);
  void detach(int idx, CacheHTTPInfo *r);
  void remove(int idx, bool destroy);
  void clear(bool destroy = true);
  void
  reset()
  {
    xcount = 0;
    data.clear();
  }
  void print(char *buffer, size_t buf_size, bool temps = true);

  int marshal_length();
  int marshal(char *buf, int length);
  uint32_t get_handles(const char *buf, int length, RefCountObj *block_ptr = nullptr);
  int unmarshal(const char *buf, int length, RefCountObj *block_ptr);

  CacheArray<vec_info> data;
  int xcount = 0;
  Ptr<RefCountObj> vector_buf;
};

TS_INLINE CacheHTTPInfo *
CacheHTTPInfoVector::get(int idx)
{
  ink_assert(idx >= 0);
  ink_assert(idx < xcount);
  return &data[idx].alternate;
}
