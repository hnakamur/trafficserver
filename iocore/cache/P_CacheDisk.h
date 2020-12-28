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

#include "I_Cache.h"

extern int cache_config_max_disk_errors;

#define DISK_BAD(_x) ((_x)->num_errors >= cache_config_max_disk_errors)
#define DISK_BAD_SIGNALLED(_x) (_x->num_errors > cache_config_max_disk_errors)
#define SET_DISK_BAD(_x) (_x->num_errors = cache_config_max_disk_errors)
#define SET_DISK_OKAY(_x) (_x->num_errors = 0)

#define VOL_BLOCK_SIZE (1024 * 1024 * 128)
#define MIN_VOL_SIZE VOL_BLOCK_SIZE
#define ROUND_DOWN_TO_VOL_BLOCK(_x) (((_x) & ~(VOL_BLOCK_SIZE - 1)))
#define VOL_BLOCK_SHIFT 27
#define ROUND_DOWN_TO_STORE_BLOCK(_x) (((_x) >> STORE_BLOCK_SHIFT) << STORE_BLOCK_SHIFT)

#define STORE_BLOCKS_PER_VOL (VOL_BLOCK_SIZE / STORE_BLOCK_SIZE)
#define DISK_HEADER_MAGIC 0xABCD1237

/* each disk vol block has a corresponding Vol object */
struct CacheDisk;

// A description of a span stripe (Vol) block.
// This is a serialized data structure.
struct DiskVolBlock {
  // Offset in bytes from the start of the disk.
  // Offset in the span of the start of the span stripe (Vol) block, in bytes.
  uint64_t offset;
  // Length in in store blocks.
  // Length of the span block in store blocks.
  uint64_t len;
  // The cache volume index for this span block.
  int number;
  // Type of the span block.
  unsigned int type : 3;
  // In use or free flag - set if the span block is not in use by a cache volume.
  unsigned int free : 1;
};

struct DiskVolBlockQueue {
  DiskVolBlock *b = nullptr;
  // Whether an existing vol or a new one.
  // Indicates if this is a new stripe rather than an existing one.
  // In case a stripe is new ATS decides to clear that stripe(Vol)
  int new_block = 0;
  LINK(DiskVolBlockQueue, link);

  DiskVolBlockQueue() {}
};

struct DiskVol {
  int num_volblocks; /* number of disk volume blocks in this volume */
  int vol_number;    /* the volume number of this volume */
  uint64_t size;     /* size in store blocks */
  CacheDisk *disk;
  Queue<DiskVolBlockQueue> dpb_queue;
};

// Header for a span. This is a serialized data structure.
struct DiskHeader {
  // Holds a magic value :code:DISK_HEADER_MAGIC to indicate the span is valid and initialized.
  unsigned int magic;
  // Number of discrete volumes (DiskVol).
  // Number of cache volumes containing stripes in this span.
  unsigned int num_volumes;
  // number of disk volume blocks free.
  // The number of span blocks defined but not in use.
  unsigned int num_free;
  // Number of disk volume blocks in use.
  // The number of span blocks in use by stripes.
  unsigned int num_used;
  // The number of disk volume blocks.
  // The number of span blocks.
  unsigned int num_diskvol_blks;
  // The number of volume blocks in the span.
  uint64_t num_blocks;
  // A flexible array. The actual length of this array is
  // num_diskvol_blks and each element describes a span block.
  DiskVolBlock vol_info[1];
};

// A representation of the physical device used for a Span.
//
// This class is a continuation and so can be used to perform potentially blocking operations on the span.
// The primary use of these is to be passed to the AIO threads as the callback when an I/O operation completes.
// These are then dispatched to AIO threads to perform storage unit (which is obsolete term for cache span) initialization.
struct CacheDisk : public Continuation {
  DiskHeader *header = nullptr;
  char *path         = nullptr;
  int header_len     = 0;
  AIOCallbackInternal io;
  off_t len               = 0; // in blocks (STORE_BLOCK)
  off_t start             = 0;
  off_t skip              = 0;
  off_t num_usable_blocks = 0;
  int hw_sector_size      = 0;
  int fd                  = -1;
  off_t free_space        = 0;
  off_t wasted_space      = 0;
  DiskVol **disk_vols     = nullptr;
  DiskVol *free_blocks    = nullptr;
  int num_errors          = 0;
  int cleared             = 0;
  bool read_only_p        = false;
  bool online             = true; /* flag marking cache disk online or offline (because of too many failures or by the operator). */

  // Extra configuration values
  int forced_volume_num = -1;      ///< Volume number for this disk.
  ats_scoped_str hash_base_string; ///< Base string for hash seed.

  CacheDisk() : Continuation(new_ProxyMutex()) {}

  ~CacheDisk() override;

  int open(bool clear);
  int open(char *s, off_t blocks, off_t skip, int hw_sector_size, int fildes, bool clear);
  int clearDisk();
  int clearDone(int event, void *data);
  int openStart(int event, void *data);
  int openDone(int event, void *data);
  int sync();
  int syncDone(int event, void *data);
  DiskVolBlock *create_volume(int number, off_t size, int scheme);
  int delete_volume(int number);
  int delete_all_volumes();
  void update_header();
  DiskVol *get_diskvol(int vol_number);
  void incrErrors(const AIOCallback *io);
};
