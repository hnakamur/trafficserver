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

#include <atomic>

#define CACHE_BLOCK_SHIFT 9
#define CACHE_BLOCK_SIZE (1 << CACHE_BLOCK_SHIFT) // 512, smallest sector size
#define ROUND_TO_STORE_BLOCK(_x) INK_ALIGN((_x), STORE_BLOCK_SIZE)
#define ROUND_TO_CACHE_BLOCK(_x) INK_ALIGN((_x), CACHE_BLOCK_SIZE)
#define ROUND_TO_SECTOR(_p, _x) INK_ALIGN((_x), _p->sector_size)
#define ROUND_TO(_x, _y) INK_ALIGN((_x), (_y))

// Vol (volumes)
#define VOL_MAGIC 0xF1D0F00D
#define START_BLOCKS 16 // 8k, STORE_BLOCK_SIZE
#define START_POS ((off_t)START_BLOCKS * CACHE_BLOCK_SIZE)
#define AGG_SIZE (4 * 1024 * 1024)     // 4MB
#define AGG_HIGH_WATER (AGG_SIZE / 2)  // 2MB
#define EVACUATION_SIZE (2 * AGG_SIZE) // 8MB
#define MAX_VOL_SIZE ((off_t)512 * 1024 * 1024 * 1024 * 1024)
#define STORE_BLOCKS_PER_CACHE_BLOCK (STORE_BLOCK_SIZE / CACHE_BLOCK_SIZE)
#define MAX_VOL_BLOCKS (MAX_VOL_SIZE / CACHE_BLOCK_SIZE)
#define MAX_FRAG_SIZE (AGG_SIZE - sizeof(Doc)) // true max
#define LEAVE_FREE DEFAULT_MAX_BUFFER_SIZE
#define PIN_SCAN_EVERY 16 // scan every 1/16 of disk
#define VOL_HASH_TABLE_SIZE 32707
#define VOL_HASH_EMPTY 0xFFFF
#define VOL_HASH_ALLOC_SIZE (8 * 1024 * 1024) // one chance per this unit
#define LOOKASIDE_SIZE 256
#define EVACUATION_BUCKET_SIZE (2 * EVACUATION_SIZE) // 16MB
#define RECOVERY_SIZE EVACUATION_SIZE                // 8MB
#define AIO_NOT_IN_PROGRESS 0
#define AIO_AGG_WRITE_IN_PROGRESS -1
#define AUTO_SIZE_RAM_CACHE -1                               // 1-1 with directory size
#define DEFAULT_TARGET_FRAGMENT_SIZE (1048576 - sizeof(Doc)) // 1MB

#define dir_offset_evac_bucket(_o) (_o / (EVACUATION_BUCKET_SIZE / CACHE_BLOCK_SIZE))
#define dir_evac_bucket(_e) dir_offset_evac_bucket(dir_offset(_e))
#define offset_evac_bucket(_d, _o) \
  dir_offset_evac_bucket((_d->offset_to_vol_offset(_o)

// Documents

#define DOC_MAGIC ((uint32_t)0x5F129B13)
#define DOC_CORRUPT ((uint32_t)0xDEADBABE)
#define DOC_NO_CHECKSUM ((uint32_t)0xA0B0C0D0)

struct Cache;
struct Vol;
struct CacheDisk;
struct VolInitInfo;
struct DiskVol;
struct CacheVol;

// header or footer in stripe metadata.
struct VolHeaderFooter {
  // Container for a magic value, VOL_MAGIC, to indicate the instance is valid.
  unsigned int magic;
  // Version of the instance.
  ts::VersionNumber version;
  // Epoch time when the stripe was created.
  time_t create_time;
  // Position of the write cursor, as a byte offset in the stripe.
  off_t write_pos;
  // Location of the write cursor of the most recently completed disk write.
  off_t last_write_pos;
  // The byte offset in the stripe where the current aggregation buffer will be written.
  off_t agg_pos;
  // Generation of this instance.
  // token generation (vary), this cannot be 0.
  uint32_t generation;
  // phase which is filpped in `Vol::agg_wrap`
  uint32_t phase;
  // cycle which is incremented in `Vol::agg_wrap`
  uint32_t cycle;
  // sync serial counter which is incremented in CacheSync::mainEvent and sync_cache_dir_on_shutdown.
  uint32_t sync_serial;
  // write serial counter which is incremented in Vol::aggWriteDone and sync_cache_dir_on_shutdown.
  uint32_t write_serial;
  // dirty flag which is set in dir_delete_entry, dir_insert, and dir_overwrite.
  uint32_t dirty;
  uint32_t sector_size;
  uint32_t unused; // pad out to 8 byte boundary
  // Array whose element is the first directory entry in the free list for the segment corresponding to the array index.
  // For header, the actual array length is Vol::segments.
  // For footer, this is not used and the array length is 1.
  uint16_t freelist[1];
};

// Key and Earliest key for each fragment that needs to be evacuated
struct EvacuationKey {
  SLink<EvacuationKey> link;
  CryptoHash key;
  CryptoHash earliest_key;
};

struct EvacuationBlock {
  union {
    unsigned int init;
    struct {
      unsigned int done : 1;          // has been evacuated
      unsigned int pinned : 1;        // check pinning timeout
      unsigned int evacuate_head : 1; // check pinning timeout
      unsigned int unused : 29;
    } f;
  };

  int readers;
  Dir dir;
  Dir new_dir;
  // we need to have a list of evacuationkeys because of collision.
  EvacuationKey evac_frags;
  CacheVC *earliest_evacuator;
  LINK(EvacuationBlock, link);
};

// a storage unit inside a cache volume.
struct Vol : public Continuation {
  char *path = nullptr;
  ats_scoped_str hash_text;
  CryptoHash hash_id;
  int fd = -1;

  char *raw_dir           = nullptr;
  Dir *dir                = nullptr;
  VolHeaderFooter *header = nullptr;
  VolHeaderFooter *footer = nullptr;
  // The number of segments in the volume. This will be roughly the total number of entries divided by the number of entries in a
  // segment. It will be rounded up to cover all entries.
  int segments = 0;
  // The number of buckets in the volume. This will be roughly the number of entries in a segment divided by DIR_DEPTH. For
  // currently defined values this is around 16,384 (2^16 / 4). Buckets are used as the targets of the index hash.
  off_t buckets          = 0;
  off_t recover_pos      = 0;
  off_t prev_recover_pos = 0;
  off_t scan_pos         = 0;
  // The start of stripe data. This represents either space reserved at the start of a physical device to avoid problems with the
  // host operating system, or an offset representing use of space in the cache span by other stripes.
  off_t skip = 0;
  // The offset for the start of the content, after the stripe metadata.
  off_t start = 0;
  // Length of stripe in bytes.
  off_t len = 0;
  // The number of blocks of storage in the stripe.
  // Total number of blocks in the stripe available for content storage.
  off_t data_blocks       = 0;
  int hit_evacuate_window = 0;
  AIOCallbackInternal io;

  Queue<CacheVC, Continuation::Link_link> agg;
  Queue<CacheVC, Continuation::Link_link> stat_cache_vcs;
  Queue<CacheVC, Continuation::Link_link> sync;
  char *agg_buffer  = nullptr;
  int agg_todo_size = 0;
  // position in the aggregation buffer. This is set to `round_to_approx_size(sizeof(Doc))` when writing sync marker in
  // Vol::aggWrite.
  int agg_buf_pos = 0;

  Event *trigger = nullptr;

  OpenDir open_dir;
  RamCache *ram_cache            = nullptr;
  int evacuate_size              = 0;
  DLL<EvacuationBlock> *evacuate = nullptr;
  DLL<EvacuationBlock> lookaside[LOOKASIDE_SIZE];
  CacheVC *doc_evacuator = nullptr;

  VolInitInfo *init_info = nullptr;

  CacheDisk *disk            = nullptr;
  Cache *cache               = nullptr;
  CacheVol *cache_vol        = nullptr;
  uint32_t last_sync_serial  = 0;
  uint32_t last_write_serial = 0;
  uint32_t sector_size       = 0;
  bool recover_wrapped       = false;
  bool dir_sync_waiting      = false;
  bool dir_sync_in_progress  = false;
  bool writing_end_marker    = false;

  CacheKey first_fragment_key;
  int64_t first_fragment_offset = 0;
  Ptr<IOBufferData> first_fragment_data;

  void cancel_trigger();

  int recover_data();

  int open_write(CacheVC *cont, int allow_if_writers, int max_writers);
  int open_write_lock(CacheVC *cont, int allow_if_writers, int max_writers);
  int close_write(CacheVC *cont);
  int close_write_lock(CacheVC *cont);
  int begin_read(CacheVC *cont);
  int begin_read_lock(CacheVC *cont);
  // unused read-write interlock code
  // currently http handles a write-lock failure by retrying the read
  OpenDirEntry *open_read(const CryptoHash *key);
  OpenDirEntry *open_read_lock(CryptoHash *key, EThread *t);
  int close_read(CacheVC *cont);
  int close_read_lock(CacheVC *cont);

  int clear_dir();

  int init(char *s, off_t blocks, off_t dir_skip, bool clear);

  int handle_dir_clear(int event, void *data);
  int handle_dir_read(int event, void *data);
  int handle_recover_from_data(int event, void *data);
  int handle_recover_write_dir(int event, void *data);
  int handle_header_read(int event, void *data);

  int dir_init_done(int event, void *data);

  int dir_check(bool fix);
  int db_check(bool fix);

  int
  is_io_in_progress()
  {
    return io.aiocb.aio_fildes != AIO_NOT_IN_PROGRESS;
  }
  int
  increment_generation()
  {
    // this is stored in the offset field of the directory (!=0)
    ink_assert(mutex->thread_holding == this_ethread());
    header->generation++;
    if (!header->generation)
      header->generation++;
    return header->generation;
  }
  void
  set_io_not_in_progress()
  {
    io.aiocb.aio_fildes = AIO_NOT_IN_PROGRESS;
  }

  int aggWriteDone(int event, Event *e);
  int aggWrite(int event, void *e);
  void agg_wrap();

  int evacuateWrite(CacheVC *evacuator, int event, Event *e);
  int evacuateDocReadDone(int event, Event *e);
  int evacuateDoc(int event, Event *e);

  int evac_range(off_t start, off_t end, int evac_phase);
  void periodic_scan();
  void scan_for_pinned_documents();
  void evacuate_cleanup_blocks(int i);
  void evacuate_cleanup();
  EvacuationBlock *force_evacuate_head(Dir *dir, int pinned);
  int within_hit_evacuate_window(Dir *dir);
  uint32_t round_to_approx_size(uint32_t l);

  // inline functions
  int headerlen();         // calculates the total length of the vol header and the freelist
  int direntries();        // total number of dir entries
  Dir *dir_segment(int s); // returns the first dir in the segment s
  size_t dirlen();         // calculates the total length of header, directories and footer
  int vol_out_of_phase_valid(Dir *e);

  int vol_out_of_phase_agg_valid(Dir *e);
  int vol_out_of_phase_write_valid(Dir *e);
  int vol_in_phase_valid(Dir *e);
  int vol_in_phase_agg_buf_valid(Dir *e);

  off_t vol_offset(Dir *e);
  off_t offset_to_vol_offset(off_t pos);
  off_t vol_offset_to_offset(off_t pos);
  off_t vol_relative_length(off_t start_offset);

  Vol() : Continuation(new_ProxyMutex())
  {
    open_dir.mutex = mutex;
    agg_buffer     = (char *)ats_memalign(ats_pagesize(), AGG_SIZE);
    memset(agg_buffer, 0, AGG_SIZE);
    SET_HANDLER(&Vol::aggWrite);
  }

  ~Vol() override { ats_memalign_free(agg_buffer); }
};

struct AIO_Callback_handler : public Continuation {
  int handle_disk_failure(int event, void *data);

  AIO_Callback_handler() : Continuation(new_ProxyMutex()) { SET_HANDLER(&AIO_Callback_handler::handle_disk_failure); }
};

// A cache volume as described in volume.config.
// This class represents a single volume.
// CacheVol comprises of stripes spread across Spans(disks)
struct CacheVol {
  // identification number of this volume
  int vol_number = -1;
  // An enumeration of value CacheType::HTTP or CacheType::Stream.
  int scheme = 0;
  off_t size = 0;
  // Number of stripes(Vol) contained in this volume
  int num_vols          = 0;
  bool ramcache_enabled = true;
  // Vol represents a single stripe in the disk. vols contains all the stripes this volume is made up of
  Vol **vols = nullptr;
  // disk_vols contain references to the disks of all the stripes in this volum
  DiskVol **disk_vols = nullptr;
  LINK(CacheVol, link);
  // per volume stats
  RecRawStatBlock *vol_rsb = nullptr;

  CacheVol() {}
};

// the header data for a fragment.
// Note : hdr() needs to be 8 byte aligned.
struct Doc {
  uint32_t magic; // DOC_MAGIC
  // The length of this segment including the header length, fragment table, and this structure.
  // length of this fragment (including hlen & sizeof(Doc), unrounded)
  uint32_t len;
  // Total length of document.
  // Total length of the entire document not including meta data but including headers.
  uint64_t total_len;
#if TS_ENABLE_FIPS == 1
  // For FIPS CryptoHash is 256 bits vs. 128, and the 'first_key' must be checked first, so
  // ensure that the new 'first_key' overlaps the old 'first_key' and that the rest of the data layout
  // is the same by putting 'key' at the ned.
  CryptoHash first_key; ///< first key in object.
#else
  // first key in object.
  // First index key in the document (the index key used to locate this object in the volume index).
  CryptoHash first_key;
  // Key for this doc.
  // The index key for this fragment. Fragment keys are computationally chained so that the key
  // for the next and previous fragments can be computed from this key.
  CryptoHash key;
#endif
  // Length of this header.
  // Document header (metadata) length. This is not the length of the HTTP headers.
  uint32_t hlen;
  uint32_t doc_type : 8; ///< Doc type - indicates the format of this structure and its content.
  uint32_t v_major : 8;  ///< Major version number.
  uint32_t v_minor : 8;  ///< Minor version number.
  uint32_t unused : 8;   ///< Unused, forced to zero.
  uint32_t sync_serial;
  uint32_t write_serial;
  // pinned until.
  // Flag and timer for pinned objects.
  uint32_t pinned;
  uint32_t checksum;
#if TS_ENABLE_FIPS == 1
  CryptoHash key; ///< Key for this doc.
#endif

  uint32_t data_len();
  uint32_t prefix_len();
  int single_fragment();
  int no_data_in_fragment();
  char *hdr();
  char *data();
};

// Global Data

extern Vol **gvol;
extern std::atomic<int> gnvol;
extern ClassAllocator<OpenDirEntry> openDirEntryAllocator;
extern ClassAllocator<EvacuationBlock> evacuationBlockAllocator;
extern ClassAllocator<EvacuationKey> evacuationKeyAllocator;
extern unsigned short *vol_hash_table;

// inline Functions

/* @brief returns the byte length of header (VolHeaderFooter) and the freelist.
 * @return the byte length of header (VolHeaderFooter) and the freelist.
 */
TS_INLINE int
Vol::headerlen()
{
  return ROUND_TO_STORE_BLOCK(sizeof(VolHeaderFooter) + sizeof(uint16_t) * (this->segments - 1));
}

/* @brief returns the Dir pointer to the start of the segment
 * @param s the segment index
 * @return the Dir pointer to the start of the segment
 */
TS_INLINE Dir *
Vol::dir_segment(int s)
{
  return (Dir *)(((char *)this->dir) + (s * this->buckets) * DIR_DEPTH * SIZEOF_DIR);
}

/* @brief returns total byte length of header, dir, and footer.
 * @return total byte length of header, dir, and footer.
 */
TS_INLINE size_t
Vol::dirlen()
{
  return this->headerlen() + ROUND_TO_STORE_BLOCK(((size_t)this->buckets) * DIR_DEPTH * this->segments * SIZEOF_DIR) +
         ROUND_TO_STORE_BLOCK(sizeof(VolHeaderFooter));
}

/* @brief returns the number of dir entries.
 * @return the number of dir entries.
 */
TS_INLINE int
Vol::direntries()
{
  return this->buckets * DIR_DEPTH * this->segments;
}

TS_INLINE int
Vol::vol_out_of_phase_valid(Dir *e)
{
  return (dir_offset(e) - 1 >= ((this->header->agg_pos - this->start) / CACHE_BLOCK_SIZE));
}

TS_INLINE int
Vol::vol_out_of_phase_agg_valid(Dir *e)
{
  return (dir_offset(e) - 1 >= ((this->header->agg_pos - this->start + AGG_SIZE) / CACHE_BLOCK_SIZE));
}

TS_INLINE int
Vol::vol_out_of_phase_write_valid(Dir *e)
{
  return (dir_offset(e) - 1 >= ((this->header->write_pos - this->start) / CACHE_BLOCK_SIZE));
}

TS_INLINE int
Vol::vol_in_phase_valid(Dir *e)
{
  return (dir_offset(e) - 1 < ((this->header->write_pos + this->agg_buf_pos - this->start) / CACHE_BLOCK_SIZE));
}

TS_INLINE off_t
Vol::vol_offset(Dir *e)
{
  return this->start + (off_t)dir_offset(e) * CACHE_BLOCK_SIZE - CACHE_BLOCK_SIZE;
}

/* @brief convert a byte offset to a vol offset.
 * @param pos is a byte offset
 * @return a vol offset (cache block index) (=ceil((pos - this->start) / CACHE_BLOCK_SIZE (512byte)))
 */
TS_INLINE off_t
Vol::offset_to_vol_offset(off_t pos)
{
  return ((pos - this->start + CACHE_BLOCK_SIZE) / CACHE_BLOCK_SIZE);
}

/* @brief convert a vol offset to a byte offset.
 * @param pos is a vol offset (cache block index).
 * @return a byte offset (= this->start + (pos - 1) * CACHE_BLOCK_SIZE (512byte))
 */
TS_INLINE off_t
Vol::vol_offset_to_offset(off_t pos)
{
  return this->start + pos * CACHE_BLOCK_SIZE - CACHE_BLOCK_SIZE;
}

TS_INLINE int
Vol::vol_in_phase_agg_buf_valid(Dir *e)
{
  return (this->vol_offset(e) >= this->header->write_pos && this->vol_offset(e) < (this->header->write_pos + this->agg_buf_pos));
}
// length of the partition not including the offset of location 0.
TS_INLINE off_t
Vol::vol_relative_length(off_t start_offset)
{
  return (this->len + this->skip) - start_offset;
}

TS_INLINE uint32_t
Doc::prefix_len()
{
  return sizeof(Doc) + hlen;
}

TS_INLINE uint32_t
Doc::data_len()
{
  return len - sizeof(Doc) - hlen;
}

TS_INLINE int
Doc::single_fragment()
{
  return data_len() == total_len;
}

TS_INLINE char *
Doc::hdr()
{
  return reinterpret_cast<char *>(this) + sizeof(Doc);
}

TS_INLINE char *
Doc::data()
{
  return this->hdr() + hlen;
}

int vol_dir_clear(Vol *d);
int vol_init(Vol *d, char *s, off_t blocks, off_t skip, bool clear);

// inline Functions

TS_INLINE EvacuationBlock *
evacuation_block_exists(Dir *dir, Vol *p)
{
  EvacuationBlock *b = p->evacuate[dir_evac_bucket(dir)].head;
  for (; b; b = b->link.next)
    if (dir_offset(&b->dir) == dir_offset(dir))
      return b;
  return nullptr;
}

TS_INLINE void
Vol::cancel_trigger()
{
  if (trigger) {
    trigger->cancel_action();
    trigger = nullptr;
  }
}

TS_INLINE EvacuationBlock *
new_EvacuationBlock(EThread *t)
{
  EvacuationBlock *b      = THREAD_ALLOC(evacuationBlockAllocator, t);
  b->init                 = 0;
  b->readers              = 0;
  b->earliest_evacuator   = nullptr;
  b->evac_frags.link.next = nullptr;
  return b;
}

TS_INLINE void
free_EvacuationBlock(EvacuationBlock *b, EThread *t)
{
  EvacuationKey *e = b->evac_frags.link.next;
  while (e) {
    EvacuationKey *n = e->link.next;
    evacuationKeyAllocator.free(e);
    e = n;
  }
  THREAD_FREE(b, evacuationBlockAllocator, t);
}

TS_INLINE OpenDirEntry *
Vol::open_read(const CryptoHash *key)
{
  return open_dir.open_read(key);
}

TS_INLINE int
Vol::within_hit_evacuate_window(Dir *xdir)
{
  off_t oft       = dir_offset(xdir) - 1;
  off_t write_off = (header->write_pos + AGG_SIZE - start) / CACHE_BLOCK_SIZE;
  off_t delta     = oft - write_off;
  if (delta >= 0)
    return delta < hit_evacuate_window;
  else
    return -delta > (data_blocks - hit_evacuate_window) && -delta < data_blocks;
}

TS_INLINE uint32_t
Vol::round_to_approx_size(uint32_t l)
{
  uint32_t ll = round_to_approx_dir_size(l);
  return ROUND_TO_SECTOR(this, ll);
}
