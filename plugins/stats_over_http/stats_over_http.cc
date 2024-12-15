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

/* stats.c:  expose traffic server stats over http
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <limits.h>
#include <ts/ts.h>
#include <string.h>
#include <inttypes.h>
#include <getopt.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <fstream>
#include <chrono>
#include <mutex>
#include <unordered_map>

#include <ts/remap.h>

#include "swoc/swoc_ip.h"

#include <tsutil/ts_ip.h>

#include "tscore/ink_config.h"
#if HAVE_BROTLI_ENCODE_H
#include <brotli/encode.h>
#endif

#define PLUGIN_NAME     "stats_over_http"
#define FREE_TMOUT      300000
#define STR_BUFFER_SIZE 1024

#define SYSTEM_RECORD_TYPE   (0x100)
#define DEFAULT_RECORD_TYPES (SYSTEM_RECORD_TYPE | TS_RECORDTYPE_PROCESS | TS_RECORDTYPE_PLUGIN)

static DbgCtl dbg_ctl{PLUGIN_NAME};

static const swoc::IP4Range DEFAULT_IP{swoc::IP4Addr::MIN, swoc::IP4Addr::MAX};
static const swoc::IP6Range DEFAULT_IP6{swoc::IP6Addr::MIN, swoc::IP6Addr::MAX};

/* global holding the path used for access to this JSON data */
std::string const DEFAULT_URL_PATH = "_stats";

// from mod_deflate:
// ZLIB's compression algorithm uses a
// 0-9 based scale that GZIP does where '1' is 'Best speed'
// and '9' is 'Best compression'. Testing has proved level '6'
// to be about the best level to use in an HTTP Server.

const int   ZLIB_COMPRESSION_LEVEL = 6;
const char *dictionary             = nullptr;

// zlib stuff, see [deflateInit2] at http://www.zlib.net/manual.html
static const int ZLIB_MEMLEVEL = 9; // min=1 (optimize for memory),max=9 (optimized for speed)

static const int WINDOW_BITS_DEFLATE = 15;
static const int WINDOW_BITS_GZIP    = 16;
#define DEFLATE_MODE WINDOW_BITS_DEFLATE
#define GZIP_MODE    (WINDOW_BITS_DEFLATE | WINDOW_BITS_GZIP)

// brotli compression quality 1-11. Testing proved level '6'
#if HAVE_BROTLI_ENCODE_H
const int BROTLI_COMPRESSION_LEVEL = 6;
const int BROTLI_LGW               = 16;
#endif

static bool integer_counters = false;
static bool wrap_counters    = false;

struct config_t {
  unsigned int     recordTypes;
  std::string      stats_path;
  swoc::IPRangeSet addrs;
};
struct config_holder_t {
  char           *config_path;
  volatile time_t last_load;
  config_t       *config;
};

enum output_format { JSON_OUTPUT, CSV_OUTPUT, TEXT_PROMETHEUS_OUTPUT };
enum encoding_format { NONE, DEFLATE, GZIP, BR };

int    configReloadRequests = 0;
int    configReloads        = 0;
time_t lastReloadRequest    = 0;
time_t lastReload           = 0;
time_t astatsLoad           = 0;

static int              free_handler(TSCont cont, TSEvent event, void *edata);
static int              config_handler(TSCont cont, TSEvent event, void *edata);
static config_t        *get_config(TSCont cont);
static config_holder_t *new_config_holder(const char *path);
static bool             is_ipmap_allowed(const config_t *config, const struct sockaddr *addr);

#if HAVE_BROTLI_ENCODE_H
struct b_stream {
  BrotliEncoderState *br;
  uint8_t            *next_in;
  size_t              avail_in;
  uint8_t            *next_out;
  size_t              avail_out;
  size_t              total_in;
  size_t              total_out;
};
#endif

struct stats_state {
  TSVConn net_vc;
  TSVIO   read_vio;
  TSVIO   write_vio;

  TSIOBuffer       req_buffer;
  TSIOBuffer       resp_buffer;
  TSIOBufferReader resp_reader;

  int             output_bytes;
  int             body_written;
  output_format   output;
  encoding_format encoding;
  z_stream        zstrm;
#if HAVE_BROTLI_ENCODE_H
  b_stream bstrm;
#endif
};

static char *
nstr(const char *s)
{
  char *mys = (char *)TSmalloc(strlen(s) + 1);
  strcpy(mys, s);
  return mys;
}

#if HAVE_BROTLI_ENCODE_H
encoding_format
init_br(stats_state *my_state)
{
  my_state->bstrm.br = nullptr;

  my_state->bstrm.br = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
  if (!my_state->bstrm.br) {
    Dbg(dbg_ctl, "Brotli Encoder Instance Failed");
    return NONE;
  }
  BrotliEncoderSetParameter(my_state->bstrm.br, BROTLI_PARAM_QUALITY, BROTLI_COMPRESSION_LEVEL);
  BrotliEncoderSetParameter(my_state->bstrm.br, BROTLI_PARAM_LGWIN, BROTLI_LGW);
  my_state->bstrm.next_in   = nullptr;
  my_state->bstrm.avail_in  = 0;
  my_state->bstrm.total_in  = 0;
  my_state->bstrm.next_out  = nullptr;
  my_state->bstrm.avail_out = 0;
  my_state->bstrm.total_out = 0;
  return BR;
}
#endif

namespace
{
inline uint64_t
ms_since_epoch()
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
} // namespace

encoding_format
init_gzip(stats_state *my_state, int mode)
{
  my_state->zstrm.next_in   = Z_NULL;
  my_state->zstrm.avail_in  = 0;
  my_state->zstrm.total_in  = 0;
  my_state->zstrm.next_out  = Z_NULL;
  my_state->zstrm.avail_out = 0;
  my_state->zstrm.total_out = 0;
  my_state->zstrm.zalloc    = Z_NULL;
  my_state->zstrm.zfree     = Z_NULL;
  my_state->zstrm.opaque    = Z_NULL;
  my_state->zstrm.data_type = Z_ASCII;
  int err = deflateInit2(&my_state->zstrm, ZLIB_COMPRESSION_LEVEL, Z_DEFLATED, mode, ZLIB_MEMLEVEL, Z_DEFAULT_STRATEGY);
  if (err != Z_OK) {
    Dbg(dbg_ctl, "gzip initialization failed");
    return NONE;
  } else {
    Dbg(dbg_ctl, "gzip initialized successfully");
    if (mode == GZIP_MODE) {
      return GZIP;
    } else if (mode == DEFLATE_MODE) {
      return DEFLATE;
    }
  }
  return NONE;
}

static void
stats_cleanup(TSCont contp, stats_state *my_state)
{
  if (my_state->req_buffer) {
    TSIOBufferDestroy(my_state->req_buffer);
    my_state->req_buffer = nullptr;
  }

  if (my_state->resp_buffer) {
    TSIOBufferDestroy(my_state->resp_buffer);
    my_state->resp_buffer = nullptr;
  }

  TSVConnClose(my_state->net_vc);
  TSfree(my_state);
  TSContDestroy(contp);
}

static void
stats_process_accept(TSCont contp, stats_state *my_state)
{
  my_state->req_buffer  = TSIOBufferCreate();
  my_state->resp_buffer = TSIOBufferCreate();
  my_state->resp_reader = TSIOBufferReaderAlloc(my_state->resp_buffer);
  my_state->read_vio    = TSVConnRead(my_state->net_vc, contp, my_state->req_buffer, INT64_MAX);
}

static int
stats_add_data_to_resp_buffer(const char *s, stats_state *my_state)
{
  int s_len = strlen(s);

  TSIOBufferWrite(my_state->resp_buffer, s, s_len);

  return s_len;
}

static const char RESP_HEADER_JSON[] = "HTTP/1.0 200 OK\r\nContent-Type: text/json\r\nCache-Control: no-cache\r\n\r\n";
static const char RESP_HEADER_JSON_GZIP[] =
  "HTTP/1.0 200 OK\r\nContent-Type: text/json\r\nContent-Encoding: gzip\r\nCache-Control: no-cache\r\n\r\n";
static const char RESP_HEADER_JSON_DEFLATE[] =
  "HTTP/1.0 200 OK\r\nContent-Type: text/json\r\nContent-Encoding: deflate\r\nCache-Control: no-cache\r\n\r\n";
static const char RESP_HEADER_JSON_BR[] =
  "HTTP/1.0 200 OK\r\nContent-Type: text/json\r\nContent-Encoding: br\r\nCache-Control: no-cache\r\n\r\n";
static const char RESP_HEADER_CSV[] = "HTTP/1.0 200 OK\r\nContent-Type: text/csv\r\nCache-Control: no-cache\r\n\r\n";
static const char RESP_HEADER_CSV_GZIP[] =
  "HTTP/1.0 200 OK\r\nContent-Type: text/csv\r\nContent-Encoding: gzip\r\nCache-Control: no-cache\r\n\r\n";
static const char RESP_HEADER_CSV_DEFLATE[] =
  "HTTP/1.0 200 OK\r\nContent-Type: text/csv\r\nContent-Encoding: deflate\r\nCache-Control: no-cache\r\n\r\n";
static const char RESP_HEADER_CSV_BR[] =
  "HTTP/1.0 200 OK\r\nContent-Type: text/csv\r\nContent-Encoding: br\r\nCache-Control: no-cache\r\n\r\n";
static const char RESP_HEADER_TEXT_PROMETHEUS[] =
  "HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nCache-Control: no-cache\r\n\r\n";
static const char RESP_HEADER_TEXT_PROMETHEUS_GZIP[] =
  "HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Encoding: gzip\r\nCache-Control: no-cache\r\n\r\n";

static int
stats_add_resp_header(stats_state *my_state)
{
  switch (my_state->output) {
  case JSON_OUTPUT:
    if (my_state->encoding == GZIP) {
      return stats_add_data_to_resp_buffer(RESP_HEADER_JSON_GZIP, my_state);
    } else if (my_state->encoding == DEFLATE) {
      return stats_add_data_to_resp_buffer(RESP_HEADER_JSON_DEFLATE, my_state);
    } else if (my_state->encoding == BR) {
      return stats_add_data_to_resp_buffer(RESP_HEADER_JSON_BR, my_state);
    } else {
      return stats_add_data_to_resp_buffer(RESP_HEADER_JSON, my_state);
    }
    break;
  case CSV_OUTPUT:
    if (my_state->encoding == GZIP) {
      return stats_add_data_to_resp_buffer(RESP_HEADER_CSV_GZIP, my_state);
    } else if (my_state->encoding == DEFLATE) {
      return stats_add_data_to_resp_buffer(RESP_HEADER_CSV_DEFLATE, my_state);
    } else if (my_state->encoding == BR) {
      return stats_add_data_to_resp_buffer(RESP_HEADER_CSV_BR, my_state);
    } else {
      return stats_add_data_to_resp_buffer(RESP_HEADER_CSV, my_state);
    }
    break;
  case TEXT_PROMETHEUS_OUTPUT:
    if (my_state->encoding == GZIP) {
      return stats_add_data_to_resp_buffer(RESP_HEADER_TEXT_PROMETHEUS_GZIP, my_state);
    } else {
      return stats_add_data_to_resp_buffer(RESP_HEADER_TEXT_PROMETHEUS, my_state);
    }
    break;
  default:
    TSError("stats_add_resp_header: Unknown output format");
    break;
  }
  return stats_add_data_to_resp_buffer(RESP_HEADER_JSON, my_state);
}

static void
stats_process_read(TSCont contp, TSEvent event, stats_state *my_state)
{
  Dbg(dbg_ctl, "stats_process_read(%d)", event);
  if (event == TS_EVENT_VCONN_READ_READY) {
    my_state->output_bytes = stats_add_resp_header(my_state);
    TSVConnShutdown(my_state->net_vc, 1, 0);
    my_state->write_vio = TSVConnWrite(my_state->net_vc, contp, my_state->resp_reader, INT64_MAX);
  } else if (event == TS_EVENT_ERROR) {
    TSError("[%s] stats_process_read: Received TS_EVENT_ERROR", PLUGIN_NAME);
  } else if (event == TS_EVENT_VCONN_EOS) {
    /* client may end the connection, simply return */
    return;
  } else if (event == TS_EVENT_NET_ACCEPT_FAILED) {
    TSError("[%s] stats_process_read: Received TS_EVENT_NET_ACCEPT_FAILED", PLUGIN_NAME);
  } else {
    printf("Unexpected Event %d\n", event);
    TSReleaseAssert(!"Unexpected Event");
  }
}

#define APPEND(a) my_state->output_bytes += stats_add_data_to_resp_buffer(a, my_state)
#define APPEND_STAT_JSON(a, fmt, v)                                              \
  do {                                                                           \
    char b[256];                                                                 \
    if (snprintf(b, sizeof(b), "\"%s\": \"" fmt "\",\n", a, v) < (int)sizeof(b)) \
      APPEND(b);                                                                 \
  } while (0)
#define APPEND_STAT_JSON_NUMERIC(a, fmt, v)                                          \
  do {                                                                               \
    char b[256];                                                                     \
    if (integer_counters) {                                                          \
      if (snprintf(b, sizeof(b), "\"%s\": " fmt ",\n", a, v) < (int)sizeof(b)) {     \
        APPEND(b);                                                                   \
      }                                                                              \
    } else {                                                                         \
      if (snprintf(b, sizeof(b), "\"%s\": \"" fmt "\",\n", a, v) < (int)sizeof(b)) { \
        APPEND(b);                                                                   \
      }                                                                              \
    }                                                                                \
  } while (0)

#define APPEND_STAT_CSV(a, fmt, v)                                     \
  do {                                                                 \
    char b[256];                                                       \
    if (snprintf(b, sizeof(b), "%s," fmt "\n", a, v) < (int)sizeof(b)) \
      APPEND(b);                                                       \
  } while (0)
#define APPEND_STAT_CSV_NUMERIC(a, fmt, v)                               \
  do {                                                                   \
    char b[256];                                                         \
    if (snprintf(b, sizeof(b), "%s," fmt "\n", a, v) < (int)sizeof(b)) { \
      APPEND(b);                                                         \
    }                                                                    \
  } while (0)

// This wraps uint64_t values to the int64_t range to fit into a Java long. Java 8 has an unsigned long which
// can interoperate with a full uint64_t, but it's unlikely that much of the ecosystem supports that yet.
static uint64_t
wrap_unsigned_counter(uint64_t value)
{
  if (wrap_counters) {
    return (value > INT64_MAX) ? value % INT64_MAX : value;
  } else {
    return value;
  }
}

static void
json_out_stat(TSRecordType /* rec_type ATS_UNUSED */, void *edata, int /* registered ATS_UNUSED */, const char *name,
              TSRecordDataType data_type, TSRecordData *datum)
{
  stats_state *my_state = static_cast<stats_state *>(edata);

  switch (data_type) {
  case TS_RECORDDATATYPE_COUNTER:
    APPEND_STAT_JSON_NUMERIC(name, "%" PRIu64, wrap_unsigned_counter(datum->rec_counter));
    break;
  case TS_RECORDDATATYPE_INT:
    APPEND_STAT_JSON_NUMERIC(name, "%" PRIu64, wrap_unsigned_counter(datum->rec_int));
    break;
  case TS_RECORDDATATYPE_FLOAT:
    APPEND_STAT_JSON_NUMERIC(name, "%f", datum->rec_float);
    break;
  case TS_RECORDDATATYPE_STRING:
    APPEND_STAT_JSON(name, "%s", datum->rec_string);
    break;
  default:
    Dbg(dbg_ctl, "unknown type for %s: %d", name, data_type);
    break;
  }
}

static void
csv_out_stat(TSRecordType /* rec_type ATS_UNUSED */, void *edata, int /* registered ATS_UNUSED */, const char *name,
             TSRecordDataType data_type, TSRecordData *datum)
{
  stats_state *my_state = static_cast<stats_state *>(edata);
  switch (data_type) {
  case TS_RECORDDATATYPE_COUNTER:
    APPEND_STAT_CSV_NUMERIC(name, "%" PRIu64, wrap_unsigned_counter(datum->rec_counter));
    break;
  case TS_RECORDDATATYPE_INT:
    APPEND_STAT_CSV_NUMERIC(name, "%" PRIu64, wrap_unsigned_counter(datum->rec_int));
    break;
  case TS_RECORDDATATYPE_FLOAT:
    APPEND_STAT_CSV_NUMERIC(name, "%f", datum->rec_float);
    break;
  case TS_RECORDDATATYPE_STRING:
    APPEND_STAT_CSV(name, "%s", datum->rec_string);
    break;
  default:
    Dbg(dbg_ctl, "unknown type for %s: %d", name, data_type);
    break;
  }
}

static void
json_out_stats(stats_state *my_state)
{
  const char *version;
  APPEND("{ \"global\": {\n");
  TSRecordDump((TSRecordType)(TS_RECORDTYPE_PLUGIN | TS_RECORDTYPE_NODE | TS_RECORDTYPE_PROCESS), json_out_stat, my_state);
  version = TSTrafficServerVersionGet();
  APPEND_STAT_JSON_NUMERIC("current_time_epoch_ms", "%" PRIu64, ms_since_epoch());
  APPEND("\"server\": \"");
  APPEND(version);
  APPEND("\"\n");

  APPEND("  }\n}\n");
}

#if HAVE_BROTLI_ENCODE_H
// Takes an input stats state struct holding the uncompressed
// stats values. Compresses and copies it back into the state struct
static void
br_out_stats(stats_state *my_state)
{
  size_t  outputsize = BrotliEncoderMaxCompressedSize(my_state->output_bytes);
  uint8_t inputbuf[my_state->output_bytes];
  uint8_t outputbuf[outputsize];

  memset(&inputbuf, 0, sizeof(inputbuf));
  memset(&outputbuf, 0, sizeof(outputbuf));

  int64_t inputbytes = TSIOBufferReaderCopy(my_state->resp_reader, &inputbuf, my_state->output_bytes);

  // Consume existing uncompressed buffer now that it has been stored to
  // free up the buffer to contain the compressed data
  int64_t toconsume = TSIOBufferReaderAvail(my_state->resp_reader);
  TSIOBufferReaderConsume(my_state->resp_reader, toconsume);
  my_state->output_bytes -= toconsume;
  BROTLI_BOOL err = BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE, inputbytes, inputbuf,
                                          &outputsize, outputbuf);

  if (err == BROTLI_FALSE) {
    Dbg(dbg_ctl, "brotli compress error");
  }
  my_state->output_bytes += TSIOBufferWrite(my_state->resp_buffer, outputbuf, outputsize);
  BrotliEncoderDestroyInstance(my_state->bstrm.br);
}
#endif

// Takes an input stats state struct holding the uncompressed
// stats values. Compresses and copies it back into the state struct
static void
gzip_out_stats(stats_state *my_state)
{
  char inputbuf[my_state->output_bytes];
  char outputbuf[deflateBound(&my_state->zstrm, my_state->output_bytes)];
  memset(&inputbuf, 0, sizeof(inputbuf));
  memset(&outputbuf, 0, sizeof(outputbuf));

  int64_t inputbytes = TSIOBufferReaderCopy(my_state->resp_reader, &inputbuf, my_state->output_bytes);

  // Consume existing uncompressed buffer now that it has been stored to
  // free up the buffer to contain the compressed data
  int64_t toconsume = TSIOBufferReaderAvail(my_state->resp_reader);
  TSIOBufferReaderConsume(my_state->resp_reader, toconsume);

  my_state->output_bytes    -= toconsume;
  my_state->zstrm.avail_in   = inputbytes;
  my_state->zstrm.avail_out  = sizeof(outputbuf);
  my_state->zstrm.next_in    = (Bytef *)inputbuf;
  my_state->zstrm.next_out   = (Bytef *)outputbuf;
  int err                    = deflate(&my_state->zstrm, Z_FINISH);
  if (err != Z_STREAM_END) {
    Dbg(dbg_ctl, "deflate error: %d", err);
  }

  err = deflateEnd(&my_state->zstrm);
  if (err != Z_OK) {
    Dbg(dbg_ctl, "deflate end err: %d", err);
  }

  my_state->output_bytes += TSIOBufferWrite(my_state->resp_buffer, outputbuf, my_state->zstrm.total_out);
}

static void
csv_out_stats(stats_state *my_state)
{
  TSRecordDump((TSRecordType)(TS_RECORDTYPE_PLUGIN | TS_RECORDTYPE_NODE | TS_RECORDTYPE_PROCESS), csv_out_stat, my_state);
  const char *version = TSTrafficServerVersionGet();
  APPEND_STAT_CSV_NUMERIC("current_time_epoch_ms", "%" PRIu64, ms_since_epoch());
  APPEND_STAT_CSV("version", "%s", version);
}

struct prom_metric_info {
  const char *prom_name;
  const char *type;
  const char *help;
};

#define COUNTER "counter"
#define GAUGE   "gauge"

static const std::unordered_map<std::string_view, prom_metric_info> prom_metric_info_map = {
  // src/iocore/aio/AIO.cc
  {"proxy.process.cache.aio.read_count",                                 {"proxy_process_cache_aio_read_count", COUNTER, nullptr}                                 },
  {"proxy.process.cache.aio.write_count",                                {"proxy_process_cache_aio_write_count", COUNTER, nullptr}                                },
  {"proxy.process.cache.aio.KB_read",                                    {"proxy_process_cache_aio_KB_read", COUNTER, nullptr}                                    },
  {"proxy.process.cache.aio.KB_write",                                   {"proxy_process_cache_aio_KB_write", COUNTER, nullptr}                                   },

  // src/iocore/cache/Cache.cc
  {"proxy.process.cache.lookup.active",                                  {"proxy_process_cache_lookup_active", GAUGE, nullptr}                                    },
  {"proxy.process.cache.lookup.success",                                 {"proxy_process_cache_lookup_success", COUNTER, nullptr}                                 },
  {"proxy.process.cache.lookup.failure",                                 {"proxy_process_cache_lookup_failure", COUNTER, nullptr}                                 },
  {"proxy.process.cache.read.active",                                    {"proxy_process_cache_read_active", GAUGE, nullptr}                                      },
  {"proxy.process.cache.read.success",                                   {"proxy_process_cache_read_success", COUNTER, nullptr}                                   },
  {"proxy.process.cache.read.failure",                                   {"proxy_process_cache_read_failure", COUNTER, nullptr}                                   },
  {"proxy.process.cache.write.active",                                   {"proxy_process_cache_write_active", GAUGE, nullptr}                                     },
  {"proxy.process.cache.write.success",                                  {"proxy_process_cache_write_success", COUNTER, nullptr}                                  },
  {"proxy.process.cache.write.failure",                                  {"proxy_process_cache_write_failure", COUNTER, nullptr}                                  },
  {"proxy.process.cache.update.active",                                  {"proxy_process_cache_update_active", GAUGE, nullptr}                                    },
  {"proxy.process.cache.update.success",                                 {"proxy_process_cache_update_success", COUNTER, nullptr}                                 },
  {"proxy.process.cache.update.failure",                                 {"proxy_process_cache_update_failure", COUNTER, nullptr}                                 },
  {"proxy.process.cache.remove.active",                                  {"proxy_process_cache_remove_active", GAUGE, nullptr}                                    },
  {"proxy.process.cache.remove.success",                                 {"proxy_process_cache_remove_success", COUNTER, nullptr}                                 },
  {"proxy.process.cache.remove.failure",                                 {"proxy_process_cache_remove_failure", COUNTER, nullptr}                                 },
  {"proxy.process.cache.evacuate.active",                                {"proxy_process_cache_evacuate_active", GAUGE, nullptr}                                  },
  {"proxy.process.cache.evacuate.success",                               {"proxy_process_cache_evacuate_success", COUNTER, nullptr}                               },
  {"proxy.process.cache.evacuate.failure",                               {"proxy_process_cache_evacuate_failure", COUNTER, nullptr}                               },
  {"proxy.process.cache.scan.active",                                    {"proxy_process_cache_scan_active", GAUGE, nullptr}                                      },
  {"proxy.process.cache.scan.success",                                   {"proxy_process_cache_scan_success", COUNTER, nullptr}                                   },
  {"proxy.process.cache.scan.failure",                                   {"proxy_process_cache_scan_failure", COUNTER, nullptr}                                   },
  {"proxy.process.cache.frags_per_doc.1",                                {"proxy_process_cache_frags_per_doc_1", COUNTER, nullptr}                                },
  {"proxy.process.cache.frags_per_doc.2",                                {"proxy_process_cache_frags_per_doc_2", COUNTER, nullptr}                                },
  {"proxy.process.cache.frags_per_doc.3+",                               {"proxy_process_cache_frags_per_doc_3plus", COUNTER, nullptr}                            }, // 3+ -> 3plus
  {"proxy.process.cache.bytes_used",                                     {"proxy_process_cache_bytes_used", GAUGE, nullptr}                                       },
  {"proxy.process.cache.bytes_total",                                    {"proxy_process_cache_bytes_total", GAUGE, nullptr}                                      },
  {"proxy.process.cache.stripes",                                        {"proxy_process_cache_stripes", GAUGE, nullptr}                                          },
  {"proxy.process.cache.ram_cache.total_bytes",                          {"proxy_process_cache_ram_cache_total_bytes", GAUGE, nullptr}                            },
  {"proxy.process.cache.ram_cache.bytes_used",                           {"proxy_process_cache_ram_cache_bytes_used", GAUGE, nullptr}                             },
  {"proxy.process.cache.ram_cache.hits",                                 {"proxy_process_cache_ram_cache_hits", COUNTER, nullptr}                                 },
  {"proxy.process.cache.ram_cache.misses",                               {"proxy_process_cache_ram_cache_misses", COUNTER, nullptr}                               },
  {"proxy.process.cache.pread_count",                                    {"proxy_process_cache_pread_count", COUNTER, nullptr}                                    },
  {"proxy.process.cache.percent_full",                                   {"proxy_process_cache_percent_full", GAUGE, nullptr}                                     },
  {"proxy.process.cache.read.seek.failure",                              {"proxy_process_cache_read_seek_failure", COUNTER, nullptr}                              },
  {"proxy.process.cache.read.invalid",                                   {"proxy_process_cache_read_invalid", COUNTER, nullptr}                                   },
  {"proxy.process.cache.write.backlog.failure",                          {"proxy_process_cache_write_backlog_failure", COUNTER, nullptr}                          },
  {"proxy.process.cache.direntries.total",                               {"proxy_process_cache_direntries_total", GAUGE, nullptr}                                 },
  {"proxy.process.cache.direntries.used",                                {"proxy_process_cache_direntries_used", GAUGE, nullptr}                                  },
  {"proxy.process.cache.directory_collision",                            {"proxy_process_cache_directory_collision", COUNTER, nullptr}                            },
  {"proxy.process.cache.read_busy.success",                              {"proxy_process_cache_read_busy_success", COUNTER, nullptr}                              },
  {"proxy.process.cache.read_busy.failure",                              {"proxy_process_cache_read_busy_failure", COUNTER, nullptr}                              },
  {"proxy.process.cache.write_bytes_stat",                               {"proxy_process_cache_write_bytes_stat", COUNTER, nullptr}                               },
  {"proxy.process.cache.vector_marshals",                                {"proxy_process_cache_vector_marshals", COUNTER, nullptr}                                },
  {"proxy.process.cache.hdr_marshals",                                   {"proxy_process_cache_hdr_marshals", COUNTER, nullptr}                                   },
  {"proxy.process.cache.hdr_marshal_bytes",                              {"proxy_process_cache_hdr_marshal_bytes", COUNTER, nullptr}                              },
  {"proxy.process.cache.gc_bytes_evacuated",                             {"proxy_process_cache_gc_bytes_evacuated", COUNTER, nullptr}                             },
  {"proxy.process.cache.gc_frags_evacuated",                             {"proxy_process_cache_gc_frags_evacuated", COUNTER, nullptr}                             },
  {"proxy.process.cache.wrap_count",                                     {"proxy_process_cache_wrap_count", COUNTER, nullptr}                                     },
  {"proxy.process.cache.sync.count",                                     {"proxy_process_cache_sync_count", COUNTER, nullptr}                                     },
  {"proxy.process.cache.sync.bytes",                                     {"proxy_process_cache_sync_bytes", COUNTER, nullptr}                                     },
  {"proxy.process.cache.sync.time",                                      {"proxy_process_cache_sync_time", COUNTER, nullptr}                                      },
  {"proxy.process.cache.span.errors.read",                               {"proxy_process_cache_span_errors_read", COUNTER, nullptr}                               },
  {"proxy.process.cache.span.errors.write",                              {"proxy_process_cache_span_errors_write", COUNTER, nullptr}                              },
  {"proxy.process.cache.span.failing",                                   {"proxy_process_cache_span_failing", GAUGE, nullptr}                                     },
  {"proxy.process.cache.span.offline",                                   {"proxy_process_cache_span_offline", GAUGE, nullptr}                                     },
  {"proxy.process.cache.span.online",                                    {"proxy_process_cache_span_online", GAUGE, nullptr}                                      },

  // src/iocore/dns/DNS.cc
  {"proxy.process.dns.fail_time",                                        {"proxy_process_dns_fail_time", COUNTER, nullptr}                                        },
  {"proxy.process.dns.in_flight",                                        {"proxy_process_dns_in_flight", GAUGE, nullptr}                                          },
  {"proxy.process.dns.lookup_failures",                                  {"proxy_process_dns_lookup_failures", COUNTER, nullptr}                                  },
  {"proxy.process.dns.lookup_successes",                                 {"proxy_process_dns_lookup_successes", COUNTER, nullptr}                                 },
  {"proxy.process.dns.max_retries_exceeded",                             {"proxy_process_dns_max_retries_exceeded", COUNTER, nullptr}                             },
  {"proxy.process.dns.lookup_time",                                      {"proxy_process_dns_lookup_time", COUNTER, nullptr}                                      },
  {"proxy.process.dns.retries",                                          {"proxy_process_dns_retries", COUNTER, nullptr}                                          },
  {"proxy.process.dns.success_time",                                     {"proxy_process_dns_success_time", COUNTER, nullptr}                                     },
  {"proxy.process.dns.tcp_reset",                                        {"proxy_process_dns_tcp_reset", COUNTER, nullptr}                                        },
  {"proxy.process.dns.tcp_retries",                                      {"proxy_process_dns_tcp_retries", COUNTER, nullptr}                                      },
  {"proxy.process.dns.total_dns_lookups",                                {"proxy_process_dns_total_dns_lookups", COUNTER, nullptr}                                },

  // src/iocore/hostdb/HostDB.cc
  {"proxy.process.hostdb.total_lookups",                                 {"proxy_process_hostdb_total_lookups", COUNTER, nullptr}                                 },
  {"proxy.process.hostdb.total_hits",                                    {"proxy_process_hostdb_total_hits", COUNTER, nullptr}                                    },
  {"proxy.process.hostdb.total_serve_stale",                             {"proxy_process_hostdb_total_serve_stale", COUNTER, nullptr}                             },
  {"proxy.process.hostdb.ttl",                                           {"proxy_process_hostdb_ttl", COUNTER, nullptr}                                           },
  {"proxy.process.hostdb.ttl_expires",                                   {"proxy_process_hostdb_ttl_expires", COUNTER, nullptr}                                   },
  {"proxy.process.hostdb.re_dns_on_reload",                              {"proxy_process_hostdb_re_dns_on_reload", COUNTER, nullptr}                              },
  {"proxy.process.hostdb.insert_duplicate_to_pending_dns",
   {"proxy_process_hostdb_insert_duplicate_to_pending_dns", COUNTER, nullptr}                                                                                     },

  // src/iocore/hostdb/P_RefCountCache.h
  {"proxy.process.hostdb.cache.current_items",                           {"proxy_process_hostdb_cache_current_items", GAUGE, nullptr}                             },
  {"proxy.process.hostdb.cache.current_size",                            {"proxy_process_hostdb_cache_current_size", GAUGE, nullptr}                              },
  {"proxy.process.hostdb.cache.total_inserts",                           {"proxy_process_hostdb_cache_total_inserts", COUNTER, nullptr}                           },
  {"proxy.process.hostdb.cache.total_failed_inserts",                    {"proxy_process_hostdb_cache_total_failed_inserts", COUNTER, nullptr}                    },
  {"proxy.process.hostdb.cache.total_lookups",                           {"proxy_process_hostdb_cache_total_lookups", COUNTER, nullptr}                           },
  {"proxy.process.hostdb.cache.total_hits",                              {"proxy_process_hostdb_cache_total_hits", COUNTER, nullptr}                              },
  {"proxy.process.hostdb.cache.last_sync.time",                          {"proxy_process_hostdb_cache_last_sync_time", COUNTER, nullptr}                          },
  {"proxy.process.hostdb.cache.last_sync.total_items",                   {"proxy_process_hostdb_cache_last_sync_total_items", COUNTER, nullptr}                   },
  {"proxy.process.hostdb.cache.last_sync.total_size",                    {"proxy_process_hostdb_cache_last_sync_total_size", COUNTER, nullptr}                    },

  // src/iocore/io_uring/io_uring.cc

  // src/iocore/net/Net.cc
  {"proxy.process.net.accepts_currently_open",                           {"proxy_process_net_accepts_currently_open", GAUGE, nullptr}                             },
  {"proxy.process.net.calls_to_read",                                    {"proxy_process_net_calls_to_read", COUNTER, nullptr}                                    },
  {"proxy.process.net.calls_to_read_nodata",                             {"proxy_process_net_calls_to_read_nodata", COUNTER, nullptr}                             },
  {"proxy.process.net.calls_to_readfromnet",                             {"proxy_process_net_calls_to_readfromnet", COUNTER, nullptr}                             },
  {"proxy.process.net.calls_to_write",                                   {"proxy_process_net_calls_to_write", COUNTER, nullptr}                                   },
  {"proxy.process.net.calls_to_write_nodata",                            {"proxy_process_net_calls_to_write_nodata", COUNTER, nullptr}                            },
  {"proxy.process.net.calls_to_writetonet",                              {"proxy_process_net_calls_to_writetonet", COUNTER, nullptr}                              },
  {"proxy.process.net.connections_currently_open",                       {"proxy_process_net_connections_currently_open", GAUGE, nullptr}                         },
  {"proxy.process.net.connections_throttled_in",                         {"proxy_process_net_connections_throttled_in", COUNTER, nullptr}                         },
  {"proxy.process.net.per_client.connections_throttled_in",
   {"proxy_process_net_per_client_connections_throttled_in", COUNTER, nullptr}                                                                                    },
  {"proxy.process.net.connections_throttled_out",                        {"proxy_process_net_connections_throttled_out", COUNTER, nullptr}                        },
  {"proxy.process.tunnel.total_client_connections_blind_tcp",
   {"proxy_process_tunnel_total_client_connections_blind_tcp", COUNTER, nullptr}                                                                                  },
  {"proxy.process.tunnel.current_client_connections_blind_tcp",
   {"proxy_process_tunnel_current_client_connections_blind_tcp", GAUGE, nullptr}                                                                                  },
  {"proxy.process.tunnel.total_server_connections_blind_tcp",
   {"proxy_process_tunnel_total_server_connections_blind_tcp", COUNTER, nullptr}                                                                                  },
  {"proxy.process.tunnel.current_server_connections_blind_tcp",
   {"proxy_process_tunnel_current_server_connections_blind_tcp", GAUGE, nullptr}                                                                                  },
  {"proxy.process.tunnel.total_client_connections_tls_tunnel",
   {"proxy_process_tunnel_total_client_connections_tls_tunnel", COUNTER, nullptr}                                                                                 },
  {"proxy.process.tunnel.current_client_connections_tls_tunnel",
   {"proxy_process_tunnel_current_client_connections_tls_tunnel", GAUGE, nullptr}                                                                                 },
  {"proxy.process.tunnel.total_client_connections_tls_forward",
   {"proxy_process_tunnel_total_client_connections_tls_forward", COUNTER, nullptr}                                                                                },
  {"proxy.process.tunnel.current_client_connections_tls_forward",
   {"proxy_process_tunnel_current_client_connections_tls_forward", GAUGE, nullptr}                                                                                },
  {"proxy.process.tunnel.total_client_connections_tls_partial_blind",
   {"proxy_process_tunnel_total_client_connections_tls_partial_blind", COUNTER, nullptr}                                                                          },
  {"proxy.process.tunnel.current_client_connections_tls_partial_blind",
   {"proxy_process_tunnel_current_client_connections_tls_partial_blind", GAUGE, nullptr}                                                                          },
  {"proxy.process.tunnel.total_client_connections_tls_http",
   {"proxy_process_tunnel_total_client_connections_tls_http", COUNTER, nullptr}                                                                                   },
  {"proxy.process.tunnel.current_client_connections_tls_http",
   {"proxy_process_tunnel_current_client_connections_tls_http", GAUGE, nullptr}                                                                                   },
  {"proxy.process.tunnel.total_server_connections_tls",                  {"proxy_process_tunnel_total_server_connections_tls", COUNTER, nullptr}                  },
  {"proxy.process.tunnel.current_server_connections_tls",                {"proxy_process_tunnel_current_server_connections_tls", GAUGE, nullptr}                  },
  {"proxy.process.net.default_inactivity_timeout_applied",
   {"proxy_process_net_default_inactivity_timeout_applied", COUNTER, nullptr}                                                                                     },
  {"proxy.process.net.default_inactivity_timeout_count",                 {"proxy_process_net_default_inactivity_timeout_count", COUNTER, nullptr}                 },
  {"proxy.process.net.fastopen_out.attempts",                            {"proxy_process_net_fastopen_out_attempts", COUNTER, nullptr}                            },
  {"proxy.process.net.fastopen_out.successes",                           {"proxy_process_net_fastopen_out_successes", COUNTER, nullptr}                           },
  {"proxy.process.net.net_handler_run",                                  {"proxy_process_net_net_handler_run", COUNTER, nullptr}                                  },
  {"proxy.process.net.inactivity_cop_lock_acquire_failure",
   {"proxy_process_net_inactivity_cop_lock_acquire_failure", COUNTER, nullptr}                                                                                    },
  {"proxy.process.net.dynamic_keep_alive_timeout_in_count",
   {"proxy_process_net_dynamic_keep_alive_timeout_in_count", COUNTER, nullptr}                                                                                    },
  {"proxy.process.net.dynamic_keep_alive_timeout_in_total",
   {"proxy_process_net_dynamic_keep_alive_timeout_in_total", COUNTER, nullptr}                                                                                    },
  {"proxy.process.net.read_bytes",                                       {"proxy_process_net_read_bytes", COUNTER, nullptr}                                       },
  {"proxy.process.net.read_bytes_count",                                 {"proxy_process_net_read_bytes_count", COUNTER, nullptr}                                 },
  {"proxy.process.net.max.requests_throttled_in",                        {"proxy_process_net_max_requests_throttled_in", COUNTER, nullptr}                        },
  {"proxy.process.socks.connections_currently_open",                     {"proxy_process_socks_connections_currently_open", GAUGE, nullptr}                       },
  {"proxy.process.socks.connections_successful",                         {"proxy_process_socks_connections_successful", COUNTER, nullptr}                         },
  {"proxy.process.socks.connections_unsuccessful",                       {"proxy_process_socks_connections_unsuccessful", COUNTER, nullptr}                       },
  {"proxy.process.tcp.total_accepts",                                    {"proxy_process_tcp_total_accepts", COUNTER, nullptr}                                    },
  {"proxy.process.net.write_bytes",                                      {"proxy_process_net_write_bytes", COUNTER, nullptr}                                      },
  {"proxy.process.net.write_bytes_count",                                {"proxy_process_net_write_bytes_count", COUNTER, nullptr}                                },
  {"proxy.process.net.connection_tracker_table_size",                    {"proxy_process_net_connection_tracker_table_size", GAUGE, nullptr}                      },

  // src/iocore/net/SSLStats.cc
  {"proxy.process.ssl.early_data_received",                              {"proxy_process_ssl_early_data_received", COUNTER, nullptr}                              },
  {"proxy.process.ssl.ssl_error_async",                                  {"proxy_process_ssl_ssl_error_async", COUNTER, nullptr}                                  },
  {"proxy.process.ssl.ssl_error_ssl",                                    {"proxy_process_ssl_ssl_error_ssl", COUNTER, nullptr}                                    },
  {"proxy.process.ssl.ssl_error_syscall",                                {"proxy_process_ssl_ssl_error_syscall", COUNTER, nullptr}                                },
  {"proxy.process.ssl.ssl_ocsp_refresh_cert_failure",                    {"proxy_process_ssl_ssl_ocsp_refresh_cert_failure", COUNTER, nullptr}                    },
  {"proxy.process.ssl.ssl_ocsp_refreshed_cert",                          {"proxy_process_ssl_ssl_ocsp_refreshed_cert", COUNTER, nullptr}                          },
  {"proxy.process.ssl.ssl_ocsp_revoked_cert",                            {"proxy_process_ssl_ssl_ocsp_revoked_cert", COUNTER, nullptr}                            },
  {"proxy.process.ssl.ssl_ocsp_unknown_cert",                            {"proxy_process_ssl_ssl_ocsp_unknown_cert", COUNTER, nullptr}                            },
  {"proxy.process.ssl.origin_server_bad_cert",                           {"proxy_process_ssl_origin_server_bad_cert", COUNTER, nullptr}                           },
  {"proxy.process.ssl.origin_server_cert_verify_failed",                 {"proxy_process_ssl_origin_server_cert_verify_failed", COUNTER, nullptr}                 },
  {"proxy.process.ssl.origin_server_decryption_failed",                  {"proxy_process_ssl_origin_server_decryption_failed", COUNTER, nullptr}                  },
  {"proxy.process.ssl.origin_server_expired_cert",                       {"proxy_process_ssl_origin_server_expired_cert", COUNTER, nullptr}                       },
  {"proxy.process.ssl.origin_server_other_errors",                       {"proxy_process_ssl_origin_server_other_errors", COUNTER, nullptr}                       },
  {"proxy.process.ssl.origin_server_revoked_cert",                       {"proxy_process_ssl_origin_server_revoked_cert", COUNTER, nullptr}                       },
  {"proxy.process.ssl.origin_server_unknown_ca",                         {"proxy_process_ssl_origin_server_unknown_ca", COUNTER, nullptr}                         },
  {"proxy.process.ssl.origin_server_unknown_cert",                       {"proxy_process_ssl_origin_server_unknown_cert", COUNTER, nullptr}                       },
  {"proxy.process.ssl.origin_server_wrong_version",                      {"proxy_process_ssl_origin_server_wrong_version", COUNTER, nullptr}                      },
  {"proxy.process.ssl.origin_session_reused",                            {"proxy_process_ssl_origin_session_reused", COUNTER, nullptr}                            },
  {"proxy.process.ssl.ssl_sni_name_set_failure",                         {"proxy_process_ssl_ssl_sni_name_set_failure", COUNTER, nullptr}                         },
  {"proxy.process.ssl.ssl_origin_session_cache_hit",                     {"proxy_process_ssl_ssl_origin_session_cache_hit", COUNTER, nullptr}                     },
  {"proxy.process.ssl.ssl_origin_session_cache_miss",                    {"proxy_process_ssl_ssl_origin_session_cache_miss", COUNTER, nullptr}                    },
  {"proxy.process.ssl.ssl_session_cache_eviction",                       {"proxy_process_ssl_ssl_session_cache_eviction", COUNTER, nullptr}                       },
  {"proxy.process.ssl.ssl_session_cache_hit",                            {"proxy_process_ssl_ssl_session_cache_hit", COUNTER, nullptr}                            },
  {"proxy.process.ssl.ssl_session_cache_lock_contention",
   {"proxy_process_ssl_ssl_session_cache_lock_contention", COUNTER, nullptr}                                                                                      },
  {"proxy.process.ssl.ssl_session_cache_miss",                           {"proxy_process_ssl_ssl_session_cache_miss", COUNTER, nullptr}                           },
  {"proxy.process.ssl.ssl_session_cache_new_session",                    {"proxy_process_ssl_ssl_session_cache_new_session", COUNTER, nullptr}                    },
  {"proxy.process.ssl.total_attempts_handshake_count_in",
   {"proxy_process_ssl_total_attempts_handshake_count_in", COUNTER, nullptr}                                                                                      },
  {"proxy.process.ssl.total_attempts_handshake_count_out",
   {"proxy_process_ssl_total_attempts_handshake_count_out", COUNTER, nullptr}                                                                                     },
  {"proxy.process.ssl.default_record_size_count",                        {"proxy_process_ssl_default_record_size_count", COUNTER, nullptr}                        },
  {"proxy.process.ssl.max_record_size_count",                            {"proxy_process_ssl_max_record_size_count", COUNTER, nullptr}                            },
  {"proxy.process.ssl.redo_record_size_count",                           {"proxy_process_ssl_redo_record_size_count", COUNTER, nullptr}                           },
  {"proxy.process.ssl.total_handshake_time",                             {"proxy_process_ssl_total_handshake_time", COUNTER, nullptr}                             },
  {"proxy.process.ssl.ssl_total_sslv3",                                  {"proxy_process_ssl_ssl_total_sslv3", COUNTER, nullptr}                                  },
  {"proxy.process.ssl.total_success_handshake_count_in",                 {"proxy_process_ssl_total_success_handshake_count_in", COUNTER, nullptr}                 },
  {"proxy.process.ssl.total_success_handshake_count_out",
   {"proxy_process_ssl_total_success_handshake_count_out", COUNTER, nullptr}                                                                                      },
  {"proxy.process.ssl.total_ticket_keys_renewed",                        {"proxy_process_ssl_total_ticket_keys_renewed", COUNTER, nullptr}                        },
  {"proxy.process.ssl.total_tickets_created",                            {"proxy_process_ssl_total_tickets_created", COUNTER, nullptr}                            },
  {"proxy.process.ssl.total_tickets_not_found",                          {"proxy_process_ssl_total_tickets_not_found", COUNTER, nullptr}                          },
  {"proxy.process.ssl.total_tickets_renewed",                            {"proxy_process_ssl_total_tickets_renewed", COUNTER, nullptr}                            },
  {"proxy.process.ssl.total_tickets_verified",                           {"proxy_process_ssl_total_tickets_verified", COUNTER, nullptr}                           },
  {"proxy.process.ssl.total_tickets_verified_old_key",                   {"proxy_process_ssl_total_tickets_verified_old_key", COUNTER, nullptr}                   },
  {"proxy.process.ssl.ssl_total_tlsv1",                                  {"proxy_process_ssl_ssl_total_tlsv1", COUNTER, nullptr}                                  },
  {"proxy.process.ssl.ssl_total_tlsv11",                                 {"proxy_process_ssl_ssl_total_tlsv11", COUNTER, nullptr}                                 },
  {"proxy.process.ssl.ssl_total_tlsv12",                                 {"proxy_process_ssl_ssl_total_tlsv12", COUNTER, nullptr}                                 },
  {"proxy.process.ssl.ssl_total_tlsv13",                                 {"proxy_process_ssl_ssl_total_tlsv13", COUNTER, nullptr}                                 },
  {"proxy.process.ssl.user_agent_bad_cert",                              {"proxy_process_ssl_user_agent_bad_cert", COUNTER, nullptr}                              },
  {"proxy.process.ssl.user_agent_cert_verify_failed",                    {"proxy_process_ssl_user_agent_cert_verify_failed", COUNTER, nullptr}                    },
  {"proxy.process.ssl.user_agent_decryption_failed",                     {"proxy_process_ssl_user_agent_decryption_failed", COUNTER, nullptr}                     },
  {"proxy.process.ssl.user_agent_expired_cert",                          {"proxy_process_ssl_user_agent_expired_cert", COUNTER, nullptr}                          },
  {"proxy.process.ssl.user_agent_other_errors",                          {"proxy_process_ssl_user_agent_other_errors", COUNTER, nullptr}                          },
  {"proxy.process.ssl.user_agent_revoked_cert",                          {"proxy_process_ssl_user_agent_revoked_cert", COUNTER, nullptr}                          },
  {"proxy.process.ssl.user_agent_session_hit",                           {"proxy_process_ssl_user_agent_session_hit", GAUGE, nullptr}                             },
  {"proxy.process.ssl.user_agent_session_miss",                          {"proxy_process_ssl_user_agent_session_miss", GAUGE, nullptr}                            },
  {"proxy.process.ssl.user_agent_session_timeout",                       {"proxy_process_ssl_user_agent_session_timeout", GAUGE, nullptr}                         },
  {"proxy.process.ssl.user_agent_sessions",                              {"proxy_process_ssl_user_agent_sessions", GAUGE, nullptr}                                },
  {"proxy.process.ssl.user_agent_unknown_ca",                            {"proxy_process_ssl_user_agent_unknown_ca", COUNTER, nullptr}                            },
  {"proxy.process.ssl.user_agent_unknown_cert",                          {"proxy_process_ssl_user_agent_unknown_cert", COUNTER, nullptr}                          },
  {"proxy.process.ssl.user_agent_wrong_version",                         {"proxy_process_ssl_user_agent_wrong_version", COUNTER, nullptr}                         },

  // src/iocore/net/quic/QUICGlobals.cc
  {"proxy.process.quic.total_packets_sent",                              {"proxy_process_quic_total_packets_sent", COUNTER, nullptr}                              },

  // src/proxy/http/HttpConfig.cc
  {"proxy.process.http.background_fill_bytes_aborted",                   {"proxy_process_http_background_fill_bytes_aborted", COUNTER, nullptr}                   },
  {"proxy.process.http.background_fill_bytes_completed",                 {"proxy_process_http_background_fill_bytes_completed", COUNTER, nullptr}                 },
  {"proxy.process.http.background_fill_current_count",                   {"proxy_process_http_background_fill_current_count", GAUGE, nullptr}                     },
  {"proxy.process.http.background_fill_total_count",                     {"proxy_process_http_background_fill_total_count", COUNTER, nullptr}                     },
  {"proxy.process.http.broken_server_connections",                       {"proxy_process_http_broken_server_connections", COUNTER, nullptr}                       },
  {"proxy.process.http.cache_deletes",                                   {"proxy_process_http_cache_deletes", COUNTER, nullptr}                                   },
  {"proxy.process.http.cache_hit_fresh",                                 {"proxy_process_http_cache_hit_fresh", COUNTER, nullptr}                                 },
  {"proxy.process.http.cache_hit_ims",                                   {"proxy_process_http_cache_hit_ims", COUNTER, nullptr}                                   },
  {"proxy.process.http.cache_hit_mem_fresh",                             {"proxy_process_http_cache_hit_mem_fresh", COUNTER, nullptr}                             },
  {"proxy.process.http.cache_hit_revalidated",                           {"proxy_process_http_cache_hit_revalidated", COUNTER, nullptr}                           },
  {"proxy.process.http.cache_hit_rww",                                   {"proxy_process_http_cache_hit_rww", COUNTER, nullptr}                                   },
  {"proxy.process.http.cache_hit_stale_served",                          {"proxy_process_http_cache_hit_stale_served", COUNTER, nullptr}                          },
  {"proxy.process.http.cache_lookups",                                   {"proxy_process_http_cache_lookups", COUNTER, nullptr}                                   },
  {"proxy.process.http.cache_miss_changed",                              {"proxy_process_http_cache_miss_changed", COUNTER, nullptr}                              },
  {"proxy.process.http.cache_miss_client_no_cache",                      {"proxy_process_http_cache_miss_client_no_cache", COUNTER, nullptr}                      },
  {"proxy.process.http.cache_miss_cold",                                 {"proxy_process_http_cache_miss_cold", COUNTER, nullptr}                                 },
  {"proxy.process.http.cache_miss_ims",                                  {"proxy_process_http_cache_miss_ims", COUNTER, nullptr}                                  },
  {"proxy.process.http.cache_miss_client_not_cacheable",                 {"proxy_process_http_cache_miss_client_not_cacheable", COUNTER, nullptr}                 },
  {"proxy.process.http.milestone.cache_open_read_begin",                 {"proxy_process_http_milestone_cache_open_read_begin", COUNTER, nullptr}                 },
  {"proxy.process.http.milestone.cache_open_read_end",                   {"proxy_process_http_milestone_cache_open_read_end", COUNTER, nullptr}                   },
  {"proxy.process.http.cache.open_write.adjust_thread",                  {"proxy_process_http_cache_open_write_adjust_thread", COUNTER, nullptr}                  },
  {"proxy.process.http.milestone.cache_open_write_begin",
   {"proxy_process_http_milestone_cache_open_write_begin", COUNTER, nullptr}                                                                                      },
  {"proxy.process.http.milestone.cache_open_write_end",                  {"proxy_process_http_milestone_cache_open_write_end", COUNTER, nullptr}                  },
  {"proxy.process.http.cache_read_error",                                {"proxy_process_http_cache_read_error", COUNTER, nullptr}                                },
  {"proxy.process.http.cache_read_errors",                               {"proxy_process_http_cache_read_errors", COUNTER, nullptr}                               },
  {"proxy.process.http.cache_updates",                                   {"proxy_process_http_cache_updates", COUNTER, nullptr}                                   },
  {"proxy.process.http.cache_write_errors",                              {"proxy_process_http_cache_write_errors", COUNTER, nullptr}                              },
  {"proxy.process.http.cache_writes",                                    {"proxy_process_http_cache_writes", COUNTER, nullptr}                                    },
  {"proxy.process.http.completed_requests",                              {"proxy_process_http_completed_requests", COUNTER, nullptr}                              },
  {"proxy.process.http.connect_requests",                                {"proxy_process_http_connect_requests", COUNTER, nullptr}                                },
  {"proxy.process.http.current_active_client_connections",
   {"proxy_process_http_current_active_client_connections", GAUGE, nullptr}                                                                                       },
  {"proxy.process.http.current_cache_connections",                       {"proxy_process_http_current_cache_connections", GAUGE, nullptr}                         },
  {"proxy.process.http.current_client_connections",                      {"proxy_process_http_current_client_connections", GAUGE, nullptr}                        },
  {"proxy.process.http.current_client_transactions",                     {"proxy_process_http_current_client_transactions", GAUGE, nullptr}                       },
  {"proxy.process.http.current_parent_proxy_connections",                {"proxy_process_http_current_parent_proxy_connections", GAUGE, nullptr}                  },
  {"proxy.process.http.current_server_connections",                      {"proxy_process_http_current_server_connections", GAUGE, nullptr}                        },
  {"proxy.process.http.current_server_transactions",                     {"proxy_process_http_current_server_transactions", GAUGE, nullptr}                       },
  {"proxy.process.http.delete_requests",                                 {"proxy_process_http_delete_requests", COUNTER, nullptr}                                 },
  {"proxy.process.http.disallowed_post_100_continue",                    {"proxy_process_http_disallowed_post_100_continue", COUNTER, nullptr}                    },
  {"proxy.process.http.milestone.dns_lookup_begin",                      {"proxy_process_http_milestone_dns_lookup_begin", COUNTER, nullptr}                      },
  {"proxy.process.http.milestone.dns_lookup_end",                        {"proxy_process_http_milestone_dns_lookup_end", COUNTER, nullptr}                        },
  {"proxy.process.http.down_server.no_requests",                         {"proxy_process_http_down_server_no_requests", COUNTER, nullptr}                         },
  {"proxy.process.http.err_client_abort_count",                          {"proxy_process_http_err_client_abort_count", COUNTER, nullptr}                          },
  {"proxy.process.http.err_client_abort_origin_server_bytes",
   {"proxy_process_http_err_client_abort_origin_server_bytes", COUNTER, nullptr}                                                                                  },
  {"proxy.process.http.err_client_abort_user_agent_bytes",
   {"proxy_process_http_err_client_abort_user_agent_bytes", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http.err_client_read_error_count",                     {"proxy_process_http_err_client_read_error_count", COUNTER, nullptr}                     },
  {"proxy.process.http.err_client_read_error_origin_server_bytes",
   {"proxy_process_http_err_client_read_error_origin_server_bytes", COUNTER, nullptr}                                                                             },
  {"proxy.process.http.err_client_read_error_user_agent_bytes",
   {"proxy_process_http_err_client_read_error_user_agent_bytes", COUNTER, nullptr}                                                                                },
  {"proxy.process.http.err_connect_fail_count",                          {"proxy_process_http_err_connect_fail_count", COUNTER, nullptr}                          },
  {"proxy.process.http.err_connect_fail_origin_server_bytes",
   {"proxy_process_http_err_connect_fail_origin_server_bytes", COUNTER, nullptr}                                                                                  },
  {"proxy.process.http.err_connect_fail_user_agent_bytes",
   {"proxy_process_http_err_connect_fail_user_agent_bytes", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http.extension_method_requests",                       {"proxy_process_http_extension_method_requests", COUNTER, nullptr}                       },
  {"proxy.process.http.get_requests",                                    {"proxy_process_http_get_requests", COUNTER, nullptr}                                    },
  {"proxy.process.http.head_requests",                                   {"proxy_process_http_head_requests", COUNTER, nullptr}                                   },
  {"proxy.process.https.incoming_requests",                              {"proxy_process_https_incoming_requests", COUNTER, nullptr}                              },
  {"proxy.process.https.total_client_connections",                       {"proxy_process_https_total_client_connections", COUNTER, nullptr}                       },
  {"proxy.process.http.incoming_requests",                               {"proxy_process_http_incoming_requests", COUNTER, nullptr}                               },
  {"proxy.process.http.incoming_responses",                              {"proxy_process_http_incoming_responses", COUNTER, nullptr}                              },
  {"proxy.process.http.invalid_client_requests",                         {"proxy_process_http_invalid_client_requests", COUNTER, nullptr}                         },
  {"proxy.process.http.misc_count",                                      {"proxy_process_http_misc_count", COUNTER, nullptr}                                      },
  {"proxy.process.http.http_misc_origin_server_bytes",                   {"proxy_process_http_http_misc_origin_server_bytes", COUNTER, nullptr}                   },
  {"proxy.process.http.misc_user_agent_bytes",                           {"proxy_process_http_misc_user_agent_bytes", COUNTER, nullptr}                           },
  {"proxy.process.http.missing_host_hdr",                                {"proxy_process_http_missing_host_hdr", COUNTER, nullptr}                                },
  {"proxy.process.http.no_remap_matched",                                {"proxy_process_http_no_remap_matched", COUNTER, nullptr}                                },
  {"proxy.process.http.options_requests",                                {"proxy_process_http_options_requests", COUNTER, nullptr}                                },
  {"proxy.process.http.origin.body",                                     {"proxy_process_http_origin_body", COUNTER, nullptr}                                     },
  {"proxy.process.http.origin.close_private",                            {"proxy_process_http_origin_close_private", COUNTER, nullptr}                            },
  {"proxy.process.http.origin.connect.adjust_thread",                    {"proxy_process_http_origin_connect_adjust_thread", COUNTER, nullptr}                    },
  {"proxy.process.http.origin_connections_throttled_out",
   {"proxy_process_http_origin_connections_throttled_out", COUNTER, nullptr}                                                                                      },
  {"proxy.process.http.origin.make_new",                                 {"proxy_process_http_origin_make_new", COUNTER, nullptr}                                 },
  {"proxy.process.http.origin.no_sharing",                               {"proxy_process_http_origin_no_sharing", COUNTER, nullptr}                               },
  {"proxy.process.http.origin.not_found",                                {"proxy_process_http_origin_not_found", COUNTER, nullptr}                                },
  {"proxy.process.http.origin.private",                                  {"proxy_process_http_origin_private", COUNTER, nullptr}                                  },
  {"proxy.process.http.origin.raw",                                      {"proxy_process_http_origin_raw", COUNTER, nullptr}                                      },
  {"proxy.process.http.origin.reuse",                                    {"proxy_process_http_origin_reuse", COUNTER, nullptr}                                    },
  {"proxy.process.http.origin.reuse_fail",                               {"proxy_process_http_origin_reuse_fail", COUNTER, nullptr}                               },
  {"proxy.process.http.origin_server_request_document_total_size",
   {"proxy_process_http_origin_server_request_document_total_size", COUNTER, nullptr}                                                                             },
  {"proxy.process.http.origin_server_request_header_total_size",
   {"proxy_process_http_origin_server_request_header_total_size", COUNTER, nullptr}                                                                               },
  {"proxy.process.http.origin_server_response_document_total_size",
   {"proxy_process_http_origin_server_response_document_total_size", COUNTER, nullptr}                                                                            },
  {"proxy.process.http.origin_server_response_header_total_size",
   {"proxy_process_http_origin_server_response_header_total_size", COUNTER, nullptr}                                                                              },
  {"proxy.process.http.origin_shutdown.cleanup_entry",                   {"proxy_process_http_origin_shutdown_cleanup_entry", COUNTER, nullptr}                   },
  {"proxy.process.http.origin_shutdown.migration_failure",
   {"proxy_process_http_origin_shutdown_migration_failure", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http.origin_shutdown.pool_lock_contention",
   {"proxy_process_http_origin_shutdown_pool_lock_contention", COUNTER, nullptr}                                                                                  },
  {"proxy.process.http.origin_shutdown.release_invalid_request",
   {"proxy_process_http_origin_shutdown_release_invalid_request", COUNTER, nullptr}                                                                               },
  {"proxy.process.http.origin_shutdown.release_invalid_response",
   {"proxy_process_http_origin_shutdown_release_invalid_response", COUNTER, nullptr}                                                                              },
  {"proxy.process.http.origin_shutdown.release_misc",                    {"proxy_process_http_origin_shutdown_release_misc", COUNTER, nullptr}                    },
  {"proxy.process.http.origin_shutdown.release_modified",
   {"proxy_process_http_origin_shutdown_release_modified", COUNTER, nullptr}                                                                                      },
  {"proxy.process.http.origin_shutdown.release_no_keep_alive",
   {"proxy_process_http_origin_shutdown_release_no_keep_alive", COUNTER, nullptr}                                                                                 },
  {"proxy.process.http.origin_shutdown.release_no_server",
   {"proxy_process_http_origin_shutdown_release_no_server", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http.origin_shutdown.release_no_sharing",
   {"proxy_process_http_origin_shutdown_release_no_sharing", COUNTER, nullptr}                                                                                    },
  {"proxy.process.http.origin_shutdown.tunnel_abort",                    {"proxy_process_http_origin_shutdown_tunnel_abort", COUNTER, nullptr}                    },
  {"proxy.process.http.origin_shutdown.tunnel_client",                   {"proxy_process_http_origin_shutdown_tunnel_client", COUNTER, nullptr}                   },
  {"proxy.process.http.origin_shutdown.tunnel_server",                   {"proxy_process_http_origin_shutdown_tunnel_server", COUNTER, nullptr}                   },
  {"proxy.process.http.origin_shutdown.tunnel_server_detach",
   {"proxy_process_http_origin_shutdown_tunnel_server_detach", COUNTER, nullptr}                                                                                  },
  {"proxy.process.http.origin_shutdown.tunnel_server_eos",
   {"proxy_process_http_origin_shutdown_tunnel_server_eos", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http.origin_shutdown.tunnel_server_no_keep_alive",
   {"proxy_process_http_origin_shutdown_tunnel_server_no_keep_alive", COUNTER, nullptr}                                                                           },
  {"proxy.process.http.origin_shutdown.tunnel_server_plugin_tunnel",
   {"proxy_process_http_origin_shutdown_tunnel_server_plugin_tunnel", COUNTER, nullptr}                                                                           },
  {"proxy.process.http.origin_shutdown.tunnel_transform_read",
   {"proxy_process_http_origin_shutdown_tunnel_transform_read", COUNTER, nullptr}                                                                                 },
  {"proxy.process.http.outgoing_requests",                               {"proxy_process_http_outgoing_requests", COUNTER, nullptr}                               },
  {"proxy.process.http_parent_count",                                    {"proxy_process_http_parent_count", COUNTER, nullptr}                                    },
  {"proxy.process.http.parent_proxy_request_total_bytes",
   {"proxy_process_http_parent_proxy_request_total_bytes", COUNTER, nullptr}                                                                                      },
  {"proxy.process.http.parent_proxy_response_total_bytes",
   {"proxy_process_http_parent_proxy_response_total_bytes", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http.parent_proxy_transaction_time",                   {"proxy_process_http_parent_proxy_transaction_time", COUNTER, nullptr}                   },
  {"proxy.process.http.pooled_server_connections",                       {"proxy_process_http_pooled_server_connections", GAUGE, nullptr}                         },
  {"proxy.process.http.post_body_too_large",                             {"proxy_process_http_post_body_too_large", COUNTER, nullptr}                             },
  {"proxy.process.http.post_requests",                                   {"proxy_process_http_post_requests", COUNTER, nullptr}                                   },
  {"proxy.process.http.http_proxy_loop_detected",                        {"proxy_process_http_http_proxy_loop_detected", COUNTER, nullptr}                        },
  {"proxy.process.http.http_proxy_mh_loop_detected",                     {"proxy_process_http_http_proxy_mh_loop_detected", COUNTER, nullptr}                     },
  {"proxy.process.http.purge_requests",                                  {"proxy_process_http_purge_requests", COUNTER, nullptr}                                  },
  {"proxy.process.http.push_requests",                                   {"proxy_process_http_push_requests", COUNTER, nullptr}                                   },
  {"proxy.process.http.pushed_document_total_size",                      {"proxy_process_http_pushed_document_total_size", COUNTER, nullptr}                      },
  {"proxy.process.http.pushed_response_header_total_size",
   {"proxy_process_http_pushed_response_header_total_size", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http.put_requests",                                    {"proxy_process_http_put_requests", COUNTER, nullptr}                                    },
  {"proxy.process.http.100_responses",                                   {"proxy_process_http_100_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.101_responses",                                   {"proxy_process_http_101_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.1xx_responses",                                   {"proxy_process_http_1xx_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.200_responses",                                   {"proxy_process_http_200_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.201_responses",                                   {"proxy_process_http_201_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.202_responses",                                   {"proxy_process_http_202_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.203_responses",                                   {"proxy_process_http_203_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.204_responses",                                   {"proxy_process_http_204_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.205_responses",                                   {"proxy_process_http_205_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.206_responses",                                   {"proxy_process_http_206_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.2xx_responses",                                   {"proxy_process_http_2xx_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.300_responses",                                   {"proxy_process_http_300_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.301_responses",                                   {"proxy_process_http_301_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.302_responses",                                   {"proxy_process_http_302_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.303_responses",                                   {"proxy_process_http_303_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.304_responses",                                   {"proxy_process_http_304_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.305_responses",                                   {"proxy_process_http_305_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.307_responses",                                   {"proxy_process_http_307_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.308_responses",                                   {"proxy_process_http_308_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.3xx_responses",                                   {"proxy_process_http_3xx_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.400_responses",                                   {"proxy_process_http_400_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.401_responses",                                   {"proxy_process_http_401_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.402_responses",                                   {"proxy_process_http_402_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.403_responses",                                   {"proxy_process_http_403_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.404_responses",                                   {"proxy_process_http_404_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.405_responses",                                   {"proxy_process_http_405_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.406_responses",                                   {"proxy_process_http_406_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.407_responses",                                   {"proxy_process_http_407_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.408_responses",                                   {"proxy_process_http_408_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.409_responses",                                   {"proxy_process_http_409_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.410_responses",                                   {"proxy_process_http_410_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.411_responses",                                   {"proxy_process_http_411_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.412_responses",                                   {"proxy_process_http_412_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.413_responses",                                   {"proxy_process_http_413_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.414_responses",                                   {"proxy_process_http_414_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.415_responses",                                   {"proxy_process_http_415_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.416_responses",                                   {"proxy_process_http_416_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.4xx_responses",                                   {"proxy_process_http_4xx_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.500_responses",                                   {"proxy_process_http_500_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.501_responses",                                   {"proxy_process_http_501_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.502_responses",                                   {"proxy_process_http_502_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.503_responses",                                   {"proxy_process_http_503_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.504_responses",                                   {"proxy_process_http_504_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.505_responses",                                   {"proxy_process_http_505_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.5xx_responses",                                   {"proxy_process_http_5xx_responses", COUNTER, nullptr}                                   },
  {"proxy.process.http.milestone.server_begin_write",                    {"proxy_process_http_milestone_server_begin_write", COUNTER, nullptr}                    },
  {"proxy.process.http.milestone.server_close",                          {"proxy_process_http_milestone_server_close", COUNTER, nullptr}                          },
  {"proxy.process.http.milestone.server_connect_end",                    {"proxy_process_http_milestone_server_connect_end", COUNTER, nullptr}                    },
  {"proxy.process.http.milestone.server_connect",                        {"proxy_process_http_milestone_server_connect", COUNTER, nullptr}                        },
  {"proxy.process.http.milestone.server_first_connect",                  {"proxy_process_http_milestone_server_first_connect", COUNTER, nullptr}                  },
  {"proxy.process.http.milestone.server_first_read",                     {"proxy_process_http_milestone_server_first_read", COUNTER, nullptr}                     },
  {"proxy.process.http.milestone.server_read_header_done",
   {"proxy_process_http_milestone_server_read_header_done", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http.milestone.sm_finish",                             {"proxy_process_http_milestone_sm_finish", COUNTER, nullptr}                             },
  {"proxy.process.http.milestone.sm_start",                              {"proxy_process_http_milestone_sm_start", COUNTER, nullptr}                              },
  {"proxy.process.http.tcp_client_refresh_count",                        {"proxy_process_http_tcp_client_refresh_count", COUNTER, nullptr}                        },
  {"proxy.process.http.tcp_client_refresh_origin_server_bytes",
   {"proxy_process_http_tcp_client_refresh_origin_server_bytes", COUNTER, nullptr}                                                                                },
  {"proxy.process.http.tcp_client_refresh_user_agent_bytes",
   {"proxy_process_http_tcp_client_refresh_user_agent_bytes", COUNTER, nullptr}                                                                                   },
  {"proxy.process.http.tcp_expired_miss_count",                          {"proxy_process_http_tcp_expired_miss_count", COUNTER, nullptr}                          },
  {"proxy.process.http.tcp_expired_miss_origin_server_bytes",
   {"proxy_process_http_tcp_expired_miss_origin_server_bytes", COUNTER, nullptr}                                                                                  },
  {"proxy.process.http.tcp_expired_miss_user_agent_bytes",
   {"proxy_process_http_tcp_expired_miss_user_agent_bytes", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http.tcp_hit_count",                                   {"proxy_process_http_tcp_hit_count", COUNTER, nullptr}                                   },
  {"proxy.process.http.tcp_hit_origin_server_bytes",                     {"proxy_process_http_tcp_hit_origin_server_bytes", COUNTER, nullptr}                     },
  {"proxy.process.http.tcp_hit_user_agent_bytes",                        {"proxy_process_http_tcp_hit_user_agent_bytes", COUNTER, nullptr}                        },
  {"proxy.process.http.tcp_ims_hit_count",                               {"proxy_process_http_tcp_ims_hit_count", COUNTER, nullptr}                               },
  {"proxy.process.http.tcp_ims_hit_origin_server_bytes",                 {"proxy_process_http_tcp_ims_hit_origin_server_bytes", COUNTER, nullptr}                 },
  {"proxy.process.http.tcp_ims_hit_user_agent_bytes",                    {"proxy_process_http_tcp_ims_hit_user_agent_bytes", COUNTER, nullptr}                    },
  {"proxy.process.http.tcp_ims_miss_count",                              {"proxy_process_http_tcp_ims_miss_count", COUNTER, nullptr}                              },
  {"proxy.process.http.tcp_ims_miss_origin_server_bytes",
   {"proxy_process_http_tcp_ims_miss_origin_server_bytes", COUNTER, nullptr}                                                                                      },
  {"proxy.process.http.tcp_ims_miss_user_agent_bytes",                   {"proxy_process_http_tcp_ims_miss_user_agent_bytes", COUNTER, nullptr}                   },
  {"proxy.process.http.tcp_miss_count",                                  {"proxy_process_http_tcp_miss_count", COUNTER, nullptr}                                  },
  {"proxy.process.http.tcp_miss_origin_server_bytes",                    {"proxy_process_http_tcp_miss_origin_server_bytes", COUNTER, nullptr}                    },
  {"proxy.process.http.tcp_miss_user_agent_bytes",                       {"proxy_process_http_tcp_miss_user_agent_bytes", COUNTER, nullptr}                       },
  {"proxy.process.http.tcp_refresh_hit_count",                           {"proxy_process_http_tcp_refresh_hit_count", COUNTER, nullptr}                           },
  {"proxy.process.http.tcp_refresh_hit_origin_server_bytes",
   {"proxy_process_http_tcp_refresh_hit_origin_server_bytes", COUNTER, nullptr}                                                                                   },
  {"proxy.process.http.tcp_refresh_hit_user_agent_bytes",
   {"proxy_process_http_tcp_refresh_hit_user_agent_bytes", COUNTER, nullptr}                                                                                      },
  {"proxy.process.http.tcp_refresh_miss_count",                          {"proxy_process_http_tcp_refresh_miss_count", COUNTER, nullptr}                          },
  {"proxy.process.http.tcp_refresh_miss_origin_server_bytes",
   {"proxy_process_http_tcp_refresh_miss_origin_server_bytes", COUNTER, nullptr}                                                                                  },
  {"proxy.process.http.tcp_refresh_miss_user_agent_bytes",
   {"proxy_process_http_tcp_refresh_miss_user_agent_bytes", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http.total_client_connections",                        {"proxy_process_http_total_client_connections", COUNTER, nullptr}                        },
  {"proxy.process.http.total_client_connections_ipv4",                   {"proxy_process_http_total_client_connections_ipv4", COUNTER, nullptr}                   },
  {"proxy.process.http.total_client_connections_ipv6",                   {"proxy_process_http_total_client_connections_ipv6", COUNTER, nullptr}                   },
  {"proxy.process.http.total_incoming_connections",                      {"proxy_process_http_total_incoming_connections", COUNTER, nullptr}                      },
  {"proxy.process.http.total_parent_marked_down_count",                  {"proxy_process_http_total_parent_marked_down_count", COUNTER, nullptr}                  },
  {"proxy.process.http.total_parent_proxy_connections",                  {"proxy_process_http_total_parent_proxy_connections", COUNTER, nullptr}                  },
  {"proxy.process.http.total_parent_retries",                            {"proxy_process_http_total_parent_retries", COUNTER, nullptr}                            },
  {"proxy.process.http.total_parent_retries_exhausted",                  {"proxy_process_http_total_parent_retries_exhausted", COUNTER, nullptr}                  },
  {"proxy.process.http.total_parent_switches",                           {"proxy_process_http_total_parent_switches", COUNTER, nullptr}                           },
  {"proxy.process.http.total_server_connections",                        {"proxy_process_http_total_server_connections", COUNTER, nullptr}                        },
  {"proxy.process.http.total_transactions_time",                         {"proxy_process_http_total_transactions_time", COUNTER, nullptr}                         },
  {"proxy.process.http.total_x_redirect_count",                          {"proxy_process_http_total_x_redirect_count", COUNTER, nullptr}                          },
  {"proxy.process.http.trace_requests",                                  {"proxy_process_http_trace_requests", COUNTER, nullptr}                                  },
  {"proxy.process.tunnel.current_active_connections",                    {"proxy_process_tunnel_current_active_connections", GAUGE, nullptr}                      },
  {"proxy.process.http.tunnels",                                         {"proxy_process_http_tunnels", COUNTER, nullptr}                                         },
  {"proxy.process.http.milestone.ua_begin",                              {"proxy_process_http_milestone_ua_begin", COUNTER, nullptr}                              },
  {"proxy.process.http.milestone.ua_begin_write",                        {"proxy_process_http_milestone_ua_begin_write", COUNTER, nullptr}                        },
  {"proxy.process.http.milestone.ua_close",                              {"proxy_process_http_milestone_ua_close", COUNTER, nullptr}                              },
  {"proxy.process.http.transaction_counts.errors.aborts",
   {"proxy_process_http_transaction_counts_errors_aborts", COUNTER, nullptr}                                                                                      },
  {"proxy.process.http.transaction_counts.errors.connect_failed",
   {"proxy_process_http_transaction_counts_errors_connect_failed", COUNTER, nullptr}                                                                              },
  {"proxy.process.http.transaction_counts.errors.other",                 {"proxy_process_http_transaction_counts_errors_other", COUNTER, nullptr}                 },
  {"proxy.process.http.transaction_counts.errors.possible_aborts",
   {"proxy_process_http_transaction_counts_errors_possible_aborts", COUNTER, nullptr}                                                                             },
  {"proxy.process.http.transaction_counts.errors.pre_accept_hangups",
   {"proxy_process_http_transaction_counts_errors_pre_accept_hangups", COUNTER, nullptr}                                                                          },
  {"proxy.process.http.transaction_counts.hit_fresh",                    {"proxy_process_http_transaction_counts_hit_fresh", COUNTER, nullptr}                    },
  {"proxy.process.http.transaction_counts.hit_fresh.process",
   {"proxy_process_http_transaction_counts_hit_fresh_process", COUNTER, nullptr}                                                                                  },
  {"proxy.process.http.transaction_counts.hit_revalidated",
   {"proxy_process_http_transaction_counts_hit_revalidated", COUNTER, nullptr}                                                                                    },
  {"proxy.process.http.transaction_counts.miss_changed",                 {"proxy_process_http_transaction_counts_miss_changed", COUNTER, nullptr}                 },
  {"proxy.process.http.transaction_counts.miss_client_no_cache",
   {"proxy_process_http_transaction_counts_miss_client_no_cache", COUNTER, nullptr}                                                                               },
  {"proxy.process.http.transaction_counts.miss_cold",                    {"proxy_process_http_transaction_counts_miss_cold", COUNTER, nullptr}                    },
  {"proxy.process.http.transaction_counts.miss_not_cacheable",
   {"proxy_process_http_transaction_counts_miss_not_cacheable", COUNTER, nullptr}                                                                                 },
  {"proxy.process.http.transaction_counts.other.unclassified",
   {"proxy_process_http_transaction_counts_other_unclassified", COUNTER, nullptr}                                                                                 },
  {"proxy.process.http.milestone.ua_first_read",                         {"proxy_process_http_milestone_ua_first_read", COUNTER, nullptr}                         },
  {"proxy.process.http.transaction_totaltime.errors.aborts",
   {"proxy_process_http_transaction_totaltime_errors_aborts", COUNTER, nullptr}                                                                                   },
  {"proxy.process.http.transaction_totaltime.errors.connect_failed",
   {"proxy_process_http_transaction_totaltime_errors_connect_failed", COUNTER, nullptr}                                                                           },
  {"proxy.process.http.transaction_totaltime.errors.other",
   {"proxy_process_http_transaction_totaltime_errors_other", COUNTER, nullptr}                                                                                    },
  {"proxy.process.http.transaction_totaltime.errors.possible_aborts",
   {"proxy_process_http_transaction_totaltime_errors_possible_aborts", COUNTER, nullptr}                                                                          },
  {"proxy.process.http.transaction_totaltime.errors.pre_accept_hangups",
   {"proxy_process_http_transaction_totaltime_errors_pre_accept_hangups", COUNTER, nullptr}                                                                       },
  {"proxy.process.http.transaction_totaltime.hit_fresh",                 {"proxy_process_http_transaction_totaltime_hit_fresh", COUNTER, nullptr}                 },
  {"proxy.process.http.transaction_totaltime.hit_fresh.process",
   {"proxy_process_http_transaction_totaltime_hit_fresh_process", COUNTER, nullptr}                                                                               },
  {"proxy.process.http.transaction_totaltime.hit_revalidated",
   {"proxy_process_http_transaction_totaltime_hit_revalidated", COUNTER, nullptr}                                                                                 },
  {"proxy.process.http.transaction_totaltime.miss_changed",
   {"proxy_process_http_transaction_totaltime_miss_changed", COUNTER, nullptr}                                                                                    },
  {"proxy.process.http.transaction_totaltime.miss_client_no_cache",
   {"proxy_process_http_transaction_totaltime_miss_client_no_cache", COUNTER, nullptr}                                                                            },
  {"proxy.process.http.transaction_totaltime.miss_cold",                 {"proxy_process_http_transaction_totaltime_miss_cold", COUNTER, nullptr}                 },
  {"proxy.process.http.transaction_totaltime.miss_not_cacheable",
   {"proxy_process_http_transaction_totaltime_miss_not_cacheable", COUNTER, nullptr}                                                                              },
  {"proxy.process.http.transaction_totaltime.other.unclassified",
   {"proxy_process_http_transaction_totaltime_other_unclassified", COUNTER, nullptr}                                                                              },
  {"proxy.process.http.milestone.ua_read_header_done",                   {"proxy_process_http_milestone_ua_read_header_done", COUNTER, nullptr}                   },
  {"proxy.process.http.user_agent_request_document_total_size",
   {"proxy_process_http_user_agent_request_document_total_size", COUNTER, nullptr}                                                                                },
  {"proxy.process.http.user_agent_request_header_total_size",
   {"proxy_process_http_user_agent_request_header_total_size", COUNTER, nullptr}                                                                                  },
  {"proxy.process.http.user_agent_response_document_total_size",
   {"proxy_process_http_user_agent_response_document_total_size", COUNTER, nullptr}                                                                               },
  {"proxy.process.http.user_agent_response_header_total_size",
   {"proxy_process_http_user_agent_response_header_total_size", COUNTER, nullptr}                                                                                 },
  {"proxy.process.http.websocket.current_active_client_connections",
   {"proxy_process_http_websocket_current_active_client_connections", GAUGE, nullptr}                                                                             },

  {"proxy.process.http.user_agent_total_request_bytes",
   {"proxy_process_http_user_agent_total_request_bytes", COUNTER, "Total bytes of client request body + headers"}                                                 },
  {"proxy.process.http.user_agent_total_response_bytes",
   {"proxy_process_http_user_agent_total_response_bytes", COUNTER, "Total bytes of client response body + headers"}                                               },
  {"proxy.process.http.origin_server_total_request_bytes",
   {"proxy_process_http_origin_server_total_request_bytes", COUNTER, "Total bytes of origin server request body + headers"}                                       },
  {"proxy.process.http.origin_server_total_response_bytes",
   {"proxy_process_http_origin_server_total_response_bytes", COUNTER, "Total bytes of origin server response body + headers"}                                     },
  {"proxy.process.user_agent_total_bytes",
   {"proxy_process_user_agent_total_bytes", COUNTER,
    "Total bytes of client request and response (total traffic to and from clients)"}                                                                             },
  {"proxy.process.origin_server_total_bytes",
   {"proxy_process_origin_server_total_bytes", COUNTER, "Total bytes of origin/parent request and response"}                                                      },
  {"proxy.process.cache_total_hits",                                     {"proxy_process_cache_total_hits", COUNTER, "Total requests which are cache hits"}       },
  {"proxy.process.cache_total_misses",                                   {"proxy_process_cache_total_misses", COUNTER, "Total requests which are cache misses"}   },
  {"proxy.process.current_server_connections",
   {"proxy_process_current_server_connections", GAUGE, "Total of all server connections (sum of origins and parent connections)"}                                 },
  {"proxy.process.cache_total_requests",
   {"proxy_process_cache_total_requests", COUNTER,
    "Total requests, both hits and misses (this is slightly superfluous, but assures correct percentage calculations)"}                                           },
  {"proxy.process.cache_total_hits_bytes",
   {"proxy_process_cache_total_hits_bytes", COUNTER, "Total cache requests bytes which are cache hits"}                                                           },
  {"proxy.process.cache_total_misses_bytes",
   {"proxy_process_cache_total_misses_bytes", COUNTER, "Total cache requests bytes which are cache misses"}                                                       },
  {"proxy.process.cache_total_bytes",                                    {"proxy_process_cache_total_bytes", COUNTER, "Total request bytes, both hits and misses"}},

  // src/proxy/http/PreWarmManager.cc

  // src/proxy/http2/HTTP2.cc
  {"proxy.process.http2.current_client_connections",                     {"proxy_process_http2_current_client_connections", GAUGE, nullptr}                       },
  {"proxy.process.http2.current_server_connections",                     {"proxy_process_http2_current_server_connections", GAUGE, nullptr}                       },
  {"proxy.process.http2.current_active_client_connections",
   {"proxy_process_http2_current_active_client_connections", GAUGE, nullptr}                                                                                      },
  {"proxy.process.http2.current_active_server_connections",
   {"proxy_process_http2_current_active_server_connections", GAUGE, nullptr}                                                                                      },
  {"proxy.process.http2.current_client_streams",                         {"proxy_process_http2_current_client_streams", GAUGE, nullptr}                           },
  {"proxy.process.http2.current_server_streams",                         {"proxy_process_http2_current_server_streams", GAUGE, nullptr}                           },
  {"proxy.process.http2.total_client_streams",                           {"proxy_process_http2_total_client_streams", COUNTER, nullptr}                           },
  {"proxy.process.http2.total_server_streams",                           {"proxy_process_http2_total_server_streams", COUNTER, nullptr}                           },
  {"proxy.process.http2.total_transactions_time",                        {"proxy_process_http2_total_transactions_time", COUNTER, nullptr}                        },
  {"proxy.process.http2.total_client_connections",                       {"proxy_process_http2_total_client_connections", COUNTER, nullptr}                       },
  {"proxy.process.http2.total_server_connections",                       {"proxy_process_http2_total_server_connections", COUNTER, nullptr}                       },
  {"proxy.process.http2.stream_errors",                                  {"proxy_process_http2_stream_errors", COUNTER, nullptr}                                  },
  {"proxy.process.http2.connection_errors",                              {"proxy_process_http2_connection_errors", COUNTER, nullptr}                              },
  {"proxy.process.http2.session_die_default",                            {"proxy_process_http2_session_die_default", COUNTER, nullptr}                            },
  {"proxy.process.http2.session_die_other",                              {"proxy_process_http2_session_die_other", COUNTER, nullptr}                              },
  {"proxy.process.http2.session_die_active",                             {"proxy_process_http2_session_die_active", COUNTER, nullptr}                             },
  {"proxy.process.http2.session_die_inactive",                           {"proxy_process_http2_session_die_inactive", COUNTER, nullptr}                           },
  {"proxy.process.http2.session_die_eos",                                {"proxy_process_http2_session_die_eos", COUNTER, nullptr}                                },
  {"proxy.process.http2.session_die_error",                              {"proxy_process_http2_session_die_error", COUNTER, nullptr}                              },
  {"proxy.process.http2.session_die_high_error_rate",                    {"proxy_process_http2_session_die_high_error_rate", COUNTER, nullptr}                    },
  {"proxy.process.http2.max_settings_per_frame_exceeded",
   {"proxy_process_http2_max_settings_per_frame_exceeded", COUNTER, nullptr}                                                                                      },
  {"proxy.process.http2.max_settings_per_minute_exceeded",
   {"proxy_process_http2_max_settings_per_minute_exceeded", COUNTER, nullptr}                                                                                     },
  {"proxy.process.http2.max_settings_frames_per_minute_exceeded",
   {"proxy_process_http2_max_settings_frames_per_minute_exceeded", COUNTER, nullptr}                                                                              },
  {"proxy.process.http2.max_ping_frames_per_minute_exceeded",
   {"proxy_process_http2_max_ping_frames_per_minute_exceeded", COUNTER, nullptr}                                                                                  },
  {"proxy.process.http2.max_priority_frames_per_minute_exceeded",
   {"proxy_process_http2_max_priority_frames_per_minute_exceeded", COUNTER, nullptr}                                                                              },
  {"proxy.process.http2.max_rst_stream_frames_per_minute_exceeded",
   {"proxy_process_http2_max_rst_stream_frames_per_minute_exceeded", COUNTER, nullptr}                                                                            },
  {"proxy.process.http2.max_continuation_frames_per_minute_exceeded",
   {"proxy_process_http2_max_continuation_frames_per_minute_exceeded", COUNTER, nullptr}                                                                          },
  {"proxy.process.http2.max_empty_frames_per_minute_exceeded",
   {"proxy_process_http2_max_empty_frames_per_minute_exceeded", COUNTER, nullptr}                                                                                 },
  {"proxy.process.http2.insufficient_avg_window_update",                 {"proxy_process_http2_insufficient_avg_window_update", COUNTER, nullptr}                 },
  {"proxy.process.http2.max_concurrent_streams_exceeded_in",
   {"proxy_process_http2_max_concurrent_streams_exceeded_in", COUNTER, nullptr}                                                                                   },
  {"proxy.process.http2.max_concurrent_streams_exceeded_out",
   {"proxy_process_http2_max_concurrent_streams_exceeded_out", COUNTER, nullptr}                                                                                  },
  {"proxy.process.http2.data_frames_in",                                 {"proxy_process_http2_data_frames_in", COUNTER, nullptr}                                 },
  {"proxy.process.http2.headers_frames_in",                              {"proxy_process_http2_headers_frames_in", COUNTER, nullptr}                              },
  {"proxy.process.http2.priority_frames_in",                             {"proxy_process_http2_priority_frames_in", COUNTER, nullptr}                             },
  {"proxy.process.http2.rst_stream_frames_in",                           {"proxy_process_http2_rst_stream_frames_in", COUNTER, nullptr}                           },
  {"proxy.process.http2.settings_frames_in",                             {"proxy_process_http2_settings_frames_in", COUNTER, nullptr}                             },
  {"proxy.process.http2.push_promise_frames_in",                         {"proxy_process_http2_push_promise_frames_in", COUNTER, nullptr}                         },
  {"proxy.process.http2.ping_frames_in",                                 {"proxy_process_http2_ping_frames_in", COUNTER, nullptr}                                 },
  {"proxy.process.http2.goaway_frames_in",                               {"proxy_process_http2_goaway_frames_in", COUNTER, nullptr}                               },
  {"proxy.process.http2.window_update_frames_in",                        {"proxy_process_http2_window_update_frames_in", COUNTER, nullptr}                        },
  {"proxy.process.http2.continuation_frames_in",                         {"proxy_process_http2_continuation_frames_in", COUNTER, nullptr}                         },
  {"proxy.process.http2.unknown_frames_in",                              {"proxy_process_http2_unknown_frames_in", COUNTER, nullptr}                              },

  // src/proxy/http3/Http3.cc
  {"proxy.process.http3.data_frames_in",                                 {"proxy_process_http3_data_frames_in", COUNTER, nullptr}                                 },
  {"proxy.process.http3.headers_frames_in",                              {"proxy_process_http3_headers_frames_in", COUNTER, nullptr}                              },
  {"proxy.process.http3.cancel_push_frames_in",                          {"proxy_process_http3_cancel_push_frames_in", COUNTER, nullptr}                          },
  {"proxy.process.http3.settings_frames_in",                             {"proxy_process_http3_settings_frames_in", COUNTER, nullptr}                             },
  {"proxy.process.http3.push_promise_frames_in",                         {"proxy_process_http3_push_promise_frames_in", COUNTER, nullptr}                         },
  {"proxy.process.http3.goaway_frames_in",                               {"proxy_process_http3_goaway_frames_in", COUNTER, nullptr}                               },
  {"proxy.process.http3.max_push_id_frames_in",                          {"proxy_process_http3_max_push_id_frames_in", COUNTER, nullptr}                          },
  {"proxy.process.http3.unknown_frames_in",                              {"proxy_process_http3_unknown_frames_in", COUNTER, nullptr}                              },

  // src/proxy/logging/LogConfig.cc
  {"proxy.process.log.event_log_error_skip",                             {"proxy_process_log_event_log_error_skip", COUNTER, nullptr}                             },
  {"proxy.process.log.event_log_error_ok",                               {"proxy_process_log_event_log_error_ok", COUNTER, nullptr}                               },
  {"proxy.process.log.event_log_error_aggr",                             {"proxy_process_log_event_log_error_aggr", COUNTER, nullptr}                             },
  {"proxy.process.log.event_log_error_full",                             {"proxy_process_log_event_log_error_full", COUNTER, nullptr}                             },
  {"proxy.process.log.event_log_error_fail",                             {"proxy_process_log_event_log_error_fail", COUNTER, nullptr}                             },
  {"proxy.process.log.event_log_access_ok",                              {"proxy_process_log_event_log_access_ok", COUNTER, nullptr}                              },
  {"proxy.process.log.event_log_access_skip",                            {"proxy_process_log_event_log_access_skip", COUNTER, nullptr}                            },
  {"proxy.process.log.event_log_access_aggr",                            {"proxy_process_log_event_log_access_aggr", COUNTER, nullptr}                            },
  {"proxy.process.log.event_log_access_full",                            {"proxy_process_log_event_log_access_full", COUNTER, nullptr}                            },
  {"proxy.process.log.event_log_access_fail",                            {"proxy_process_log_event_log_access_fail", COUNTER, nullptr}                            },
  {"proxy.process.log.num_sent_to_network",                              {"proxy_process_log_num_sent_to_network", COUNTER, nullptr}                              },
  {"proxy.process.log.num_lost_before_sent_to_network",                  {"proxy_process_log_num_lost_before_sent_to_network", COUNTER, nullptr}                  },
  {"proxy.process.log.num_received_from_network",                        {"proxy_process_log_num_received_from_network", COUNTER, nullptr}                        },
  {"proxy.process.log.num_flush_to_disk",                                {"proxy_process_log_num_flush_to_disk", COUNTER, nullptr}                                },
  {"proxy.process.log.num_lost_before_flush_to_disk",                    {"proxy_process_log_num_lost_before_flush_to_disk", COUNTER, nullptr}                    },
  {"proxy.process.log.bytes_lost_before_preproc",                        {"proxy_process_log_bytes_lost_before_preproc", COUNTER, nullptr}                        },
  {"proxy.process.log.bytes_sent_to_network",                            {"proxy_process_log_bytes_sent_to_network", COUNTER, nullptr}                            },
  {"proxy.process.log.bytes_lost_before_sent_to_network",
   {"proxy_process_log_bytes_lost_before_sent_to_network", COUNTER, nullptr}                                                                                      },
  {"proxy.process.log.bytes_received_from_network",                      {"proxy_process_log_bytes_received_from_network", COUNTER, nullptr}                      },
  {"proxy.process.log.bytes_flush_to_disk",                              {"proxy_process_log_bytes_flush_to_disk", COUNTER, nullptr}                              },
  {"proxy.process.log.bytes_lost_before_flush_to_disk",                  {"proxy_process_log_bytes_lost_before_flush_to_disk", COUNTER, nullptr}                  },
  {"proxy.process.log.bytes_written_to_disk",                            {"proxy_process_log_bytes_written_to_disk", COUNTER, nullptr}                            },
  {"proxy.process.log.bytes_lost_before_written_to_disk",
   {"proxy_process_log_bytes_lost_before_written_to_disk", COUNTER, nullptr}                                                                                      },
  {"proxy.process.log.log_files_open",                                   {"proxy_process_log_log_files_open", GAUGE, nullptr}                                     },
  {"proxy.process.log.log_files_space_used",                             {"proxy_process_log_log_files_space_used", GAUGE, nullptr}                               },

  // src/traffic_server/traffic_server.cc
  {"proxy.process.traffic_server.memory.rss",                            {"proxy_process_traffic_server_memory_rss", GAUGE, nullptr}                              },
  {"proxy.process.proxy.reconfigure_time",                               {"proxy_process_proxy_reconfigure_time", GAUGE, nullptr}                                 },
  {"proxy.process.proxy.start_time",                                     {"proxy_process_proxy_start_time", GAUGE, nullptr}                                       },
  {"proxy.process.proxy.reconfigure_required",                           {"proxy_process_proxy_reconfigure_required", GAUGE, nullptr}                             },
  {"proxy.process.proxy.restart_required",                               {"proxy_process_proxy_restart_required", GAUGE, nullptr}                                 },
  {"proxy.process.proxy.draining",                                       {"proxy_process_proxy_draining", GAUGE, nullptr}                                         },
  {"proxy.process.proxy.cache_ready_time",                               {"proxy_process_proxy_cache_ready_time", GAUGE, nullptr}                                 },

  // plugins/stats_over_http/stats_over_http.cc
  {"current_time_epoch_ms",                                              {"proxy_process_current_time_epoch_ms", COUNTER, "current time epoch in milliseconds"}   },
};

#define APPEND_STAT_TEXT_PROMETHEUS(a, fmt, v)                                                                                 \
  do {                                                                                                                         \
    char b[256];                                                                                                               \
    char prom_name[256];                                                                                                       \
    /* replace character other than [a-zA-Z0-9_:] with _ */                                                                    \
    char *q = prom_name;                                                                                                       \
    for (const char *p = a; *p; p++, q++) {                                                                                    \
      char c = *p;                                                                                                             \
      *q     = (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '_' || c == ':') ? c : '_'; \
    }                                                                                                                          \
    *q = '\0';                                                                                                                 \
    if (snprintf(b, sizeof(b), "# %s " fmt "\n", prom_name, v) < (int)sizeof(b))                                               \
      APPEND(b);                                                                                                               \
  } while (0)
#define API_TIME_PREFIX              "proxy.process.api.time."
#define EVENTLOOP_PREFIX             "proxy.process.eventloop."
#define SSL_CIPHER_USER_AGENT_PREFIX "proxy.process.ssl.cipher.user_agent."
#define has_prefix_literal(s, lit)   (!strncmp(s, lit, sizeof(lit) - 1))
#define APPEND_STAT_TEXT_PROMETHEUS_NUMERIC(a, fmt, v)                                                                           \
  do {                                                                                                                           \
    char        b[256];                                                                                                          \
    char        prom_name_buf[256];                                                                                              \
    const char *prom_name;                                                                                                       \
    const char *type = nullptr;                                                                                                  \
    const char *help = nullptr;                                                                                                  \
    auto        it   = prom_metric_info_map.find(a);                                                                             \
    if (it != prom_metric_info_map.end()) {                                                                                      \
      prom_name = it->second.prom_name;                                                                                          \
      type      = it->second.type;                                                                                               \
      help      = it->second.help;                                                                                               \
    } else {                                                                                                                     \
      /* replace character other than [a-zA-Z0-9_:] with _ */                                                                    \
      char *q = prom_name_buf;                                                                                                   \
      for (const char *p = a; *p; p++, q++) {                                                                                    \
        char c = *p;                                                                                                             \
        *q     = (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '_' || c == ':') ? c : '_'; \
      }                                                                                                                          \
      *q        = '\0';                                                                                                          \
      prom_name = prom_name_buf;                                                                                                 \
      if (has_prefix_literal(a, API_TIME_PREFIX) || has_prefix_literal(a, EVENTLOOP_PREFIX) ||                                   \
          has_prefix_literal(a, SSL_CIPHER_USER_AGENT_PREFIX))                                                                   \
        type = COUNTER;                                                                                                          \
    }                                                                                                                            \
    if (help != nullptr) {                                                                                                       \
      if (snprintf(b, sizeof(b), "# HELP %s %s\n# TYPE %s %s\n%s " fmt "\n", prom_name, help, prom_name, type, prom_name, v) <   \
          (int)sizeof(b))                                                                                                        \
        APPEND(b);                                                                                                               \
    } else if (type != nullptr) {                                                                                                \
      if (snprintf(b, sizeof(b), "# TYPE %s %s\n%s " fmt "\n", prom_name, type, prom_name, v) < (int)sizeof(b))                  \
        APPEND(b);                                                                                                               \
    } else {                                                                                                                     \
      if (snprintf(b, sizeof(b), "%s " fmt "\n", prom_name, v) < (int)sizeof(b))                                                 \
        APPEND(b);                                                                                                               \
    }                                                                                                                            \
  } while (0)

static void
text_prometheus_out_stat(TSRecordType /* rec_type ATS_UNUSED */, void *edata, int /* registered ATS_UNUSED */, const char *name,
                         TSRecordDataType data_type, TSRecordData *datum)
{
  stats_state *my_state = static_cast<stats_state *>(edata);

  switch (data_type) {
  case TS_RECORDDATATYPE_COUNTER:
    APPEND_STAT_TEXT_PROMETHEUS_NUMERIC(name, "%" PRIu64, wrap_unsigned_counter(datum->rec_counter));
    break;
  case TS_RECORDDATATYPE_INT:
    APPEND_STAT_TEXT_PROMETHEUS_NUMERIC(name, "%" PRIu64, wrap_unsigned_counter(datum->rec_int));
    break;
  case TS_RECORDDATATYPE_FLOAT:
    APPEND_STAT_TEXT_PROMETHEUS_NUMERIC(name, "%g", datum->rec_float);
    break;
  case TS_RECORDDATATYPE_STRING:
    APPEND_STAT_TEXT_PROMETHEUS(name, "%s", datum->rec_string);
    break;
  default:
    Dbg(dbg_ctl, "unknown type for %s: %d", name, data_type);
    break;
  }
}

static void
text_prometheus_out_stats(stats_state *my_state)
{
  const char *version;
  TSRecordDump((TSRecordType)(TS_RECORDTYPE_PLUGIN | TS_RECORDTYPE_NODE | TS_RECORDTYPE_PROCESS), text_prometheus_out_stat,
               my_state);
  APPEND_STAT_TEXT_PROMETHEUS_NUMERIC("current_time_epoch_ms", "%" PRIu64, ms_since_epoch());
  version = TSTrafficServerVersionGet();
  APPEND_STAT_TEXT_PROMETHEUS("version", "%s", version);
}

static void
stats_process_write(TSCont contp, TSEvent event, stats_state *my_state)
{
  if (event == TS_EVENT_VCONN_WRITE_READY) {
    if (my_state->body_written == 0) {
      my_state->body_written = 1;
      switch (my_state->output) {
      case JSON_OUTPUT:
        json_out_stats(my_state);
        break;
      case CSV_OUTPUT:
        csv_out_stats(my_state);
        break;
      case TEXT_PROMETHEUS_OUTPUT:
        text_prometheus_out_stats(my_state);
        break;
      default:
        TSError("stats_process_write: Unknown output type\n");
        break;
      }

      if ((my_state->encoding == GZIP) || (my_state->encoding == DEFLATE)) {
        gzip_out_stats(my_state);
      }
#if HAVE_BROTLI_ENCODE_H
      else if (my_state->encoding == BR) {
        br_out_stats(my_state);
      }
#endif
      TSVIONBytesSet(my_state->write_vio, my_state->output_bytes);
    }
    TSVIOReenable(my_state->write_vio);
  } else if (event == TS_EVENT_VCONN_WRITE_COMPLETE) {
    stats_cleanup(contp, my_state);
  } else if (event == TS_EVENT_ERROR) {
    TSError("[%s] stats_process_write: Received TS_EVENT_ERROR", PLUGIN_NAME);
  } else {
    TSReleaseAssert(!"Unexpected Event");
  }
}

static int
stats_dostuff(TSCont contp, TSEvent event, void *edata)
{
  stats_state *my_state = static_cast<stats_state *>(TSContDataGet(contp));
  if (event == TS_EVENT_NET_ACCEPT) {
    my_state->net_vc = (TSVConn)edata;
    stats_process_accept(contp, my_state);
  } else if (edata == my_state->read_vio) {
    stats_process_read(contp, event, my_state);
  } else if (edata == my_state->write_vio) {
    stats_process_write(contp, event, my_state);
  } else {
    TSReleaseAssert(!"Unexpected Event");
  }
  return 0;
}

static int
stats_origin(TSCont contp, TSEvent /* event ATS_UNUSED */, void *edata)
{
  TSCont       icontp;
  stats_state *my_state;
  config_t    *config;
  TSHttpTxn    txnp = (TSHttpTxn)edata;
  TSMBuffer    reqp;
  TSMLoc       hdr_loc = nullptr, url_loc = nullptr, accept_field = nullptr, accept_encoding_field = nullptr;
  TSEvent      reenable = TS_EVENT_HTTP_CONTINUE;
  int          path_len = 0;
  const char  *path     = nullptr;

  Dbg(dbg_ctl, "in the read stuff");
  config = get_config(contp);

  if (TSHttpTxnClientReqGet(txnp, &reqp, &hdr_loc) != TS_SUCCESS) {
    goto cleanup;
  }

  if (TSHttpHdrUrlGet(reqp, hdr_loc, &url_loc) != TS_SUCCESS) {
    goto cleanup;
  }

  path = TSUrlPathGet(reqp, url_loc, &path_len);
  Dbg(dbg_ctl, "Path: %.*s", path_len, path);

  if (!(path_len != 0 && path_len == int(config->stats_path.length()) &&
        !memcmp(path, config->stats_path.c_str(), config->stats_path.length()))) {
    Dbg(dbg_ctl, "not this plugins path, saw: %.*s, looking for: %s", path_len, path, config->stats_path.c_str());
    goto notforme;
  }

  if (auto addr = TSHttpTxnClientAddrGet(txnp); !is_ipmap_allowed(config, addr)) {
    Dbg(dbg_ctl, "not right ip");
    TSHttpTxnStatusSet(txnp, TS_HTTP_STATUS_FORBIDDEN);
    reenable = TS_EVENT_HTTP_ERROR;
    goto notforme;
  }

  TSHttpTxnCntlSet(txnp, TS_HTTP_CNTL_SKIP_REMAPPING, true); // not strictly necessary, but speed is everything these days

  /* This is us -- register our intercept */
  Dbg(dbg_ctl, "Intercepting request");

  my_state = (stats_state *)TSmalloc(sizeof(*my_state));
  memset(my_state, 0, sizeof(*my_state));
  icontp = TSContCreate(stats_dostuff, TSMutexCreate());

  accept_field     = TSMimeHdrFieldFind(reqp, hdr_loc, TS_MIME_FIELD_ACCEPT, TS_MIME_LEN_ACCEPT);
  my_state->output = JSON_OUTPUT; // default to json output
  // accept header exists, use it to determine response type
  if (accept_field != TS_NULL_MLOC) {
    int         len = -1;
    const char *str = TSMimeHdrFieldValueStringGet(reqp, hdr_loc, accept_field, -1, &len);

    // Parse the Accept header, default to JSON output unless its another supported format
    if (!strncasecmp(str, "text/csv", len)) {
      my_state->output = CSV_OUTPUT;
    } else if (!strncasecmp(str, "text/plain", len)) {
      my_state->output = TEXT_PROMETHEUS_OUTPUT;
    } else {
      my_state->output = JSON_OUTPUT;
    }
  }

  // Check for Accept Encoding and init
  accept_encoding_field = TSMimeHdrFieldFind(reqp, hdr_loc, TS_MIME_FIELD_ACCEPT_ENCODING, TS_MIME_LEN_ACCEPT_ENCODING);
  my_state->encoding    = NONE;
  if (accept_encoding_field != TS_NULL_MLOC) {
    int         len = -1;
    const char *str = TSMimeHdrFieldValueStringGet(reqp, hdr_loc, accept_encoding_field, -1, &len);
    if (len >= TS_HTTP_LEN_DEFLATE && strstr(str, TS_HTTP_VALUE_DEFLATE) != nullptr && my_state->output != TEXT_PROMETHEUS_OUTPUT) {
      Dbg(dbg_ctl, "Saw deflate in accept encoding");
      my_state->encoding = init_gzip(my_state, DEFLATE_MODE);
    } else if (len >= TS_HTTP_LEN_GZIP && strstr(str, TS_HTTP_VALUE_GZIP) != nullptr) {
      Dbg(dbg_ctl, "Saw gzip in accept encoding");
      my_state->encoding = init_gzip(my_state, GZIP_MODE);
    }
#if HAVE_BROTLI_ENCODE_H
    else if (len >= TS_HTTP_LEN_BROTLI && strstr(str, TS_HTTP_VALUE_BROTLI) != nullptr &&
             my_state->output != TEXT_PROMETHEUS_OUTPUT) {
      Dbg(dbg_ctl, "Saw br in accept encoding");
      my_state->encoding = init_br(my_state);
    }
#endif
    else {
      my_state->encoding = NONE;
    }
  }
  Dbg(dbg_ctl, "Finished AE check");

  TSContDataSet(icontp, my_state);
  TSHttpTxnIntercept(icontp, txnp);
  goto cleanup;

notforme:

cleanup:
  if (url_loc) {
    TSHandleMLocRelease(reqp, hdr_loc, url_loc);
  }
  if (hdr_loc) {
    TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdr_loc);
  }
  if (accept_field) {
    TSHandleMLocRelease(reqp, TS_NULL_MLOC, accept_field);
  }
  if (accept_encoding_field) {
    TSHandleMLocRelease(reqp, TS_NULL_MLOC, accept_encoding_field);
  }
  TSHttpTxnReenable(txnp, reenable);
  return 0;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  static const char          usage[]    = PLUGIN_NAME ".so [--integer-counters] [PATH]";
  static const struct option longopts[] = {
    {(char *)("integer-counters"), no_argument, nullptr, 'i'},
    {(char *)("wrap-counters"),    no_argument, nullptr, 'w'},
    {nullptr,                      0,           nullptr, 0  }
  };
  TSCont           main_cont, config_cont;
  config_holder_t *config_holder;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] registration failed", PLUGIN_NAME);
    goto done;
  }

  for (;;) {
    switch (getopt_long(argc, (char *const *)argv, "iw", longopts, nullptr)) {
    case 'i':
      integer_counters = true;
      break;
    case 'w':
      wrap_counters = true;
      break;
    case -1:
      goto init;
    default:
      TSError("[%s] usage: %s", PLUGIN_NAME, usage);
    }
  }

init:
  argc -= optind;
  argv += optind;

  config_holder = new_config_holder(argc > 0 ? argv[0] : nullptr);

  /* Path was not set during load, so the param was not a config file, we also
    have an argument so it must be the path, set it here.  Otherwise if no argument
    then use the default _stats path */
  if ((config_holder->config != nullptr) && (config_holder->config->stats_path.empty()) && (argc > 0) &&
      (config_holder->config_path == nullptr)) {
    config_holder->config->stats_path = argv[0] + ('/' == argv[0][0] ? 1 : 0);
  } else if ((config_holder->config != nullptr) && (config_holder->config->stats_path.empty())) {
    config_holder->config->stats_path = DEFAULT_URL_PATH;
  }

  /* Create a continuation with a mutex as there is a shared global structure
     containing the headers to add */
  main_cont = TSContCreate(stats_origin, nullptr);
  TSContDataSet(main_cont, (void *)config_holder);
  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, main_cont);

  /* Create continuation for management updates to re-read config file */
  if (config_holder->config_path != nullptr) {
    config_cont = TSContCreate(config_handler, TSMutexCreate());
    TSContDataSet(config_cont, (void *)config_holder);
    TSMgmtUpdateRegister(config_cont, PLUGIN_NAME);
  }

  if (config_holder->config != nullptr) {
    Dbg(dbg_ctl, "stats module registered with path %s", config_holder->config->stats_path.c_str());
  }

done:
  return;
}

static bool
is_ipmap_allowed(const config_t *config, const struct sockaddr *addr)
{
  if (!addr) {
    return true;
  }

  if (config->addrs.contains(swoc::IPAddr(addr))) {
    return true;
  }

  return false;
}
static void
parseIpMap(config_t *config, swoc::TextView txt)
{
  // sent null ipstring, fill with default open IPs
  if (txt.empty()) {
    config->addrs.fill(DEFAULT_IP6);
    config->addrs.fill(DEFAULT_IP);
    Dbg(dbg_ctl, "Empty allow settings, setting all IPs in allow list");
    return;
  }

  while (txt) {
    auto token{txt.take_prefix_at(',')};
    if (swoc::IPRange r; r.load(token)) {
      config->addrs.fill(r);
      Dbg(dbg_ctl, "Added %.*s to allow ip list", int(token.length()), token.data());
    }
  }
}

static config_t *
new_config(std::fstream &fh)
{
  config_t *config    = nullptr;
  config              = new config_t();
  config->recordTypes = DEFAULT_RECORD_TYPES;
  config->stats_path  = "";
  std::string cur_line;

  if (!fh) {
    Dbg(dbg_ctl, "No config file, using defaults");
    return config;
  }

  while (std::getline(fh, cur_line)) {
    swoc::TextView line{cur_line};
    if (line.ltrim_if(&isspace).empty() || '#' == *line) {
      continue; /* # Comments, only at line beginning */
    }

    size_t p = 0;

    static constexpr swoc::TextView PATH_TAG   = "path=";
    static constexpr swoc::TextView RECORD_TAG = "record_types=";
    static constexpr swoc::TextView ADDR_TAG   = "allow_ip=";
    static constexpr swoc::TextView ADDR6_TAG  = "allow_ip6=";

    if ((p = line.find(PATH_TAG)) != std::string::npos) {
      line.remove_prefix(p + PATH_TAG.size()).ltrim('/');
      Dbg(dbg_ctl, "parsing path");
      config->stats_path = line;
    } else if ((p = line.find(RECORD_TAG)) != std::string::npos) {
      Dbg(dbg_ctl, "parsing record types");
      line.remove_prefix(p).remove_prefix(RECORD_TAG.size());
      config->recordTypes = swoc::svtou(line, nullptr, 16);
    } else if ((p = line.find(ADDR_TAG)) != std::string::npos) {
      parseIpMap(config, line.remove_prefix(p).remove_prefix(ADDR_TAG.size()));
    } else if ((p = line.find(ADDR6_TAG)) != std::string::npos) {
      parseIpMap(config, line.remove_prefix(p).remove_prefix(ADDR6_TAG.size()));
    }
  }

  if (config->addrs.count() == 0) {
    Dbg(dbg_ctl, "empty ip map found, setting defaults");
    parseIpMap(config, nullptr);
  }

  Dbg(dbg_ctl, "config path=%s", config->stats_path.c_str());

  return config;
}

static void
delete_config(config_t *config)
{
  Dbg(dbg_ctl, "Freeing config");
  TSfree(config);
}

// standard api below...
static config_t *
get_config(TSCont cont)
{
  config_holder_t *configh = (config_holder_t *)TSContDataGet(cont);
  if (!configh) {
    return 0;
  }
  return configh->config;
}

static void
load_config_file(config_holder_t *config_holder)
{
  std::fstream fh;
  struct stat  s;

  config_t *newconfig, *oldconfig;
  TSCont    free_cont;

  configReloadRequests++;
  lastReloadRequest = time(nullptr);

  // check date
  if ((config_holder->config_path == nullptr) || (stat(config_holder->config_path, &s) < 0)) {
    Dbg(dbg_ctl, "Could not stat %s", config_holder->config_path);
    config_holder->config_path = nullptr;
    if (config_holder->config) {
      return;
    }
  } else {
    Dbg(dbg_ctl, "s.st_mtime=%lu, last_load=%lu", s.st_mtime, config_holder->last_load);
    if (s.st_mtime < config_holder->last_load) {
      return;
    }
  }

  if (config_holder->config_path != nullptr) {
    Dbg(dbg_ctl, "Opening config file: %s", config_holder->config_path);
    fh.open(config_holder->config_path, std::ios::in);
  }

  if (!fh.is_open() && config_holder->config_path != nullptr) {
    TSError("[%s] Unable to open config: %s. Will use the param as the path, or %s if null\n", PLUGIN_NAME,
            config_holder->config_path, DEFAULT_URL_PATH.c_str());
    if (config_holder->config) {
      return;
    }
  }

  newconfig = 0;
  newconfig = new_config(fh);
  if (newconfig) {
    configReloads++;
    lastReload               = lastReloadRequest;
    config_holder->last_load = lastReloadRequest;
    config_t **confp         = &(config_holder->config);
    oldconfig                = __sync_lock_test_and_set(confp, newconfig);
    if (oldconfig) {
      Dbg(dbg_ctl, "scheduling free: %p (%p)", oldconfig, newconfig);
      free_cont = TSContCreate(free_handler, TSMutexCreate());
      TSContDataSet(free_cont, (void *)oldconfig);
      TSContScheduleOnPool(free_cont, FREE_TMOUT, TS_THREAD_POOL_TASK);
    }
  }
  if (fh) {
    fh.close();
  }
  return;
}

static config_holder_t *
new_config_holder(const char *path)
{
  config_holder_t *config_holder = static_cast<config_holder_t *>(TSmalloc(sizeof(config_holder_t)));
  config_holder->config_path     = 0;
  config_holder->config          = 0;
  config_holder->last_load       = 0;

  if (path) {
    config_holder->config_path = nstr(path);
  } else {
    config_holder->config_path = nullptr;
  }
  load_config_file(config_holder);
  return config_holder;
}

static int
free_handler(TSCont cont, TSEvent /* event ATS_UNUSED */, void * /* edata ATS_UNUSED */)
{
  config_t *config;
  config = (config_t *)TSContDataGet(cont);
  delete_config(config);
  TSContDestroy(cont);
  return 0;
}

static int
config_handler(TSCont cont, TSEvent /* event ATS_UNUSED */, void * /* edata ATS_UNUSED */)
{
  config_holder_t *config_holder;
  config_holder = (config_holder_t *)TSContDataGet(cont);
  load_config_file(config_holder);

  /* We received a reload, check if the path value was removed since it was not set after load.
     If unset, then we'll use the default */
  if (config_holder->config->stats_path == "") {
    config_holder->config->stats_path = DEFAULT_URL_PATH;
  }
  return 0;
}
