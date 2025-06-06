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

/****************************************************************************

   HttpTunnel.h

   Description:


****************************************************************************/

#pragma once

#include "iocore/eventsystem/EventSystem.h"

// Get rid of any previous definition first... /leif
#ifdef MAX_PRODUCERS
#undef MAX_PRODUCERS
#endif
#ifdef MAX_CONSUMERS
#undef MAX_CONSUMERS
#endif
#define MAX_PRODUCERS 4
#define MAX_CONSUMERS 8

#define HTTP_TUNNEL_EVENT_DONE            (HTTP_TUNNEL_EVENTS_START + 1)
#define HTTP_TUNNEL_EVENT_PRECOMPLETE     (HTTP_TUNNEL_EVENTS_START + 2)
#define HTTP_TUNNEL_EVENT_CONSUMER_DETACH (HTTP_TUNNEL_EVENTS_START + 3)
#define HTTP_TUNNEL_EVENT_ACTIVITY_CHECK  (HTTP_TUNNEL_EVENTS_START + 4)
#define HTTP_TUNNEL_EVENT_PARSE_ERROR     (HTTP_TUNNEL_EVENTS_START + 5)

#define HTTP_TUNNEL_STATIC_PRODUCER (VConnection *)!0

// YTS Team, yamsat Plugin
#define ALLOCATE_AND_WRITE_TO_BUF 1
#define WRITE_TO_BUF              2

struct HttpTunnelProducer;
class HttpSM;
using HttpSMHandler = int (HttpSM::*)(int, void *);

struct HttpTunnelConsumer;
struct HttpTunnelProducer;
using HttpProducerHandler = int (HttpSM::*)(int, HttpTunnelProducer *);
using HttpConsumerHandler = int (HttpSM::*)(int, HttpTunnelConsumer *);

enum class HttpTunnelType_t { HTTP_SERVER, HTTP_CLIENT, CACHE_READ, CACHE_WRITE, TRANSFORM, STATIC, BUFFER_READ };

enum class TunnelChunkingAction_t { CHUNK_CONTENT, DECHUNK_CONTENT, PASSTHRU_CHUNKED_CONTENT, PASSTHRU_DECHUNKED_CONTENT };

struct ChunkedHandler {
  enum class ChunkedState {
    READ_CHUNK = 0,
    READ_SIZE_START,
    READ_SIZE,
    READ_SIZE_CRLF,
    READ_TRAILER_BLANK,
    READ_TRAILER_CR,
    READ_TRAILER_LINE,
    READ_ERROR,
    READ_DONE,
    WRITE_CHUNK,
    WRITE_DONE,
    FLOW_CONTROL
  };

  static int const DEFAULT_MAX_CHUNK_SIZE = 4096;

  enum class Action { DOCHUNK = 0, DECHUNK, PASSTHRU, UNSET };

  Action action = Action::UNSET;

  IOBufferReader *chunked_reader   = nullptr;
  MIOBuffer      *dechunked_buffer = nullptr;
  int64_t         dechunked_size   = 0;

  IOBufferReader *dechunked_reader = nullptr;
  MIOBuffer      *chunked_buffer   = nullptr;
  int64_t         chunked_size     = 0;

  /** When passing through chunked content, filter out chunked trailers.
   *
   * @note this is only true when: (1) we are passing through chunked content
   * and (2) we are configured to filter out chunked trailers.
   */
  bool drop_chunked_trailers = false;

  bool strict_chunk_parsing = true;
  bool truncation           = false;

  /** The number of bytes to skip from the reader because they are not body bytes.
   *
   * These skipped bytes are generally header bytes. We copy these in for any
   * internal buffers we'll send to consumers, but skip them when parsing body
   * bytes.
   */
  int64_t skip_bytes = 0;

  ChunkedState state                = ChunkedState::READ_CHUNK;
  int64_t      cur_chunk_size       = 0;
  int64_t      cur_chunk_bytes_left = 0;
  int          last_server_event    = VC_EVENT_NONE;

  // Chunked header size parsing info.
  int  running_sum = 0;
  int  num_digits  = 0;
  int  num_cr      = 0;
  bool prev_is_cr  = false;

  /// @name Output data.
  //@{
  /// The maximum chunk size.
  /// This is the preferred size as well, used whenever possible.
  int64_t max_chunk_size;
  /// Caching members to avoid using printf on every chunk.
  /// It holds the header for a maximal sized chunk which will cover
  /// almost all output chunks.
  char max_chunk_header[16];
  int  max_chunk_header_len = 0;
  //@}
  ChunkedHandler();

  void init(IOBufferReader *buffer_in, HttpTunnelProducer *p, bool drop_chunked_trailers, bool strict_parsing);
  void init_by_action(IOBufferReader *buffer_in, Action action, bool drop_chunked_trailers, bool strict_parsing);
  void clear();

  /// Set the max chunk @a size.
  /// If @a size is zero it is set to @c DEFAULT_MAX_CHUNK_SIZE.
  void set_max_chunk_size(int64_t size);

  /** Consumes and processes chunked content.
   *
   * This consumes data from @a chunked_reader and, if dechunking, writes the
   * dechunked body to @a dechunked_buffer.
   *
   * @return The number of bytes consumed from the chunked reader and true if
   * the entire chunked content is processed, false otherwise.
   */
  std::pair<int64_t, bool> process_chunked_content();

  /** Writes chunked content.
   *
   * This reads from @a dechunked_reader and writes chunked formatted content to
   * @a chunked_buffer.
   *
   * @return The number of bytes consumed from the dechunked reader and true if
   * the entire chunked content is written, false otherwise.
   */
  std::pair<int64_t, bool> generate_chunked_content();

private:
  /** Read a chunk header containing the size of the chunk.
   *
   * @return The number of bytes consumed from the chunked buffer reader.
   */
  int64_t read_size();

  /** Read a chunk body.
   *
   * This is called after read_size so that the chunk size is known.
   *
   * @return The number of bytes consumed from the chunked buffer reader.
   */
  int64_t read_chunk();

  /** Read a chunk trailer.
   *
   * @return The number of bytes consumed from the chunked buffer reader.
   */
  int64_t read_trailer();

  /** Transfer body bytes from the chunked reader.
   *
   * This will either simply consume the chunked body bytes in the case of
   * chunked passthrough, or transfer the chunked body to the dechunked buffer.
   *
   * @return The number of bytes consumed from the chunked buffer reader.
   */
  int64_t transfer_bytes();

  constexpr static std::string_view FINAL_CRLF = "\r\n";
};

struct HttpTunnelConsumer {
  HttpTunnelConsumer();

  LINK(HttpTunnelConsumer, link);
  HttpTunnelProducer *producer      = nullptr;
  HttpTunnelProducer *self_producer = nullptr;

  HttpTunnelType_t    vc_type       = HttpTunnelType_t::HTTP_CLIENT;
  VConnection        *vc            = nullptr;
  IOBufferReader     *buffer_reader = nullptr;
  HttpConsumerHandler vc_handler    = nullptr;
  VIO                *write_vio     = nullptr;

  int64_t skip_bytes    = 0; // bytes to skip at beginning of stream
  int64_t bytes_written = 0; // total bytes written to the vc
  int     handler_state = 0; // state used the handlers

  bool        alive         = false;
  bool        write_success = false;
  const char *name          = nullptr;

  /** Check if this consumer is downstream from @a vc.
      @return @c true if any producer in the tunnel eventually feeds
      data to this consumer.
  */
  bool is_downstream_from(VConnection *vc);
  /** Check if this is a sink (final data destination).
      @return @c true if data exits the ATS process at this consumer.
  */
  bool is_sink() const;
};

struct HttpTunnelProducer {
  HttpTunnelProducer();

  DLL<HttpTunnelConsumer> consumer_list;
  HttpTunnelConsumer     *self_consumer = nullptr;
  VConnection            *vc            = nullptr;
  HttpProducerHandler     vc_handler    = nullptr;
  VIO                    *read_vio      = nullptr;
  MIOBuffer              *read_buffer   = nullptr;
  IOBufferReader         *buffer_start  = nullptr;
  HttpTunnelType_t        vc_type       = HttpTunnelType_t::HTTP_SERVER;

  ChunkedHandler         chunked_handler;
  TunnelChunkingAction_t chunking_action = TunnelChunkingAction_t::PASSTHRU_DECHUNKED_CONTENT;

  bool do_chunking         = false;
  bool do_dechunking       = false;
  bool do_chunked_passthru = false;

  /** The number of bytes available in the reader at the start of the tunnel.
   *
   * @note In the case of pipelined requests, not all these bytes should be used.
   */
  int64_t init_bytes_done = 0;

  /** The total number of bytes read from the reader, including any @a skip_bytes.
   *
   * In straightforward cases where @a total_bytes is specified (non-INT64_MAX),
   * these should wind up being the same as @a total_bytes. For unspecified,
   * generally chunked content, this will be the number of bytes actually
   * consumed from the reader.
   *
   * @note that in the case of pipelined requests, this may be less than @a
   * init_bytes_done because some of those bytes might be for a future request
   * rather than for this body/tunnel.
   */
  int64_t bytes_consumed = 0;

  /** The total number of bytes to be transferred through the tunnel.
   *
   * This will include any bytes skipped at the start of the tunnel.
   *
   * @note This is set by the creator of the tunnel and in the simple case the
   * value is precisely known via a Content-Length header value. However, a user
   * may set this to INT64_MAX or any negative value to indicate that the total
   * is unknown at the start of the tunnel (such as is the case with chunked
   * encoded content).
   */
  int64_t total_bytes = 0;

  /** The number of bytes still to read after @a init_bytes_done to reach @a
   * total_bytes.
   *
   * A value of zero indicates that all the required bytes have already been
   * read off the socket. @a ntodo will be used to indicate how much more we
   * have to read.
   */
  int64_t ntodo = 0;

  /** The number of bytes read from the vc since the start of the tunnel. */
  int64_t bytes_read = 0;

  int handler_state = 0; // state used the handlers
  int last_event    = 0; ///< Tracking for flow control restarts.

  int num_consumers = 0;

  bool alive        = false;
  bool read_success = false;
  /// Flag and pointer for active flow control throttling.
  /// If this is set, it points at the source producer that is under flow control.
  /// If @c NULL then data flow is not being throttled.
  HttpTunnelProducer *flow_control_source = nullptr;
  const char         *name                = nullptr;

  /** Get the largest number of bytes any consumer has not consumed.
      Use @a limit if you only need to check if the backlog is at least @a limit.
      @return The actual backlog or a number at least @a limit.
   */
  uint64_t backlog(uint64_t limit = UINT64_MAX ///< More than this is irrelevant
  );
  /** Indicate whether this producer is handling some kind of chunked content.
   *
   * @return True if this producer is handling chunked content, false
   * otherwise.
   */
  bool is_handling_chunked_content() const;
  /// Check if producer is original (to ATS) source of data.
  /// @return @c true if this producer is the source of bytes from outside ATS.
  bool is_source() const;
  /// Throttle the flow.
  void throttle();
  /// Unthrottle the flow.
  void unthrottle();
  /// Check throttled state.
  bool is_throttled() const;

  /// Update the handler_state member if it is still 0
  void update_state_if_not_set(int new_handler_state);

  /** Set the flow control source producer for the flow.
      This sets the value for this producer and all downstream producers.
      @note This is the implementation for @c throttle and @c unthrottle.
      @see throttle
      @see unthrottle
  */
  void set_throttle_src(HttpTunnelProducer *srcp ///< Source producer of flow.
  );
};

class HttpTunnel : public Continuation
{
  /** Data for implementing flow control across a tunnel.

      The goal is to bound the amount of data buffered for a
      transaction flowing through the tunnel to (roughly) between the
      @a high_water and @a low_water water marks. Due to the chunky nater of data
      flow this always approximate.
  */
  struct FlowControl {
    // Default value for high and low water marks.
    static uint64_t const DEFAULT_WATER_MARK = 1 << 16;

    uint64_t high_water;        ///< Buffered data limit - throttle if more than this.
    uint64_t low_water;         ///< Unthrottle if less than this buffered.
    bool     enabled_p = false; ///< Flow control state (@c false means disabled).

    /// Default constructor.
    FlowControl();
  };

public:
  HttpTunnel();

  void init(HttpSM *sm_arg, Ptr<ProxyMutex> &amutex);
  void reset();
  void abort_tunnel();
  void kill_tunnel();

  bool is_tunnel_active() const;
  bool is_tunnel_alive() const;
  bool has_cache_writer() const;
  bool has_consumer_besides_client() const;

  // CAVEAT: This is different from the HttpTunnel::active flag
  void mark_tls_tunnel_active();
  void mark_tls_tunnel_inactive();

  HttpTunnelProducer *add_producer(VConnection *vc, int64_t nbytes, IOBufferReader *reader_start, HttpProducerHandler sm_handler,
                                   HttpTunnelType_t vc_type, const char *name);

  /// A named variable for the @a drop_chunked_trailers parameter to @a set_producer_chunking_action.
  static constexpr bool DROP_CHUNKED_TRAILERS = true;
  static constexpr bool PARSE_CHUNK_STRICTLY  = true;

  /** Designate chunking behavior to the producer.
   *
   * @param[in] producer The producer being configured.
   * @param[in] skip_bytes The number of bytes to consume off the stream before
   * any chunked data is encountered. These are generally header bytes, if any.
   * @param[in] action The chunking behavior to enact on incoming bytes.
   * @param[in] drop_chunked_trailers If @c true, chunked trailers are filtered
   *   out. Logically speaking, this is only applicable when proxying chunked
   *   content, thus only when @a action is @c TunnelChunkingAction_t::PASSTHRU_CHUNKED_CONTENT.
   * @param[in] parse_chunk_strictly If @c true, no parse error will be allowed
   */
  void set_producer_chunking_action(HttpTunnelProducer *p, int64_t skip_bytes, TunnelChunkingAction_t action,
                                    bool drop_chunked_trailers, bool parse_chunk_strictly);
  /// Set the maximum (preferred) chunk @a size of chunked output for @a producer.
  void set_producer_chunking_size(HttpTunnelProducer *producer, int64_t size);

  HttpTunnelConsumer *add_consumer(VConnection *vc, VConnection *producer, HttpConsumerHandler sm_handler, HttpTunnelType_t vc_type,
                                   const char *name, int64_t skip_bytes = 0);

  int                      deallocate_buffers();
  DLL<HttpTunnelConsumer> *get_consumers(VConnection *vc);
  HttpTunnelProducer      *get_producer(VConnection *vc);
  HttpTunnelConsumer      *get_consumer(VConnection *vc);
  HttpTunnelProducer      *get_producer(HttpTunnelType_t type);
  void                     tunnel_run(HttpTunnelProducer *p = nullptr);

  int     main_handler(int event, void *data);
  void    consumer_reenable(HttpTunnelConsumer *c);
  bool    consumer_handler(int event, HttpTunnelConsumer *c);
  bool    producer_handler(int event, HttpTunnelProducer *p);
  int     producer_handler_dechunked(int event, HttpTunnelProducer *p);
  int     producer_handler_chunked(int event, HttpTunnelProducer *p);
  void    local_finish_all(HttpTunnelProducer *p);
  void    chain_finish_all(HttpTunnelProducer *p);
  void    chain_abort_cache_write(HttpTunnelProducer *p);
  void    chain_abort_all(HttpTunnelProducer *p);
  void    abort_cache_write_finish_others(HttpTunnelProducer *p);
  void    append_message_to_producer_buffer(HttpTunnelProducer *p, const char *msg, int64_t msg_len);
  int64_t final_consumer_bytes_to_write(HttpTunnelProducer *p, HttpTunnelConsumer *c);

  /** Mark a producer and consumer as the same underlying object.

      This is use to chain producer/consumer pairs together to
      indicate the data flows through them sequentially. The primary
      example is a transform which serves as a consumer on the server
      side and a producer on the cache/client side.
  */
  void chain(HttpTunnelConsumer *c, ///< Flow goes in here
             HttpTunnelProducer *p  ///< Flow comes back out here
  );

  void close_vc(HttpTunnelProducer *p);
  void close_vc(HttpTunnelConsumer *c);

private:
  void internal_error();
  void finish_all_internal(HttpTunnelProducer *p, bool chain);
  void update_stats_after_abort(HttpTunnelType_t t);
  void producer_run(HttpTunnelProducer *p);
  void _schedule_tls_tunnel_activity_check_event();
  bool _is_tls_tunnel_active() const;

  HttpTunnelProducer *get_producer(VIO *vio);
  HttpTunnelConsumer *get_consumer(VIO *vio);

  HttpTunnelProducer *alloc_producer();
  HttpTunnelConsumer *alloc_consumer();

  int                num_producers = 0;
  int                num_consumers = 0;
  HttpTunnelConsumer consumers[MAX_CONSUMERS];
  HttpTunnelProducer producers[MAX_PRODUCERS];
  HttpSM            *sm = nullptr;

  bool active = false;

  // Activity check for SNI Routing Tunnel
  bool       _tls_tunnel_active               = false;
  Event     *_tls_tunnel_activity_check_event = nullptr;
  ink_hrtime _tls_tunnel_last_update          = 0;

  /// State data about flow control.
  FlowControl flow_state;

private:
  int  reentrancy_count = 0;
  bool call_sm          = false;

  /// Corresponds to proxy.config.http.drop_chunked_trailers having a value of 1.
  bool http_drop_chunked_trailers = false;

  /// Corresponds to proxy.config.http.strict_chunk_parsing having a value of 1.
  bool http_strict_chunk_parsing = false;

  /** The number of body bytes processed in this last execution of the tunnel.
   *
   * This accounting is used to determine how many bytes to copy into the body
   * buffer via HttpSM::postbuf_copy_partial_data.
   */
  int64_t body_bytes_to_copy = 0;

  /** The cumulative number of bytes that all calls to
   * HttpSM::post_copy_partial_data have copied.
   *
   * This is recorded so we don't copy more bytes than the creator of the tunnel
   * told us to via nbytes.
   */
  int64_t body_bytes_copied = 0;
};

////
// Inline Functions
//
inline bool
HttpTunnel::is_tunnel_active() const
{
  return active;
}

// void HttpTunnel::abort_cache_write_finish_others
//
//    Abort all downstream cache writes and finsish
//      all other local consumers
//
inline void
HttpTunnel::abort_cache_write_finish_others(HttpTunnelProducer *p)
{
  chain_abort_cache_write(p);
  local_finish_all(p);
}

// void HttpTunnel::local_finish_all(HttpTunnelProducer* p)
//
//   After the producer has finished, causes direct consumers
//      to finish their writes
//
inline void
HttpTunnel::local_finish_all(HttpTunnelProducer *p)
{
  finish_all_internal(p, false);
}

// void HttpTunnel::chain_finish_all(HttpTunnelProducer* p)
//
//   After the producer has finished, cause everyone
//    downstream in the tunnel to send everything
//    that producer has placed in the buffer
//
inline void
HttpTunnel::chain_finish_all(HttpTunnelProducer *p)
{
  finish_all_internal(p, true);
}

inline bool
HttpTunnel::is_tunnel_alive() const
{
  bool tunnel_alive = false;

  for (const auto &producer : producers) {
    if (producer.alive == true) {
      tunnel_alive = true;
      break;
    }
  }
  if (!tunnel_alive) {
    for (const auto &consumer : consumers) {
      if (consumer.alive == true) {
        tunnel_alive = true;
        break;
      }
    }
  }

  return tunnel_alive;
}

inline HttpTunnelProducer *
HttpTunnel::get_producer(VConnection *vc)
{
  for (int i = 0; i < MAX_PRODUCERS; i++) {
    if (producers[i].vc == vc) {
      return producers + i;
    }
  }
  return nullptr;
}

inline HttpTunnelProducer *
HttpTunnel::get_producer(HttpTunnelType_t type)
{
  for (int i = 0; i < MAX_PRODUCERS; i++) {
    if (producers[i].vc_type == type) {
      return producers + i;
    }
  }
  return nullptr;
}

inline HttpTunnelConsumer *
HttpTunnel::get_consumer(VConnection *vc)
{
  /** Rare but persistent problem in which a @c INKVConnInternal is used by a consumer, released,
      and then re-allocated for a different consumer. This causes two consumers to have the same VC
      pointer resulting in this method returning the wrong consumer. Note this is a not a bad use of
      the tunnel, but an unfortunate interaction with the FIFO free lists.

      It's not correct to check for the consumer being alive - at a minimum `HTTP_TUNNEL_EVENT_DONE`
      is dispatched against a consumer after the consumer is not alive. Instead if a non-alive
      consumer matches it is stored as a candidate and returned if no other match is found. If a
      live matching consumer is found, it is immediately returned. It is never valid to have the
      same VC in more than one active consumer. This should avoid a performance impact because in
      the usual case the consumer will be alive.

      In the case of a deliberate dispatch of an event to a dead consumer that has a duplicate vc
      address, this will select the last consumer which will be correct as the consumers are added
      in order therefore the latter consumer will be the most recent / appropriate target.
  */
  HttpTunnelConsumer *zret = nullptr;
  for (HttpTunnelConsumer &c : consumers) {
    if (c.vc == vc) {
      zret = &c;
      if (c.alive) { // a match that's alive is always the best.
        break;
      }
    }
  }
  return zret;
}

inline HttpTunnelProducer *
HttpTunnel::get_producer(VIO *vio)
{
  for (int i = 0; i < MAX_PRODUCERS; i++) {
    if (producers[i].read_vio == vio) {
      return producers + i;
    }
  }
  return nullptr;
}

inline HttpTunnelConsumer *
HttpTunnel::get_consumer(VIO *vio)
{
  if (vio) {
    for (int i = 0; i < MAX_CONSUMERS; i++) {
      if (consumers[i].alive && consumers[i].write_vio == vio) {
        return consumers + i;
      }
    }
  }
  return nullptr;
}

inline void
HttpTunnel::append_message_to_producer_buffer(HttpTunnelProducer *p, const char *msg, int64_t msg_len)
{
  if (p == nullptr || p->read_buffer == nullptr) {
    return;
  }

  p->read_buffer->write(msg, msg_len);
  p->total_bytes += msg_len;
  p->bytes_read  += msg_len;
}

inline bool
HttpTunnel::has_cache_writer() const
{
  for (const auto &consumer : consumers) {
    if (consumer.vc_type == HttpTunnelType_t::CACHE_WRITE && consumer.vc != nullptr) {
      return true;
    }
  }
  return false;
}

/**
   Return false if there is only a consumer for client
 */
inline bool
HttpTunnel::has_consumer_besides_client() const
{
  bool res = false; // case of no consumers

  for (const auto &consumer : consumers) {
    if (!consumer.alive) {
      continue;
    }

    switch (consumer.vc_type) {
    case HttpTunnelType_t::HTTP_CLIENT:
      continue;
    case HttpTunnelType_t::HTTP_SERVER:
      // ignore uploading data to servers
      continue;
    default:
      return true;
    }
  }

  return res;
}

inline bool
HttpTunnelConsumer::is_downstream_from(VConnection *vc)
{
  HttpTunnelProducer *p = producer;

  while (p) {
    if (p->vc == vc) {
      return true;
    }
    // The producer / consumer chain can contain a cycle in the case
    // of a blind tunnel so give up if we find ourself (the original
    // consumer).
    HttpTunnelConsumer *c = p->self_consumer;

    p = (c && c != this) ? c->producer : nullptr;
  }
  return false;
}

inline bool
HttpTunnelConsumer::is_sink() const
{
  return HttpTunnelType_t::HTTP_CLIENT == vc_type || HttpTunnelType_t::CACHE_WRITE == vc_type;
}

inline bool
HttpTunnelProducer::is_handling_chunked_content() const
{
  return do_chunking || do_dechunking || do_chunked_passthru;
}

inline bool
HttpTunnelProducer::is_source() const
{
  // If a producer is marked as a client, then it's part of a bidirectional tunnel
  // and so is an actual source of data.
  return HttpTunnelType_t::HTTP_SERVER == vc_type || HttpTunnelType_t::CACHE_READ == vc_type ||
         HttpTunnelType_t::HTTP_CLIENT == vc_type;
}

inline void
HttpTunnelProducer::update_state_if_not_set(int new_handler_state)
{
  if (this->handler_state == 0) {
    this->handler_state = new_handler_state;
  }
}

inline bool
HttpTunnelProducer::is_throttled() const
{
  return nullptr != flow_control_source;
}

inline void
HttpTunnelProducer::throttle()
{
  if (!this->is_throttled()) {
    this->set_throttle_src(this);
  }
}

inline void
HttpTunnelProducer::unthrottle()
{
  if (this->is_throttled()) {
    this->set_throttle_src(nullptr);
  }
}

inline HttpTunnel::FlowControl::FlowControl() : high_water(DEFAULT_WATER_MARK), low_water(DEFAULT_WATER_MARK) {}
