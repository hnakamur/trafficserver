/** @file

  This file implements the LogConfig object.

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

#include "tscore/ink_platform.h"
#include "tscore/Layout.h"
#include "iocore/utils/Machine.h"

#include <memory>

using namespace std::literals;

#include "tscore/ink_platform.h"
#include "tscore/ink_file.h"

#include "tscore/Filenames.h"
#include "tscore/List.h"
#include "tscore/LogMessage.h"

#include "proxy/logging/Log.h"
#include "proxy/logging/LogField.h"
#include "proxy/logging/LogFilter.h"
#include "proxy/logging/LogFormat.h"
#include "proxy/logging/LogFile.h"
#include "proxy/logging/LogBuffer.h"
#include "proxy/logging/LogObject.h"
#include "proxy/logging/LogConfig.h"
#include "proxy/logging/LogUtils.h"
#include "tscore/SimpleTokenizer.h"

#include "proxy/logging/YamlLogConfig.h"

#define DISK_IS_CONFIG_FULL_MESSAGE                    \
  "Access logging to local log directory suspended - " \
  "configured space allocation exhausted."
#define DISK_IS_ACTUAL_FULL_MESSAGE                    \
  "Access logging to local log directory suspended - " \
  "no more space on the logging partition."
#define DISK_IS_CONFIG_LOW_MESSAGE                     \
  "Access logging to local log directory suspended - " \
  "configured space allocation almost exhausted."
#define DISK_IS_ACTUAL_LOW_MESSAGE "Access logging to local log directory suspended - partition space is low."

#define PARTITION_HEADROOM_MB 10
#define DIAGS_LOG_FILENAME    "diags.log"
#define MANAGER_LOG_FILENAME  "manager.log"

namespace
{
DbgCtl dbg_ctl_logspace{"logspace"};
DbgCtl dbg_ctl_log{"log"};
DbgCtl dbg_ctl_log_config{"log-config"};

} // end anonymous namespace

void
LogConfig::reconfigure_mgmt_variables(swoc::MemSpan<void>)
{
  Note("received log reconfiguration event, rolling now");
  Log::config->roll_log_files_now = true;
}

void
LogConfig::register_rolled_log_auto_delete(std::string_view logname, int rolling_min_count)
{
  if (!auto_delete_rolled_files) {
    // Nothing to do if auto-deletion is not configured.
    return;
  }

  Dbg(dbg_ctl_logspace, "Registering rotated log deletion for %s with min roll count %d", std::string(logname).c_str(),
      rolling_min_count);
  rolledLogDeleter.register_log_type_for_deletion(logname, rolling_min_count);
}

void
LogConfig::read_configuration_variables()
{
  int val;

  val = RecGetRecordInt("proxy.config.log.log_buffer_size").value_or(0);
  if (val > 0) {
    log_buffer_size = val;
  }

  val = RecGetRecordInt("proxy.config.log.log_fast_buffer").value_or(0);
  if (val > 0) {
    log_fast_buffer = true;
  }

  val = RecGetRecordInt("proxy.config.log.max_secs_per_buffer").value_or(0);
  if (val > 0) {
    max_secs_per_buffer = val;
  }

  val = RecGetRecordInt("proxy.config.log.max_space_mb_for_logs").value_or(0);
  if (val > 0) {
    max_space_mb_for_logs = val;
  }

  val = RecGetRecordInt("proxy.config.log.max_space_mb_headroom").value_or(0);
  if (val > 0) {
    max_space_mb_headroom = val;
  }

  val = RecGetRecordInt("proxy.config.log.io.max_buffer_index").value_or(0);
  if (val > 0) {
    logbuffer_max_iobuf_index = val;
  }

  {
    auto str{RecGetRecordStringAlloc("proxy.config.log.logfile_perm")};
    if (auto logfile_perm_parsed{ink_fileperm_parse(ats_as_c_str(str))}; logfile_perm_parsed != -1) {
      logfile_perm = logfile_perm_parsed;
    }
  }

  if (auto str{RecGetRecordStringAlloc("proxy.config.log.hostname")}; str && !str.value().empty() && str.value() != "localhost"sv) {
    ats_free(hostname);
    hostname = ats_stringdup(str);
  }

  if (auto str{RecGetRecordStringAlloc("proxy.config.error.logfile.filename")}; str && !str.value().empty()) {
    ats_free(error_log_filename);
    error_log_filename = ats_stringdup(str);
  }

  ats_free(logfile_dir);
  logfile_dir = ats_stringdup(RecConfigReadLogDir());

  if (access(logfile_dir, R_OK | W_OK | X_OK) == -1) {
    // Try 'system_root_dir/var/log/trafficserver' directory
    fprintf(stderr, "unable to access log directory '%s': %d, %s\n", logfile_dir, errno, strerror(errno));
    fprintf(stderr, "please set 'proxy.config.log.logfile_dir'\n");
    ::exit(1);
  }

  val = RecGetRecordInt("proxy.config.log.preproc_threads").value_or(0);
  if (val > 0 && val <= 128) {
    preproc_threads = val;
  }

  // ROLLING

  // we don't check for valid values of rolling_enabled, rolling_interval_sec,
  // rolling_offset_hr, or rolling_size_mb because the LogObject takes care of this
  //
  rolling_interval_sec = RecGetRecordInt("proxy.config.log.rolling_interval_sec").value_or(0);
  rolling_offset_hr    = RecGetRecordInt("proxy.config.log.rolling_offset_hr").value_or(0);
  rolling_size_mb      = RecGetRecordInt("proxy.config.log.rolling_size_mb").value_or(0);
  rolling_min_count    = RecGetRecordInt("proxy.config.log.rolling_min_count").value_or(0);
  val                  = RecGetRecordInt("proxy.config.log.rolling_enabled").value_or(0);
  if (LogRollingEnabledIsValid(val)) {
    rolling_enabled = static_cast<Log::RollingEnabledValues>(val);
  } else {
    Warning("invalid value '%d' for '%s', disabling log rolling", val, "proxy.config.log.rolling_enabled");
    rolling_enabled = Log::NO_ROLLING;
  }

  val                      = RecGetRecordInt("proxy.config.log.auto_delete_rolled_files").value_or(0);
  auto_delete_rolled_files = (val > 0);

  val                 = RecGetRecordInt("proxy.config.log.rolling_allow_empty").value_or(0);
  rolling_allow_empty = (val > 0);

  // THROTTLING
  val = RecGetRecordInt("proxy.config.log.throttling_interval_msec").value_or(0);
  if (LogThrottlingIsValid(val)) {
    LogMessage::set_default_log_throttling_interval(std::chrono::milliseconds{val});
  } else {
    Warning("invalid value '%d' for '%s', disabling log rolling", val, "proxy.config.log.throttling_interval_msec");
  }
  val = RecGetRecordInt("proxy.config.diags.debug.throttling_interval_msec").value_or(0);
  if (LogThrottlingIsValid(val)) {
    LogMessage::set_default_debug_throttling_interval(std::chrono::milliseconds{val});
  } else {
    Warning("invalid value '%d' for '%s', disabling log rolling", val, "proxy.config.diags.debug.throttling_interval_msec");
  }

  // Read in min_count control values for auto deletion
  if (auto_delete_rolled_files) {
    // The majority of register_rolled_log_auto_delete() updates come in
    // through LogObject. However, not all ATS logs are managed by LogObject.
    // The following register these other core logs for log rotation deletion.

    // For diagnostic logs
    val = RecGetRecordInt("proxy.config.diags.logfile.rolling_min_count").value_or(0);
    register_rolled_log_auto_delete(DIAGS_LOG_FILENAME, val);
    register_rolled_log_auto_delete(MANAGER_LOG_FILENAME, val);

    // For traffic.out
    auto configured_name{RecGetRecordStringAlloc("proxy.config.output.logfile.name")};
    auto traffic_logname{configured_name && !configured_name.value().empty() ? configured_name.value() : "traffic.out"sv};
    val = static_cast<int>(RecGetRecordInt("proxy.config.output.logfile.rolling_min_count").value_or(0));
    register_rolled_log_auto_delete(traffic_logname, val);

    rolling_max_count = RecGetRecordInt("proxy.config.log.rolling_max_count").value_or(0);
  }
  // PERFORMANCE
  val = RecGetRecordInt("proxy.config.log.sampling_frequency").value_or(0);
  if (val > 0) {
    sampling_frequency = val;
  }

  val = RecGetRecordInt("proxy.config.log.file_stat_frequency").value_or(0);
  if (val > 0) {
    file_stat_frequency = val;
  }

  val = RecGetRecordInt("proxy.config.log.space_used_frequency").value_or(0);
  if (val > 0) {
    space_used_frequency = val;
  }

  // ASCII BUFFER
  val = RecGetRecordInt("proxy.config.log.ascii_buffer_size").value_or(0);
  if (val > 0) {
    ascii_buffer_size = val;
  }

  val = RecGetRecordInt("proxy.config.log.max_line_size").value_or(0);
  if (val > 0) {
    max_line_size = val;
  }
}

/*-------------------------------------------------------------------------
  LogConfig::LogConfig

  Read the logging configuration variables from the config file and
  initialize the LogConfig member variables.  Assign some meaningful
  default value if we get garbage back from the config file.
  -------------------------------------------------------------------------*/

// TODO: Is UINT_MAX here really correct?
LogConfig::LogConfig() : m_partition_space_left(static_cast<int64_t>(UINT_MAX))
{
  // Setup the default values for all LogConfig public variables so that
  // a LogConfig object is valid upon return from the constructor even
  // if no configuration file is read
  hostname           = ats_strdup(Machine::instance()->host_name.c_str());
  error_log_filename = ats_strdup("error.log");
  logfile_dir        = ats_strdup(".");
}

/*-------------------------------------------------------------------------
  LogConfig::~LogConfig

  Delete all config variable strings.
  -------------------------------------------------------------------------*/

LogConfig::~LogConfig()
{
  ats_free(hostname);
  ats_free(error_log_filename);
  ats_free(logfile_dir);
}

/*-------------------------------------------------------------------------
  LogConfig::init
  -------------------------------------------------------------------------*/

void
LogConfig::init(LogConfig *prev_config)
{
  LogObject *errlog = nullptr;

  ink_assert(!initialized);

  update_space_used();

  // create log objects
  //
  if (Log::transaction_logging_enabled()) {
    setup_log_objects();
  }

  // ----------------------------------------------------------------------
  // Construct a new error log object candidate.
  if (Log::error_logging_enabled()) {
    std::unique_ptr<LogFormat> fmt(MakeTextLogFormat("error"));

    Dbg(dbg_ctl_log, "creating predefined error log object");

    errlog = new LogObject(this, fmt.get(), logfile_dir, error_log_filename, LOG_FILE_ASCII, nullptr, rolling_enabled,
                           preproc_threads, rolling_interval_sec, rolling_offset_hr, rolling_size_mb, /* auto_created */ false,
                           rolling_max_count, rolling_min_count);

    log_object_manager.manage_object(errlog);
    errlog->set_fmt_timestamps();
  } else {
    Log::error_log = nullptr;
  }

  if (prev_config) {
    // Transfer objects from previous configuration.
    transfer_objects(prev_config);

    // After transferring objects, we are going to keep either the new error log or the old one. Figure out
    // which one we are keeping and make that the global ...
    if (Log::error_log) {
      errlog = this->log_object_manager.find_by_format_name(Log::error_log->m_format->name());
    }
  }

  ink_atomic_swap(&Log::error_log, errlog);

  initialized = true;
}

/*-------------------------------------------------------------------------
  LogConfig::display

  Dump the values for the current LogConfig object.
  -------------------------------------------------------------------------*/

void
LogConfig::display(FILE *fd)
{
  fprintf(fd, "-----------------------------\n");
  fprintf(fd, "--- Logging Configuration ---\n");
  fprintf(fd, "-----------------------------\n");
  fprintf(fd, "Config variables:\n");
  fprintf(fd, "   log_buffer_size = %d\n", log_buffer_size);
  fprintf(fd, "   max_secs_per_buffer = %d\n", max_secs_per_buffer);
  fprintf(fd, "   max_space_mb_for_logs = %d\n", max_space_mb_for_logs);
  fprintf(fd, "   max_space_mb_headroom = %d\n", max_space_mb_headroom);
  fprintf(fd, "   hostname = %s\n", hostname);
  fprintf(fd, "   logfile_dir = %s\n", logfile_dir);
  fprintf(fd, "   logfile_perm = 0%o\n", logfile_perm);
  fprintf(fd, "   error_log_filename = %s\n", error_log_filename);

  fprintf(fd, "   preproc_threads = %d\n", preproc_threads);
  fprintf(fd, "   rolling_enabled = %d\n", rolling_enabled);
  fprintf(fd, "   rolling_interval_sec = %d\n", rolling_interval_sec);
  fprintf(fd, "   rolling_offset_hr = %d\n", rolling_offset_hr);
  fprintf(fd, "   rolling_size_mb = %d\n", rolling_size_mb);
  fprintf(fd, "   rolling_min_count = %d\n", rolling_min_count);
  fprintf(fd, "   rolling_max_count = %d\n", rolling_max_count);
  fprintf(fd, "   rolling_allow_empty = %d\n", rolling_allow_empty);
  fprintf(fd, "   auto_delete_rolled_files = %d\n", auto_delete_rolled_files);
  fprintf(fd, "   sampling_frequency = %d\n", sampling_frequency);
  fprintf(fd, "   file_stat_frequency = %d\n", file_stat_frequency);
  fprintf(fd, "   space_used_frequency = %d\n", space_used_frequency);
  fprintf(fd, "   logbuffer_max_iobuf_index = %d\n", logbuffer_max_iobuf_index);

  fprintf(fd, "\n");
  fprintf(fd, "************ Log Objects (%u objects) ************\n", log_object_manager.get_num_objects());
  log_object_manager.display(fd);

  fprintf(fd, "************ Filter List (%u filters) ************\n", filter_list.count());
  filter_list.display(fd);

  fprintf(fd, "************ Format List (%u formats) ************\n", format_list.count());
  format_list.display(fd);
}

//-----------------------------------------------------------------------------
// setup_log_objects
//
// Construct: All custom objects.
//
// Upon return from this function:
// - global_object_list has the aforementioned objects
// - global_filter_list has all custom filters
//
void
LogConfig::setup_log_objects()
{
  Dbg(dbg_ctl_log, "creating objects...");

  filter_list.clear();

  // Evaluate logging.yaml to construct the custom log objects.
  evaluate_config();

  // Open local pipes so readers can see them.
  log_object_manager.open_local_pipes();

  if (dbg_ctl_log.on()) {
    log_object_manager.display();
  }
}

/*-------------------------------------------------------------------------
  LogConfig::reconfigure

  This is the manager callback for any logging config variable change.
  Since we want to access the config variables to build a new config
  object, but can't from this function (big lock technology in the
  manager), we'll just set a flag and call the real reconfiguration
  function from the logging thread.
  -------------------------------------------------------------------------*/

int
LogConfig::reconfigure(const char * /* name ATS_UNUSED */, RecDataT /* data_type ATS_UNUSED */, RecData /* data ATS_UNUSED */,
                       void * /* cookie ATS_UNUSED */)
{
  Dbg(dbg_ctl_log_config, "Reconfiguration request accepted");
  Log::config->reconfiguration_needed = true;
  return 0;
}

/*-------------------------------------------------------------------------
  LogConfig::register_config_callbacks

  This static function is called by Log::init to register the config update
  function for each of the logging configuration variables.
  -------------------------------------------------------------------------*/

void
LogConfig::register_config_callbacks()
{
  static const char *names[] = {
    "proxy.config.log.log_buffer_size",
    "proxy.config.log.max_secs_per_buffer",
    "proxy.config.log.max_space_mb_for_logs",
    "proxy.config.log.max_space_mb_headroom",
    "proxy.config.log.error_log_filename",
    "proxy.config.log.logfile_perm",
    "proxy.config.log.hostname",
    "proxy.config.log.logfile_dir",
    "proxy.config.log.rolling_enabled",
    "proxy.config.log.rolling_interval_sec",
    "proxy.config.log.rolling_offset_hr",
    "proxy.config.log.rolling_size_mb",
    "proxy.config.log.auto_delete_rolled_files",
    "proxy.config.log.rolling_max_count",
    "proxy.config.log.rolling_allow_empty",
    "proxy.config.log.config.filename",
    "proxy.config.log.sampling_frequency",
    "proxy.config.log.file_stat_frequency",
    "proxy.config.log.space_used_frequency",
    "proxy.config.log.io.max_buffer_index",
    "proxy.config.log.throttling_interval_msec",
    "proxy.config.diags.debug.throttling_interval_msec",
  };

  for (unsigned i = 0; i < countof(names); ++i) {
    RecRegisterConfigUpdateCb(names[i], &LogConfig::reconfigure, nullptr);
  }
}

/*-------------------------------------------------------------------------
  LogConfig::register_stat_callbacks

  This static function is called by Log::init to register the stat update
  function for each of the logging stats variables.
  -------------------------------------------------------------------------*/

void
LogConfig::register_stat_callbacks()
{
  //
  // events
  //
  log_rsb.event_log_error_skip              = Metrics::Counter::createPtr("proxy.process.log.event_log_error_skip");
  log_rsb.event_log_error_ok                = Metrics::Counter::createPtr("proxy.process.log.event_log_error_ok");
  log_rsb.event_log_error_aggr              = Metrics::Counter::createPtr("proxy.process.log.event_log_error_aggr");
  log_rsb.event_log_error_full              = Metrics::Counter::createPtr("proxy.process.log.event_log_error_full");
  log_rsb.event_log_error_fail              = Metrics::Counter::createPtr("proxy.process.log.event_log_error_fail");
  log_rsb.event_log_access_ok               = Metrics::Counter::createPtr("proxy.process.log.event_log_access_ok");
  log_rsb.event_log_access_skip             = Metrics::Counter::createPtr("proxy.process.log.event_log_access_skip");
  log_rsb.event_log_access_aggr             = Metrics::Counter::createPtr("proxy.process.log.event_log_access_aggr");
  log_rsb.event_log_access_full             = Metrics::Counter::createPtr("proxy.process.log.event_log_access_full");
  log_rsb.event_log_access_fail             = Metrics::Counter::createPtr("proxy.process.log.event_log_access_fail");
  log_rsb.num_sent_to_network               = Metrics::Counter::createPtr("proxy.process.log.num_sent_to_network");
  log_rsb.num_lost_before_sent_to_network   = Metrics::Counter::createPtr("proxy.process.log.num_lost_before_sent_to_network");
  log_rsb.num_received_from_network         = Metrics::Counter::createPtr("proxy.process.log.num_received_from_network");
  log_rsb.num_flush_to_disk                 = Metrics::Counter::createPtr("proxy.process.log.num_flush_to_disk");
  log_rsb.num_lost_before_flush_to_disk     = Metrics::Counter::createPtr("proxy.process.log.num_lost_before_flush_to_disk");
  log_rsb.bytes_lost_before_preproc         = Metrics::Counter::createPtr("proxy.process.log.bytes_lost_before_preproc");
  log_rsb.bytes_sent_to_network             = Metrics::Counter::createPtr("proxy.process.log.bytes_sent_to_network");
  log_rsb.bytes_lost_before_sent_to_network = Metrics::Counter::createPtr("proxy.process.log.bytes_lost_before_sent_to_network");
  log_rsb.bytes_received_from_network       = Metrics::Counter::createPtr("proxy.process.log.bytes_received_from_network");
  log_rsb.bytes_flush_to_disk               = Metrics::Counter::createPtr("proxy.process.log.bytes_flush_to_disk");
  log_rsb.bytes_lost_before_flush_to_disk   = Metrics::Counter::createPtr("proxy.process.log.bytes_lost_before_flush_to_disk");
  log_rsb.bytes_written_to_disk             = Metrics::Counter::createPtr("proxy.process.log.bytes_written_to_disk");
  log_rsb.bytes_lost_before_written_to_disk = Metrics::Counter::createPtr("proxy.process.log.bytes_lost_before_written_to_disk");
  log_rsb.log_files_open                    = Metrics::Gauge::createPtr("proxy.process.log.log_files_open");
  log_rsb.log_files_space_used              = Metrics::Gauge::createPtr("proxy.process.log.log_files_space_used");
}

/*-------------------------------------------------------------------------
  LogConfig::space_to_write

  This function returns true if there is enough disk space to write the
  given number of bytes, false otherwise.
  -------------------------------------------------------------------------*/

bool
LogConfig::space_to_write(int64_t bytes_to_write) const
{
  int64_t config_space, partition_headroom;
  int64_t logical_space_used, physical_space_left;
  bool    space;

  config_space       = static_cast<int64_t>(get_max_space_mb()) * LOG_MEGABYTE;
  partition_headroom = static_cast<int64_t>(PARTITION_HEADROOM_MB) * LOG_MEGABYTE;

  logical_space_used  = m_space_used + bytes_to_write;
  physical_space_left = m_partition_space_left - bytes_to_write;

  space = ((logical_space_used < config_space) && (physical_space_left > partition_headroom));

  Dbg(dbg_ctl_logspace,
      "logical space used %" PRId64 ", configured space %" PRId64 ", physical space left %" PRId64 ", partition headroom %" PRId64
      ", space %s available",
      logical_space_used, config_space, physical_space_left, partition_headroom, space ? "is" : "is not");

  return space;
}

/*-------------------------------------------------------------------------
  LogConfig::update_space_used

  Update the m_space_used variable by reading the logging dir and counting
  the total bytes being occupied by files.  If we've used too much space
  (space_used > max_space - headroom) then start deleting some files (if
  auto_delete_rolled_files is set) to make room. Finally, update the
  space_used stat.

  This routine will only be executed SINGLE-THREADED, either by the main
  thread when a LogConfig is initialized, or by the event thread during the
  periodic space check.
  -------------------------------------------------------------------------*/

void
LogConfig::update_space_used()
{
  // no need to update space used if log directory is inaccessible
  //
  if (m_log_directory_inaccessible) {
    return;
  }

  int64_t        total_space_used, partition_space_left;
  char           path[MAXPATHLEN];
  int            sret;
  struct dirent *entry;
  struct stat    sbuf;
  DIR           *ld;

  // check if logging directory has been specified
  //
  if (!logfile_dir) {
    const char *msg = "Logging directory not specified";
    Error("%s", msg);
    m_log_directory_inaccessible = true;
    return;
  }

  // check if logging directory exists and is searchable readable & writable
  int err;
  do {
    err = access(logfile_dir, R_OK | W_OK | X_OK);
  } while ((err < 0) && (errno == EINTR));

  if (err < 0) {
    const char *msg = "Error accessing logging directory %s: %s.";
    Error(msg, logfile_dir, strerror(errno));
    m_log_directory_inaccessible = true;
    return;
  }

  ld = ::opendir(logfile_dir);
  if (ld == nullptr) {
    const char *msg = "Error opening logging directory %s to perform a space check: %s.";
    Error(msg, logfile_dir, strerror(errno));
    m_log_directory_inaccessible = true;
    return;
  }

  total_space_used = 0LL;

  while ((entry = readdir(ld))) {
    snprintf(path, MAXPATHLEN, "%s/%s", logfile_dir, entry->d_name);

    sret = ::stat(path, &sbuf);
    if (sret != -1 && S_ISREG(sbuf.st_mode)) {
      total_space_used += static_cast<int64_t>(sbuf.st_size);

      if (auto_delete_rolled_files && LogFile::rolled_logfile(entry->d_name)) {
        rolledLogDeleter.consider_for_candidacy(path, sbuf.st_size, sbuf.st_mtime);
      }
    }
  }

  ::closedir(ld);

  //
  // Now check the partition to see if there is enough *actual* space.
  //
  partition_space_left = m_partition_space_left;

  struct statvfs fs;

  if (::statvfs(logfile_dir, &fs) >= 0) {
    partition_space_left = static_cast<int64_t>(fs.f_bavail) * static_cast<int64_t>(fs.f_bsize);
  }

  //
  // Update the config variables for space used/left
  //
  m_space_used           = total_space_used;
  m_partition_space_left = partition_space_left;
  Metrics::Gauge::store(log_rsb.log_files_space_used, m_space_used);

  Dbg(dbg_ctl_logspace, "%" PRId64 " bytes being used for logs", m_space_used);
  Dbg(dbg_ctl_logspace, "%" PRId64 " bytes left on partition", m_partition_space_left);

  //
  // Now that we have an accurate picture of the amount of space being
  // used by logging, we can see if we're running low on space.  If so,
  // we might consider deleting some files that are stored in the
  // candidate array.
  //
  // To delete oldest files first, we'll sort our candidate array by
  // timestamps, making the oldest files first in the array (thus first
  // selected).
  //

  int64_t max_space = static_cast<int64_t>(get_max_space_mb()) * LOG_MEGABYTE;
  int64_t headroom  = static_cast<int64_t>(max_space_mb_headroom) * LOG_MEGABYTE;

  if (!space_to_write(headroom)) {
    Dbg(dbg_ctl_logspace, "headroom reached, trying to clear space ...");
    if (!rolledLogDeleter.has_candidates()) {
      Note("Cannot clear space because there are no recognized Traffic Server rolled logs for auto deletion.");
    } else {
      Dbg(dbg_ctl_logspace, "Considering %zu delete candidates ...", rolledLogDeleter.get_candidate_count());
    }

    while (rolledLogDeleter.has_candidates()) {
      if (space_to_write(headroom + log_buffer_size)) {
        Dbg(dbg_ctl_logspace, "low water mark reached; stop deleting");
        break;
      }

      auto victim = rolledLogDeleter.take_next_candidate_to_delete();
      // Check if any candidate exists
      if (!victim) {
        // This shouldn't be triggered unless min_count are configured wrong or extra non-log files occupy the directory
        Dbg(dbg_ctl_logspace, "No more victims. Check your rolling_min_count settings and logging directory.");
      } else {
        Dbg(dbg_ctl_logspace, "auto-deleting %s", victim->rolled_log_path.c_str());

        if (unlink(victim->rolled_log_path.c_str()) < 0) {
          Note("Traffic Server was unable to auto-delete rolled "
               "logfile %s: %s.",
               victim->rolled_log_path.c_str(), strerror(errno));
        } else {
          Dbg(dbg_ctl_logspace,
              "The rolled logfile, %s, was auto-deleted; "
              "%" PRId64 " bytes were reclaimed.",
              victim->rolled_log_path.c_str(), victim->size);

          // Update after successful unlink;
          m_space_used           -= victim->size;
          m_partition_space_left += victim->size;
        }
      }
    }
  }

  // The set of files in the logs dir may change between iterations to check
  // for logs to delete. To deal with this, we simply clear our internal
  // candidates metadata and regenerate it on each iteration.
  rolledLogDeleter.clear_candidates();

  //
  // Now that we've updated the m_space_used value, see if we need to
  // issue any alarms or warnings about space
  //

  if (!space_to_write(headroom)) {
    if (!logging_space_exhausted) {
      Note("Logging space exhausted, any logs writing to local disk will be dropped!");
    }

    logging_space_exhausted = true;
    //
    // Despite our best efforts, we still can't write to the disk.
    // Find out why and set/clear warnings.
    //
    // First, are we out of space based on configuration?
    //
    if (m_space_used >= max_space) {
      if (!m_disk_full) {
        m_disk_full = true;
        Warning(DISK_IS_CONFIG_FULL_MESSAGE);
      }
    }
    //
    // How about out of actual space on the partition?
    //
    else if (m_partition_space_left <= 0) {
      if (!m_partition_full) {
        m_partition_full = true;
        Warning(DISK_IS_ACTUAL_FULL_MESSAGE);
      }
    }
    //
    // How about being within the headroom limit?
    //
    else if (m_space_used + headroom >= max_space) {
      if (!m_disk_low) {
        m_disk_low = true;
        Warning(DISK_IS_CONFIG_LOW_MESSAGE);
      }
    } else {
      if (!m_partition_low) {
        m_partition_low = true;
        Warning(DISK_IS_ACTUAL_LOW_MESSAGE);
      }
    }
  } else {
    //
    // We have enough space to log again; clear any previous messages
    //
    if (logging_space_exhausted) {
      Note("Logging space is no longer exhausted.");
    }

    logging_space_exhausted = false;
    if (m_disk_full || m_partition_full) {
      Note("Logging disk is no longer full; access logging to local log directory resumed.");
      m_disk_full      = false;
      m_partition_full = false;
    }
    if (m_disk_low || m_partition_low) {
      Note("Logging disk is no longer low; access logging to local log directory resumed.");
      m_disk_low      = false;
      m_partition_low = false;
    }
  }
}

bool
LogConfig::evaluate_config()
{
  ats_scoped_str path(RecConfigReadConfigPath("proxy.config.log.config.filename", ts::filename::LOGGING));
  struct stat    sbuf;
  if (stat(path.get(), &sbuf) == -1 && errno == ENOENT) {
    Warning("logging configuration '%s' doesn't exist", path.get());
    return false;
  }

  Note("%s loading ...", path.get());
  YamlLogConfig y(this);

  bool zret = y.parse(path.get());
  if (zret) {
    Note("%s finished loading", path.get());
  } else {
    Note("%s failed to load", path.get());
  }

  return zret;
}
