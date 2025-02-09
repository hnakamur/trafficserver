#######################
#
#  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
#  agreements.  See the NOTICE file distributed with this work for additional information regarding
#  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
#  (the "License"); you may not use this file except in compliance with the License.  You may obtain
#  a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
#  or implied. See the License for the specific language governing permissions and limitations under
#  the License.
#
#######################

add_atsplugin(otel_tracer otel_tracer.cc)
target_link_libraries(
  otel_tracer
  PRIVATE
    "$<LINK_GROUP:RESCAN,opentelemetry::opentelemetry_exporter_ostream_span,opentelemetry::opentelemetry_exporter_otlp_http,opentelemetry::opentelemetry_exporter_otlp_http_client,opentelemetry::opentelemetry_http_client_curl,opentelemetry::opentelemetry_logs,opentelemetry::opentelemetry_metrics,opentelemetry::opentelemetry_otlp_recordable,opentelemetry::opentelemetry_proto,opentelemetry::opentelemetry_resources,opentelemetry::opentelemetry_trace,opentelemetry::opentelemetry_version,opentelemetry::opentelemetry_common,protobuf::protobuf,curl::curl,absl::absl_bad_any_cast_impl,absl::absl_bad_optional_access,absl::absl_bad_variant_access,absl::absl_base,absl::absl_city,absl::absl_civil_time,absl::absl_cord,absl::absl_cord_internal,absl::absl_cordz_functions,absl::absl_cordz_handle,absl::absl_cordz_info,absl::absl_cordz_sample_token,absl::absl_crc32c,absl::absl_crc_cord_state,absl::absl_crc_cpu_detect,absl::absl_crc_internal,absl::absl_debugging_internal,absl::absl_demangle_internal,absl::absl_die_if_null,absl::absl_examine_stack,absl::absl_exponential_biased,absl::absl_failure_signal_handler,absl::absl_flags_commandlineflag,absl::absl_flags_commandlineflag_internal,absl::absl_flags_config,absl::absl_flags_internal,absl::absl_flags_marshalling,absl::absl_flags_parse,absl::absl_flags_private_handle_accessor,absl::absl_flags_program_name,absl::absl_flags_reflection,absl::absl_flags_usage,absl::absl_flags_usage_internal,absl::absl_graphcycles_internal,absl::absl_hash,absl::absl_hashtablez_sampler,absl::absl_int128,absl::absl_kernel_timeout_internal,absl::absl_leak_check,absl::absl_log_entry,absl::absl_log_flags,absl::absl_log_globals,absl::absl_log_initialize,absl::absl_log_internal_check_op,absl::absl_log_internal_conditions,absl::absl_log_internal_fnmatch,absl::absl_log_internal_format,absl::absl_log_internal_globals,absl::absl_log_internal_log_sink_set,absl::absl_log_internal_message,absl::absl_log_internal_nullguard,absl::absl_log_internal_proto,absl::absl_log_severity,absl::absl_log_sink,absl::absl_low_level_hash,absl::absl_malloc_internal,absl::absl_periodic_sampler,absl::absl_random_distributions,absl::absl_random_internal_distribution_test_util,absl::absl_random_internal_platform,absl::absl_random_internal_pool_urbg,absl::absl_random_internal_randen,absl::absl_random_internal_randen_hwaes,absl::absl_random_internal_randen_hwaes_impl,absl::absl_random_internal_randen_slow,absl::absl_random_internal_seed_material,absl::absl_random_seed_gen_exception,absl::absl_random_seed_sequences,absl::absl_raw_hash_set,absl::absl_raw_logging_internal,absl::absl_scoped_set_env,absl::absl_spinlock_wait,absl::absl_stacktrace,absl::absl_status,absl::absl_statusor,absl::absl_str_format_internal,absl::absl_strerror,absl::absl_string_view,absl::absl_strings,absl::absl_strings_internal,absl::absl_symbolize,absl::absl_synchronization,absl::absl_throw_delegate,absl::absl_time,absl::absl_time_zone,absl::absl_vlog_config_internal,utf8::utf8_range,utf8::utf8_validity,upb::upb>"
)
verify_global_plugin(otel_tracer)
