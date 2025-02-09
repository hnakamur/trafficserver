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

# Findabsl.cmake
#
# This will define the following variables
#
#     absl_FOUND
#     absl_bad_any_cast_impl_LIBRARY
#     absl_bad_optional_access_LIBRARY
#     absl_bad_variant_access_LIBRARY
#     absl_base_LIBRARY
#     absl_city_LIBRARY
#     absl_civil_time_LIBRARY
#     absl_cord_LIBRARY
#     absl_cord_internal_LIBRARY
#     absl_cordz_functions_LIBRARY
#     absl_cordz_handle_LIBRARY
#     absl_cordz_info_LIBRARY
#     absl_cordz_sample_token_LIBRARY
#     absl_crc32c_LIBRARY
#     absl_crc_cord_state_LIBRARY
#     absl_crc_cpu_detect_LIBRARY
#     absl_crc_internal_LIBRARY
#     absl_debugging_internal_LIBRARY
#     absl_demangle_internal_LIBRARY
#     absl_die_if_null_LIBRARY
#     absl_examine_stack_LIBRARY
#     absl_exponential_biased_LIBRARY
#     absl_failure_signal_handler_LIBRARY
#     absl_flags_commandlineflag_LIBRARY
#     absl_flags_commandlineflag_internal_LIBRARY
#     absl_flags_config_LIBRARY
#     absl_flags_internal_LIBRARY
#     absl_flags_marshalling_LIBRARY
#     absl_flags_parse_LIBRARY
#     absl_flags_private_handle_accessor_LIBRARY
#     absl_flags_program_name_LIBRARY
#     absl_flags_reflection_LIBRARY
#     absl_flags_usage_LIBRARY
#     absl_flags_usage_internal_LIBRARY
#     absl_graphcycles_internal_LIBRARY
#     absl_hash_LIBRARY
#     absl_hashtablez_sampler_LIBRARY
#     absl_int128_LIBRARY
#     absl_kernel_timeout_internal_LIBRARY
#     absl_leak_check_LIBRARY
#     absl_log_entry_LIBRARY
#     absl_log_flags_LIBRARY
#     absl_log_globals_LIBRARY
#     absl_log_initialize_LIBRARY
#     absl_log_internal_check_op_LIBRARY
#     absl_log_internal_conditions_LIBRARY
#     absl_log_internal_fnmatch_LIBRARY
#     absl_log_internal_format_LIBRARY
#     absl_log_internal_globals_LIBRARY
#     absl_log_internal_log_sink_set_LIBRARY
#     absl_log_internal_message_LIBRARY
#     absl_log_internal_nullguard_LIBRARY
#     absl_log_internal_proto_LIBRARY
#     absl_log_severity_LIBRARY
#     absl_log_sink_LIBRARY
#     absl_low_level_hash_LIBRARY
#     absl_malloc_internal_LIBRARY
#     absl_periodic_sampler_LIBRARY
#     absl_random_distributions_LIBRARY
#     absl_random_internal_distribution_test_util_LIBRARY
#     absl_random_internal_platform_LIBRARY
#     absl_random_internal_pool_urbg_LIBRARY
#     absl_random_internal_randen_LIBRARY
#     absl_random_internal_randen_hwaes_LIBRARY
#     absl_random_internal_randen_hwaes_impl_LIBRARY
#     absl_random_internal_randen_slow_LIBRARY
#     absl_random_internal_seed_material_LIBRARY
#     absl_random_seed_gen_exception_LIBRARY
#     absl_random_seed_sequences_LIBRARY
#     absl_raw_hash_set_LIBRARY
#     absl_raw_logging_internal_LIBRARY
#     absl_scoped_set_env_LIBRARY
#     absl_spinlock_wait_LIBRARY
#     absl_stacktrace_LIBRARY
#     absl_status_LIBRARY
#     absl_statusor_LIBRARY
#     absl_str_format_internal_LIBRARY
#     absl_strerror_LIBRARY
#     absl_string_view_LIBRARY
#     absl_strings_LIBRARY
#     absl_strings_internal_LIBRARY
#     absl_symbolize_LIBRARY
#     absl_synchronization_LIBRARY
#     absl_throw_delegate_LIBRARY
#     absl_time_LIBRARY
#     absl_time_zone_LIBRARY
#     absl_vlog_config_internal_LIBRARY
#     absl_INCLUDE_DIRS
#
# and the following imported targets
#
#     absl::absl_bad_any_cast_impl
#     absl::absl_bad_optional_access
#     absl::absl_bad_variant_access
#     absl::absl_base
#     absl::absl_city
#     absl::absl_civil_time
#     absl::absl_cord
#     absl::absl_cord_internal
#     absl::absl_cordz_functions
#     absl::absl_cordz_handle
#     absl::absl_cordz_info
#     absl::absl_cordz_sample_token
#     absl::absl_crc32c
#     absl::absl_crc_cord_state
#     absl::absl_crc_cpu_detect
#     absl::absl_crc_internal
#     absl::absl_debugging_internal
#     absl::absl_demangle_internal
#     absl::absl_die_if_null
#     absl::absl_examine_stack
#     absl::absl_exponential_biased
#     absl::absl_failure_signal_handler
#     absl::absl_flags_commandlineflag
#     absl::absl_flags_commandlineflag_internal
#     absl::absl_flags_config
#     absl::absl_flags_internal
#     absl::absl_flags_marshalling
#     absl::absl_flags_parse
#     absl::absl_flags_private_handle_accessor
#     absl::absl_flags_program_name
#     absl::absl_flags_reflection
#     absl::absl_flags_usage
#     absl::absl_flags_usage_internal
#     absl::absl_graphcycles_internal
#     absl::absl_hash
#     absl::absl_hashtablez_sampler
#     absl::absl_int128
#     absl::absl_kernel_timeout_internal
#     absl::absl_leak_check
#     absl::absl_log_entry
#     absl::absl_log_flags
#     absl::absl_log_globals
#     absl::absl_log_initialize
#     absl::absl_log_internal_check_op
#     absl::absl_log_internal_conditions
#     absl::absl_log_internal_fnmatch
#     absl::absl_log_internal_format
#     absl::absl_log_internal_globals
#     absl::absl_log_internal_log_sink_set
#     absl::absl_log_internal_message
#     absl::absl_log_internal_nullguard
#     absl::absl_log_internal_proto
#     absl::absl_log_severity
#     absl::absl_log_sink
#     absl::absl_low_level_hash
#     absl::absl_malloc_internal
#     absl::absl_periodic_sampler
#     absl::absl_random_distributions
#     absl::absl_random_internal_distribution_test_util
#     absl::absl_random_internal_platform
#     absl::absl_random_internal_pool_urbg
#     absl::absl_random_internal_randen
#     absl::absl_random_internal_randen_hwaes
#     absl::absl_random_internal_randen_hwaes_impl
#     absl::absl_random_internal_randen_slow
#     absl::absl_random_internal_seed_material
#     absl::absl_random_seed_gen_exception
#     absl::absl_random_seed_sequences
#     absl::absl_raw_hash_set
#     absl::absl_raw_logging_internal
#     absl::absl_scoped_set_env
#     absl::absl_spinlock_wait
#     absl::absl_stacktrace
#     absl::absl_status
#     absl::absl_statusor
#     absl::absl_str_format_internal
#     absl::absl_strerror
#     absl::absl_string_view
#     absl::absl_strings
#     absl::absl_strings_internal
#     absl::absl_symbolize
#     absl::absl_synchronization
#     absl::absl_throw_delegate
#     absl::absl_time
#     absl::absl_time_zone
#     absl::absl_vlog_config_internal
#

find_library(absl_bad_any_cast_impl_LIBRARY NAMES absl_bad_any_cast_impl)
find_library(absl_bad_optional_access_LIBRARY NAMES absl_bad_optional_access)
find_library(absl_bad_variant_access_LIBRARY NAMES absl_bad_variant_access)
find_library(absl_base_LIBRARY NAMES absl_base)
find_library(absl_city_LIBRARY NAMES absl_city)
find_library(absl_civil_time_LIBRARY NAMES absl_civil_time)
find_library(absl_cord_LIBRARY NAMES absl_cord)
find_library(absl_cord_internal_LIBRARY NAMES absl_cord_internal)
find_library(absl_cordz_functions_LIBRARY NAMES absl_cordz_functions)
find_library(absl_cordz_handle_LIBRARY NAMES absl_cordz_handle)
find_library(absl_cordz_info_LIBRARY NAMES absl_cordz_info)
find_library(absl_cordz_sample_token_LIBRARY NAMES absl_cordz_sample_token)
find_library(absl_crc32c_LIBRARY NAMES absl_crc32c)
find_library(absl_crc_cord_state_LIBRARY NAMES absl_crc_cord_state)
find_library(absl_crc_cpu_detect_LIBRARY NAMES absl_crc_cpu_detect)
find_library(absl_crc_internal_LIBRARY NAMES absl_crc_internal)
find_library(absl_debugging_internal_LIBRARY NAMES absl_debugging_internal)
find_library(absl_demangle_internal_LIBRARY NAMES absl_demangle_internal)
find_library(absl_die_if_null_LIBRARY NAMES absl_die_if_null)
find_library(absl_examine_stack_LIBRARY NAMES absl_examine_stack)
find_library(absl_exponential_biased_LIBRARY NAMES absl_exponential_biased)
find_library(absl_failure_signal_handler_LIBRARY NAMES absl_failure_signal_handler)
find_library(absl_flags_commandlineflag_LIBRARY NAMES absl_flags_commandlineflag)
find_library(absl_flags_commandlineflag_internal_LIBRARY NAMES absl_flags_commandlineflag_internal)
find_library(absl_flags_config_LIBRARY NAMES absl_flags_config)
find_library(absl_flags_internal_LIBRARY NAMES absl_flags_internal)
find_library(absl_flags_marshalling_LIBRARY NAMES absl_flags_marshalling)
find_library(absl_flags_parse_LIBRARY NAMES absl_flags_parse)
find_library(absl_flags_private_handle_accessor_LIBRARY NAMES absl_flags_private_handle_accessor)
find_library(absl_flags_program_name_LIBRARY NAMES absl_flags_program_name)
find_library(absl_flags_reflection_LIBRARY NAMES absl_flags_reflection)
find_library(absl_flags_usage_LIBRARY NAMES absl_flags_usage)
find_library(absl_flags_usage_internal_LIBRARY NAMES absl_flags_usage_internal)
find_library(absl_graphcycles_internal_LIBRARY NAMES absl_graphcycles_internal)
find_library(absl_hash_LIBRARY NAMES absl_hash)
find_library(absl_hashtablez_sampler_LIBRARY NAMES absl_hashtablez_sampler)
find_library(absl_int128_LIBRARY NAMES absl_int128)
find_library(absl_kernel_timeout_internal_LIBRARY NAMES absl_kernel_timeout_internal)
find_library(absl_leak_check_LIBRARY NAMES absl_leak_check)
find_library(absl_log_entry_LIBRARY NAMES absl_log_entry)
find_library(absl_log_flags_LIBRARY NAMES absl_log_flags)
find_library(absl_log_globals_LIBRARY NAMES absl_log_globals)
find_library(absl_log_initialize_LIBRARY NAMES absl_log_initialize)
find_library(absl_log_internal_check_op_LIBRARY NAMES absl_log_internal_check_op)
find_library(absl_log_internal_conditions_LIBRARY NAMES absl_log_internal_conditions)
find_library(absl_log_internal_fnmatch_LIBRARY NAMES absl_log_internal_fnmatch)
find_library(absl_log_internal_format_LIBRARY NAMES absl_log_internal_format)
find_library(absl_log_internal_globals_LIBRARY NAMES absl_log_internal_globals)
find_library(absl_log_internal_log_sink_set_LIBRARY NAMES absl_log_internal_log_sink_set)
find_library(absl_log_internal_message_LIBRARY NAMES absl_log_internal_message)
find_library(absl_log_internal_nullguard_LIBRARY NAMES absl_log_internal_nullguard)
find_library(absl_log_internal_proto_LIBRARY NAMES absl_log_internal_proto)
find_library(absl_log_severity_LIBRARY NAMES absl_log_severity)
find_library(absl_log_sink_LIBRARY NAMES absl_log_sink)
find_library(absl_low_level_hash_LIBRARY NAMES absl_low_level_hash)
find_library(absl_malloc_internal_LIBRARY NAMES absl_malloc_internal)
find_library(absl_periodic_sampler_LIBRARY NAMES absl_periodic_sampler)
find_library(absl_random_distributions_LIBRARY NAMES absl_random_distributions)
find_library(absl_random_internal_distribution_test_util_LIBRARY NAMES absl_random_internal_distribution_test_util)
find_library(absl_random_internal_platform_LIBRARY NAMES absl_random_internal_platform)
find_library(absl_random_internal_pool_urbg_LIBRARY NAMES absl_random_internal_pool_urbg)
find_library(absl_random_internal_randen_LIBRARY NAMES absl_random_internal_randen)
find_library(absl_random_internal_randen_hwaes_LIBRARY NAMES absl_random_internal_randen_hwaes)
find_library(absl_random_internal_randen_hwaes_impl_LIBRARY NAMES absl_random_internal_randen_hwaes_impl)
find_library(absl_random_internal_randen_slow_LIBRARY NAMES absl_random_internal_randen_slow)
find_library(absl_random_internal_seed_material_LIBRARY NAMES absl_random_internal_seed_material)
find_library(absl_random_seed_gen_exception_LIBRARY NAMES absl_random_seed_gen_exception)
find_library(absl_random_seed_sequences_LIBRARY NAMES absl_random_seed_sequences)
find_library(absl_raw_hash_set_LIBRARY NAMES absl_raw_hash_set)
find_library(absl_raw_logging_internal_LIBRARY NAMES absl_raw_logging_internal)
find_library(absl_scoped_set_env_LIBRARY NAMES absl_scoped_set_env)
find_library(absl_spinlock_wait_LIBRARY NAMES absl_spinlock_wait)
find_library(absl_stacktrace_LIBRARY NAMES absl_stacktrace)
find_library(absl_status_LIBRARY NAMES absl_status)
find_library(absl_statusor_LIBRARY NAMES absl_statusor)
find_library(absl_str_format_internal_LIBRARY NAMES absl_str_format_internal)
find_library(absl_strerror_LIBRARY NAMES absl_strerror)
find_library(absl_string_view_LIBRARY NAMES absl_string_view)
find_library(absl_strings_LIBRARY NAMES absl_strings)
find_library(absl_strings_internal_LIBRARY NAMES absl_strings_internal)
find_library(absl_symbolize_LIBRARY NAMES absl_symbolize)
find_library(absl_synchronization_LIBRARY NAMES absl_synchronization)
find_library(absl_throw_delegate_LIBRARY NAMES absl_throw_delegate)
find_library(absl_time_LIBRARY NAMES absl_time)
find_library(absl_time_zone_LIBRARY NAMES absl_time_zone)
find_library(absl_vlog_config_internal_LIBRARY NAMES absl_vlog_config_internal)
find_path(absl_INCLUDE_DIR NAMES absl/base/config.h)

mark_as_advanced(
  absl_FOUND
  absl_bad_any_cast_impl_LIBRARY
  absl_bad_optional_access_LIBRARY
  absl_bad_variant_access_LIBRARY
  absl_base_LIBRARY
  absl_city_LIBRARY
  absl_civil_time_LIBRARY
  absl_cord_LIBRARY
  absl_cord_internal_LIBRARY
  absl_cordz_functions_LIBRARY
  absl_cordz_handle_LIBRARY
  absl_cordz_info_LIBRARY
  absl_cordz_sample_token_LIBRARY
  absl_crc32c_LIBRARY
  absl_crc_cord_state_LIBRARY
  absl_crc_cpu_detect_LIBRARY
  absl_crc_internal_LIBRARY
  absl_debugging_internal_LIBRARY
  absl_demangle_internal_LIBRARY
  absl_die_if_null_LIBRARY
  absl_examine_stack_LIBRARY
  absl_exponential_biased_LIBRARY
  absl_failure_signal_handler_LIBRARY
  absl_flags_commandlineflag_LIBRARY
  absl_flags_commandlineflag_internal_LIBRARY
  absl_flags_config_LIBRARY
  absl_flags_internal_LIBRARY
  absl_flags_marshalling_LIBRARY
  absl_flags_parse_LIBRARY
  absl_flags_private_handle_accessor_LIBRARY
  absl_flags_program_name_LIBRARY
  absl_flags_reflection_LIBRARY
  absl_flags_usage_LIBRARY
  absl_flags_usage_internal_LIBRARY
  absl_graphcycles_internal_LIBRARY
  absl_hash_LIBRARY
  absl_hashtablez_sampler_LIBRARY
  absl_int128_LIBRARY
  absl_kernel_timeout_internal_LIBRARY
  absl_leak_check_LIBRARY
  absl_log_entry_LIBRARY
  absl_log_flags_LIBRARY
  absl_log_globals_LIBRARY
  absl_log_initialize_LIBRARY
  absl_log_internal_check_op_LIBRARY
  absl_log_internal_conditions_LIBRARY
  absl_log_internal_fnmatch_LIBRARY
  absl_log_internal_format_LIBRARY
  absl_log_internal_globals_LIBRARY
  absl_log_internal_log_sink_set_LIBRARY
  absl_log_internal_message_LIBRARY
  absl_log_internal_nullguard_LIBRARY
  absl_log_internal_proto_LIBRARY
  absl_log_severity_LIBRARY
  absl_log_sink_LIBRARY
  absl_low_level_hash_LIBRARY
  absl_malloc_internal_LIBRARY
  absl_periodic_sampler_LIBRARY
  absl_random_distributions_LIBRARY
  absl_random_internal_distribution_test_util_LIBRARY
  absl_random_internal_platform_LIBRARY
  absl_random_internal_pool_urbg_LIBRARY
  absl_random_internal_randen_LIBRARY
  absl_random_internal_randen_hwaes_LIBRARY
  absl_random_internal_randen_hwaes_impl_LIBRARY
  absl_random_internal_randen_slow_LIBRARY
  absl_random_internal_seed_material_LIBRARY
  absl_random_seed_gen_exception_LIBRARY
  absl_random_seed_sequences_LIBRARY
  absl_raw_hash_set_LIBRARY
  absl_raw_logging_internal_LIBRARY
  absl_scoped_set_env_LIBRARY
  absl_spinlock_wait_LIBRARY
  absl_stacktrace_LIBRARY
  absl_status_LIBRARY
  absl_statusor_LIBRARY
  absl_str_format_internal_LIBRARY
  absl_strerror_LIBRARY
  absl_string_view_LIBRARY
  absl_strings_LIBRARY
  absl_strings_internal_LIBRARY
  absl_symbolize_LIBRARY
  absl_synchronization_LIBRARY
  absl_throw_delegate_LIBRARY
  absl_time_LIBRARY
  absl_time_zone_LIBRARY
  absl_vlog_config_internal_LIBRARY
  absl_INCLUDE_DIR
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(absl REQUIRED_VARS absl_INCLUDE_DIR absl_crc_cpu_detect_LIBRARY absl_status_LIBRARY)

if(absl_FOUND)
  set(absl_INCLUDE_DIRS "${absl_INCLUDE_DIR}")
endif()

if(absl_FOUND AND NOT TARGET absl::absl_bad_any_cast_impl)
  add_library(absl::absl_bad_any_cast_impl STATIC IMPORTED)
  set_target_properties(
    absl::absl_bad_any_cast_impl PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                            IMPORTED_LOCATION "${absl_bad_any_cast_impl_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_bad_optional_access)
  add_library(absl::absl_bad_optional_access STATIC IMPORTED)
  set_target_properties(
    absl::absl_bad_optional_access PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                              IMPORTED_LOCATION "${absl_bad_optional_access_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_bad_variant_access)
  add_library(absl::absl_bad_variant_access STATIC IMPORTED)
  set_target_properties(
    absl::absl_bad_variant_access PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                             IMPORTED_LOCATION "${absl_bad_variant_access_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_base)
  add_library(absl::absl_base STATIC IMPORTED)
  set_target_properties(
    absl::absl_base PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                   "${absl_base_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_city)
  add_library(absl::absl_city STATIC IMPORTED)
  set_target_properties(
    absl::absl_city PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                   "${absl_city_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_civil_time)
  add_library(absl::absl_civil_time STATIC IMPORTED)
  set_target_properties(
    absl::absl_civil_time PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                         "${absl_civil_time_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_cord)
  add_library(absl::absl_cord STATIC IMPORTED)
  set_target_properties(
    absl::absl_cord PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                   "${absl_cord_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_cord_internal)
  add_library(absl::absl_cord_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_cord_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                        IMPORTED_LOCATION "${absl_cord_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_cordz_functions)
  add_library(absl::absl_cordz_functions STATIC IMPORTED)
  set_target_properties(
    absl::absl_cordz_functions PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                          IMPORTED_LOCATION "${absl_cordz_functions_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_cordz_handle)
  add_library(absl::absl_cordz_handle STATIC IMPORTED)
  set_target_properties(
    absl::absl_cordz_handle PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                       IMPORTED_LOCATION "${absl_cordz_handle_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_cordz_info)
  add_library(absl::absl_cordz_info STATIC IMPORTED)
  set_target_properties(
    absl::absl_cordz_info PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                         "${absl_cordz_info_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_cordz_sample_token)
  add_library(absl::absl_cordz_sample_token STATIC IMPORTED)
  set_target_properties(
    absl::absl_cordz_sample_token PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                             IMPORTED_LOCATION "${absl_cordz_sample_token_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_crc32c)
  add_library(absl::absl_crc32c STATIC IMPORTED)
  set_target_properties(
    absl::absl_crc32c PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                     "${absl_crc32c_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_crc_cord_state)
  add_library(absl::absl_crc_cord_state STATIC IMPORTED)
  set_target_properties(
    absl::absl_crc_cord_state PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                         IMPORTED_LOCATION "${absl_crc_cord_state_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_crc_cpu_detect)
  add_library(absl::absl_crc_cpu_detect STATIC IMPORTED)
  set_target_properties(
    absl::absl_crc_cpu_detect PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                         IMPORTED_LOCATION "${absl_crc_cpu_detect_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_crc_internal)
  add_library(absl::absl_crc_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_crc_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                       IMPORTED_LOCATION "${absl_crc_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_debugging_internal)
  add_library(absl::absl_debugging_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_debugging_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                             IMPORTED_LOCATION "${absl_debugging_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_demangle_internal)
  add_library(absl::absl_demangle_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_demangle_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                            IMPORTED_LOCATION "${absl_demangle_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_die_if_null)
  add_library(absl::absl_die_if_null STATIC IMPORTED)
  set_target_properties(
    absl::absl_die_if_null PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                          "${absl_die_if_null_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_examine_stack)
  add_library(absl::absl_examine_stack STATIC IMPORTED)
  set_target_properties(
    absl::absl_examine_stack PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                        IMPORTED_LOCATION "${absl_examine_stack_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_exponential_biased)
  add_library(absl::absl_exponential_biased STATIC IMPORTED)
  set_target_properties(
    absl::absl_exponential_biased PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                             IMPORTED_LOCATION "${absl_exponential_biased_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_failure_signal_handler)
  add_library(absl::absl_failure_signal_handler STATIC IMPORTED)
  set_target_properties(
    absl::absl_failure_signal_handler PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                 IMPORTED_LOCATION "${absl_failure_signal_handler_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_commandlineflag)
  add_library(absl::absl_flags_commandlineflag STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_commandlineflag PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                IMPORTED_LOCATION "${absl_flags_commandlineflag_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_commandlineflag_internal)
  add_library(absl::absl_flags_commandlineflag_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_commandlineflag_internal
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                   "${absl_flags_commandlineflag_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_config)
  add_library(absl::absl_flags_config STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_config PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                       IMPORTED_LOCATION "${absl_flags_config_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_internal)
  add_library(absl::absl_flags_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                         IMPORTED_LOCATION "${absl_flags_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_marshalling)
  add_library(absl::absl_flags_marshalling STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_marshalling PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                            IMPORTED_LOCATION "${absl_flags_marshalling_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_parse)
  add_library(absl::absl_flags_parse STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_parse PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                          "${absl_flags_parse_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_private_handle_accessor)
  add_library(absl::absl_flags_private_handle_accessor STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_private_handle_accessor
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                   "${absl_flags_private_handle_accessor_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_program_name)
  add_library(absl::absl_flags_program_name STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_program_name PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                             IMPORTED_LOCATION "${absl_flags_program_name_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_reflection)
  add_library(absl::absl_flags_reflection STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_reflection PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                           IMPORTED_LOCATION "${absl_flags_reflection_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_usage)
  add_library(absl::absl_flags_usage STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_usage PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                          "${absl_flags_usage_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_flags_usage_internal)
  add_library(absl::absl_flags_usage_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_flags_usage_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                               IMPORTED_LOCATION "${absl_flags_usage_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_graphcycles_internal)
  add_library(absl::absl_graphcycles_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_graphcycles_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                               IMPORTED_LOCATION "${absl_graphcycles_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_hash)
  add_library(absl::absl_hash STATIC IMPORTED)
  set_target_properties(
    absl::absl_hash PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                   "${absl_hash_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_hashtablez_sampler)
  add_library(absl::absl_hashtablez_sampler STATIC IMPORTED)
  set_target_properties(
    absl::absl_hashtablez_sampler PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                             IMPORTED_LOCATION "${absl_hashtablez_sampler_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_int128)
  add_library(absl::absl_int128 STATIC IMPORTED)
  set_target_properties(
    absl::absl_int128 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                     "${absl_int128_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_kernel_timeout_internal)
  add_library(absl::absl_kernel_timeout_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_kernel_timeout_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                  IMPORTED_LOCATION "${absl_kernel_timeout_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_leak_check)
  add_library(absl::absl_leak_check STATIC IMPORTED)
  set_target_properties(
    absl::absl_leak_check PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                         "${absl_leak_check_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_entry)
  add_library(absl::absl_log_entry STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_entry PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                        "${absl_log_entry_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_flags)
  add_library(absl::absl_log_flags STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_flags PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                        "${absl_log_flags_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_globals)
  add_library(absl::absl_log_globals STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_globals PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                          "${absl_log_globals_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_initialize)
  add_library(absl::absl_log_initialize STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_initialize PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                         IMPORTED_LOCATION "${absl_log_initialize_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_internal_check_op)
  add_library(absl::absl_log_internal_check_op STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_internal_check_op PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                IMPORTED_LOCATION "${absl_log_internal_check_op_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_internal_conditions)
  add_library(absl::absl_log_internal_conditions STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_internal_conditions PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                  IMPORTED_LOCATION "${absl_log_internal_conditions_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_internal_fnmatch)
  add_library(absl::absl_log_internal_fnmatch STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_internal_fnmatch PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                               IMPORTED_LOCATION "${absl_log_internal_fnmatch_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_internal_format)
  add_library(absl::absl_log_internal_format STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_internal_format PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                              IMPORTED_LOCATION "${absl_log_internal_format_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_internal_globals)
  add_library(absl::absl_log_internal_globals STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_internal_globals PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                               IMPORTED_LOCATION "${absl_log_internal_globals_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_internal_log_sink_set)
  add_library(absl::absl_log_internal_log_sink_set STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_internal_log_sink_set PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                    IMPORTED_LOCATION "${absl_log_internal_log_sink_set_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_internal_message)
  add_library(absl::absl_log_internal_message STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_internal_message PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                               IMPORTED_LOCATION "${absl_log_internal_message_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_internal_nullguard)
  add_library(absl::absl_log_internal_nullguard STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_internal_nullguard PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                 IMPORTED_LOCATION "${absl_log_internal_nullguard_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_internal_proto)
  add_library(absl::absl_log_internal_proto STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_internal_proto PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                             IMPORTED_LOCATION "${absl_log_internal_proto_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_severity)
  add_library(absl::absl_log_severity STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_severity PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                       IMPORTED_LOCATION "${absl_log_severity_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_log_sink)
  add_library(absl::absl_log_sink STATIC IMPORTED)
  set_target_properties(
    absl::absl_log_sink PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                       "${absl_log_sink_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_low_level_hash)
  add_library(absl::absl_low_level_hash STATIC IMPORTED)
  set_target_properties(
    absl::absl_low_level_hash PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                         IMPORTED_LOCATION "${absl_low_level_hash_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_malloc_internal)
  add_library(absl::absl_malloc_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_malloc_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                          IMPORTED_LOCATION "${absl_malloc_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_periodic_sampler)
  add_library(absl::absl_periodic_sampler STATIC IMPORTED)
  set_target_properties(
    absl::absl_periodic_sampler PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                           IMPORTED_LOCATION "${absl_periodic_sampler_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_distributions)
  add_library(absl::absl_random_distributions STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_distributions PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                               IMPORTED_LOCATION "${absl_random_distributions_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_internal_distribution_test_util)
  add_library(absl::absl_random_internal_distribution_test_util STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_internal_distribution_test_util
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
               IMPORTED_LOCATION "${absl_random_internal_distribution_test_util_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_internal_platform)
  add_library(absl::absl_random_internal_platform STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_internal_platform PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                   IMPORTED_LOCATION "${absl_random_internal_platform_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_internal_pool_urbg)
  add_library(absl::absl_random_internal_pool_urbg STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_internal_pool_urbg PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                    IMPORTED_LOCATION "${absl_random_internal_pool_urbg_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_internal_randen)
  add_library(absl::absl_random_internal_randen STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_internal_randen PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                 IMPORTED_LOCATION "${absl_random_internal_randen_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_internal_randen_hwaes)
  add_library(absl::absl_random_internal_randen_hwaes STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_internal_randen_hwaes PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                       IMPORTED_LOCATION "${absl_random_internal_randen_hwaes_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_internal_randen_hwaes_impl)
  add_library(absl::absl_random_internal_randen_hwaes_impl STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_internal_randen_hwaes_impl
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                   "${absl_random_internal_randen_hwaes_impl_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_internal_randen_slow)
  add_library(absl::absl_random_internal_randen_slow STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_internal_randen_slow PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                      IMPORTED_LOCATION "${absl_random_internal_randen_slow_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_internal_seed_material)
  add_library(absl::absl_random_internal_seed_material STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_internal_seed_material
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                   "${absl_random_internal_seed_material_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_seed_gen_exception)
  add_library(absl::absl_random_seed_gen_exception STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_seed_gen_exception PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                    IMPORTED_LOCATION "${absl_random_seed_gen_exception_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_random_seed_sequences)
  add_library(absl::absl_random_seed_sequences STATIC IMPORTED)
  set_target_properties(
    absl::absl_random_seed_sequences PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                                IMPORTED_LOCATION "${absl_random_seed_sequences_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_raw_hash_set)
  add_library(absl::absl_raw_hash_set STATIC IMPORTED)
  set_target_properties(
    absl::absl_raw_hash_set PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                       IMPORTED_LOCATION "${absl_raw_hash_set_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_raw_logging_internal)
  add_library(absl::absl_raw_logging_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_raw_logging_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                               IMPORTED_LOCATION "${absl_raw_logging_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_scoped_set_env)
  add_library(absl::absl_scoped_set_env STATIC IMPORTED)
  set_target_properties(
    absl::absl_scoped_set_env PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                         IMPORTED_LOCATION "${absl_scoped_set_env_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_spinlock_wait)
  add_library(absl::absl_spinlock_wait STATIC IMPORTED)
  set_target_properties(
    absl::absl_spinlock_wait PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                        IMPORTED_LOCATION "${absl_spinlock_wait_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_stacktrace)
  add_library(absl::absl_stacktrace STATIC IMPORTED)
  set_target_properties(
    absl::absl_stacktrace PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                         "${absl_stacktrace_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_status)
  add_library(absl::absl_status STATIC IMPORTED)
  set_target_properties(
    absl::absl_status PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                     "${absl_status_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_statusor)
  add_library(absl::absl_statusor STATIC IMPORTED)
  set_target_properties(
    absl::absl_statusor PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                       "${absl_statusor_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_str_format_internal)
  add_library(absl::absl_str_format_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_str_format_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                              IMPORTED_LOCATION "${absl_str_format_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_strerror)
  add_library(absl::absl_strerror STATIC IMPORTED)
  set_target_properties(
    absl::absl_strerror PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                       "${absl_strerror_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_string_view)
  add_library(absl::absl_string_view STATIC IMPORTED)
  set_target_properties(
    absl::absl_string_view PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                          "${absl_string_view_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_strings)
  add_library(absl::absl_strings STATIC IMPORTED)
  set_target_properties(
    absl::absl_strings PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                      "${absl_strings_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_strings_internal)
  add_library(absl::absl_strings_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_strings_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                           IMPORTED_LOCATION "${absl_strings_internal_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_symbolize)
  add_library(absl::absl_symbolize STATIC IMPORTED)
  set_target_properties(
    absl::absl_symbolize PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                        "${absl_symbolize_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_synchronization)
  add_library(absl::absl_synchronization STATIC IMPORTED)
  set_target_properties(
    absl::absl_synchronization PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                          IMPORTED_LOCATION "${absl_synchronization_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_throw_delegate)
  add_library(absl::absl_throw_delegate STATIC IMPORTED)
  set_target_properties(
    absl::absl_throw_delegate PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                         IMPORTED_LOCATION "${absl_throw_delegate_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_time)
  add_library(absl::absl_time STATIC IMPORTED)
  set_target_properties(
    absl::absl_time PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                   "${absl_time_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_time_zone)
  add_library(absl::absl_time_zone STATIC IMPORTED)
  set_target_properties(
    absl::absl_time_zone PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                        "${absl_time_zone_LIBRARY}"
  )
endif()
if(absl_FOUND AND NOT TARGET absl::absl_vlog_config_internal)
  add_library(absl::absl_vlog_config_internal STATIC IMPORTED)
  set_target_properties(
    absl::absl_vlog_config_internal PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIR}"
                                               IMPORTED_LOCATION "${absl_vlog_config_internal_LIBRARY}"
  )
endif()
