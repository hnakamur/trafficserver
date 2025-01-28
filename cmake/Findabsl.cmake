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
#     absl_LIBRARY
#     absl_INCLUDE_DIRS
#
# and the following imported targets
#
#     absl::absl
#


set(ABSL_LIBS
  absl_crc_cpu_detect
  absl_status
  absl_raw_logging_internal
  absl_kernel_timeout_internal
  absl_strerror
  absl_flags_parse
  absl_statusor
  absl_log_internal_conditions
  absl_malloc_internal
  absl_log_initialize
  absl_flags_commandlineflag
  absl_flags_marshalling
  absl_low_level_hash
  absl_flags_private_handle_accessor
  absl_cordz_sample_token
  absl_graphcycles_internal
  absl_bad_variant_access
  absl_periodic_sampler
  absl_log_severity
  absl_log_internal_globals
  absl_random_internal_seed_material
  absl_exponential_biased
  absl_crc_cord_state
  absl_log_internal_proto
  absl_flags_usage
  absl_log_internal_check_op
  absl_time_zone
  absl_random_internal_randen_slow
  absl_symbolize
  absl_vlog_config_internal
  absl_flags_commandlineflag_internal
  absl_log_flags
  absl_debugging_internal
  absl_cordz_info
  absl_log_internal_format
  absl_crc_internal
  absl_failure_signal_handler
  absl_crc32c
  absl_leak_check
  absl_log_internal_message
  absl_city
  absl_throw_delegate
  absl_log_internal_log_sink_set
  absl_stacktrace
  absl_time
  absl_cordz_handle
  absl_strings_internal
  absl_strings
  absl_random_seed_gen_exception
  absl_random_internal_pool_urbg
  absl_cord_internal
  absl_random_internal_distribution_test_util
  absl_base
  absl_bad_optional_access
  absl_flags_program_name
  absl_die_if_null
  absl_random_internal_randen_hwaes
  absl_random_internal_randen_hwaes_impl
  absl_cordz_functions
  absl_examine_stack
  absl_log_internal_fnmatch
  absl_random_internal_platform
  absl_synchronization
  absl_flags_usage_internal
  absl_spinlock_wait
  absl_bad_any_cast_impl
  absl_random_internal_randen
  absl_random_distributions
  absl_string_view
  absl_log_entry
  absl_flags_internal
  absl_log_sink
  absl_demangle_internal
  absl_raw_hash_set
  absl_log_globals
  absl_cord
  absl_hash
  absl_str_format_internal
  absl_civil_time
  absl_log_internal_nullguard
  absl_scoped_set_env
  absl_flags_config
  absl_hashtablez_sampler
  absl_flags_reflection
  absl_random_seed_sequences
  absl_int128
)

#set(ABSL_LIBS
#  absl_crc_cpu_detect
#  absl_status
#  absl_raw_logging_internal
#  absl_kernel_timeout_internal
#  absl_strerror
#  absl_flags_parse
#  absl_statusor
#  absl_log_internal_conditions
#  absl_malloc_internal
#  absl_log_initialize
#  absl_flags_commandlineflag
#  absl_flags_marshalling
#  absl_low_level_hash
#  absl_flags_private_handle_accessor
#  absl_cordz_sample_token
#  absl_graphcycles_internal
#  absl_bad_variant_access
#  absl_periodic_sampler
#  absl_log_severity
#  absl_log_internal_globals
#  absl_random_internal_seed_material
#  absl_exponential_biased
#  absl_crc_cord_state
#  absl_log_internal_proto
#  absl_flags_usage
#  absl_log_internal_check_op
#  absl_time_zone
#  absl_random_internal_randen_slow
#  absl_symbolize
#  absl_vlog_config_internal
#  absl_flags_commandlineflag_internal
#  absl_log_flags
#  absl_debugging_internal
#  absl_cordz_info
#  absl_log_internal_format
#  absl_int128
#  absl_crc_internal
#  absl_failure_signal_handler
#  absl_crc32c
#  absl_leak_check
#  absl_log_internal_message
#  absl_city
#  absl_throw_delegate
#  absl_log_internal_log_sink_set
#  absl_stacktrace
#  absl_time
#  absl_cordz_handle
#  absl_strings_internal
#  absl_strings
#  absl_random_seed_gen_exception
#  absl_random_internal_pool_urbg
#  absl_cord_internal
#  absl_random_internal_distribution_test_util
#  absl_base
#  absl_bad_optional_access
#  absl_flags_program_name
#  absl_die_if_null
#  absl_random_internal_randen_hwaes
#  absl_random_internal_randen_hwaes_impl
#  absl_cordz_functions
#  absl_examine_stack
#  absl_log_internal_fnmatch
#  absl_random_internal_platform
#  absl_synchronization
#  absl_flags_usage_internal
#  absl_spinlock_wait
#  absl_bad_any_cast_impl
#  absl_random_internal_randen
#  absl_random_distributions
#  absl_string_view
#  absl_log_entry
#  absl_flags_internal
#  absl_log_sink
#  absl_demangle_internal
#  absl_raw_hash_set
#  absl_log_globals
#  absl_cord
#  absl_hash
#  absl_str_format_internal
#  absl_civil_time
#  absl_log_internal_nullguard
#  absl_scoped_set_env
#  absl_flags_config
#  absl_hashtablez_sampler
#  absl_flags_reflection
#  absl_random_seed_sequences
#)

#set(ABSL_LIBS
#  absl_bad_any_cast_impl
#  absl_bad_optional_access
#  absl_bad_variant_access
#  absl_city
#  absl_civil_time
#  absl_cord
#  absl_cord_internal
#  absl_cordz_functions
#  absl_cordz_info
#  absl_cordz_sample_token
#  absl_crc32c
#  absl_crc_cord_state
#  absl_crc_cpu_detect
#  absl_crc_internal
#  absl_demangle_internal
#  absl_die_if_null
#  absl_examine_stack
#  absl_exponential_biased
#  absl_failure_signal_handler
#  absl_flags_commandlineflag
#  absl_flags_commandlineflag_internal
#  absl_flags_config
#  absl_flags_internal
#  absl_flags_marshalling
#  absl_flags_parse
#  absl_flags_private_handle_accessor
#  absl_flags_program_name
#  absl_flags_reflection
#  absl_flags_usage
#  absl_flags_usage_internal
#  absl_graphcycles_internal
#  absl_hash
#  absl_hashtablez_sampler
#  absl_leak_check
#  absl_log_entry
#  absl_log_flags
#  absl_log_initialize
#  absl_log_internal_check_op
#  absl_log_internal_conditions
#  absl_log_internal_fnmatch
#  absl_log_internal_log_sink_set
#  absl_log_internal_message
#  absl_log_internal_nullguard
#  absl_log_internal_proto
#  absl_log_severity
#  absl_log_sink
#  absl_low_level_hash
#  absl_periodic_sampler
#  absl_random_distributions
#  absl_random_internal_distribution_test_util
#  absl_random_internal_platform
#  absl_random_internal_pool_urbg
#  absl_random_internal_randen
#  absl_random_internal_randen_hwaes
#  absl_random_internal_randen_hwaes_impl
#  absl_random_internal_randen_slow
#  absl_random_internal_seed_material
#  absl_random_seed_gen_exception
#  absl_random_seed_sequences
#  absl_raw_hash_set
#  absl_raw_logging_internal
#  absl_scoped_set_env
#  absl_spinlock_wait
#  absl_stacktrace
#  absl_status
#  absl_statusor
#  absl_str_format_internal
#  absl_strerror
#  absl_string_view
#  absl_strings
#  absl_strings_internal
#  absl_symbolize
#  absl_synchronization
#  absl_throw_delegate
#  absl_time_zone
#  absl_vlog_config_internal
#
#  # the following libraries must be placed here for the correct link order.
#  absl_log_internal_format
#  absl_log_internal_globals
#  absl_log_globals
#  absl_debugging_internal
#  absl_time
#  absl_kernel_timeout_internal
#  absl_cordz_handle
#  absl_int128
#  absl_base
#  absl_malloc_internal
#)

find_path(absl_INCLUDE_DIR NAMES absl/base/config.h)

foreach(ABSLLIB ${ABSL_LIBS})
  set(ABSLLIB_NAME ${ABSLLIB}_LIBRARY)
  find_library(${ABSLLIB_NAME} NAMES ${ABSLLIB})
  list(APPEND ABSL_LIBRARIES ${ABSLLIB_NAME})
endforeach()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(absl REQUIRED_VARS absl_INCLUDE_DIR ${ABSL_LIBRARIES})

if(absl_FOUND)
  mark_as_advanced(absl_FOUND ${ABSL_LIBRARIES})
  set(absl_INCLUDE_DIRS "${absl_INCLUDE_DIR}")

  foreach(OTELLIB ${ABSL_LIBRARIES})
    list(APPEND absl_LIBRARIES ${${OTELLIB}})
  endforeach()
  message(STATUS "absl found: ${absl_LIBRARIES}")
  message(STATUS "absl include: ${absl_INCLUDE_DIRS}")

  if(NOT TARGET absl::absl)
    add_library(absl::absl STATIC IMPORTED)
    # set_target_properties(
    #   absl::absl PROPERTIES
    #   IMPORTED_LOCATION "${absl_LIBRARIES}"
    #   INTERFACE_INCLUDE_DIRECTORIES "${absl_INCLUDE_DIRS}"
    # )
    target_include_directories(absl::absl INTERFACE ${absl_INCLUDE_DIRS})
    target_link_libraries(absl::absl INTERFACE ${absl_LIBRARIES})
  endif()
endif()
