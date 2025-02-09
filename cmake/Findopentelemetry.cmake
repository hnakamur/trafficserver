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

# Findopentelemetry.cmake
#
# This will define the following variables
#
#     opentelemetry_FOUND
#     opentelemetry_exporter_ostream_span_LIBRARY
#     opentelemetry_exporter_otlp_http_LIBRARY
#     opentelemetry_exporter_otlp_http_client_LIBRARY
#     opentelemetry_http_client_curl_LIBRARY
#     opentelemetry_logs_LIBRARY
#     opentelemetry_metrics_LIBRARY
#     opentelemetry_otlp_recordable_LIBRARY
#     opentelemetry_proto_LIBRARY
#     opentelemetry_resources_LIBRARY
#     opentelemetry_trace_LIBRARY
#     opentelemetry_version_LIBRARY
#     opentelemetry_common_LIBRARY
#     opentelemetry_INCLUDE_DIRS
#
# and the following imported targets
#
#     opentelemetry::opentelemetry_exporter_ostream_span
#     opentelemetry::opentelemetry_exporter_otlp_http
#     opentelemetry::opentelemetry_exporter_otlp_http_client
#     opentelemetry::opentelemetry_http_client_curl
#     opentelemetry::opentelemetry_logs
#     opentelemetry::opentelemetry_metrics
#     opentelemetry::opentelemetry_otlp_recordable
#     opentelemetry::opentelemetry_proto
#     opentelemetry::opentelemetry_resources
#     opentelemetry::opentelemetry_trace
#     opentelemetry::opentelemetry_version
#     opentelemetry::opentelemetry_common
#

find_library(opentelemetry_exporter_ostream_span_LIBRARY NAMES opentelemetry_exporter_ostream_span)
find_library(opentelemetry_exporter_otlp_http_LIBRARY NAMES opentelemetry_exporter_otlp_http)
find_library(opentelemetry_exporter_otlp_http_client_LIBRARY NAMES opentelemetry_exporter_otlp_http_client)
find_library(opentelemetry_http_client_curl_LIBRARY NAMES opentelemetry_http_client_curl)
find_library(opentelemetry_logs_LIBRARY NAMES opentelemetry_logs)
find_library(opentelemetry_metrics_LIBRARY NAMES opentelemetry_metrics)
find_library(opentelemetry_otlp_recordable_LIBRARY NAMES opentelemetry_otlp_recordable)
find_library(opentelemetry_proto_LIBRARY NAMES opentelemetry_proto)
find_library(opentelemetry_resources_LIBRARY NAMES opentelemetry_resources)
find_library(opentelemetry_trace_LIBRARY NAMES opentelemetry_trace)
find_library(opentelemetry_version_LIBRARY NAMES opentelemetry_version)
find_library(opentelemetry_common_LIBRARY NAMES opentelemetry_common)
find_path(opentelemetry_INCLUDE_DIR NAMES opentelemetry/version.h)

mark_as_advanced(
  opentelemetry_FOUND
  opentelemetry_exporter_ostream_span_LIBRARY
  opentelemetry_exporter_otlp_http_LIBRARY
  opentelemetry_exporter_otlp_http_client_LIBRARY
  opentelemetry_http_client_curl_LIBRARY
  opentelemetry_logs_LIBRARY
  opentelemetry_metrics_LIBRARY
  opentelemetry_otlp_recordable_LIBRARY
  opentelemetry_proto_LIBRARY
  opentelemetry_resources_LIBRARY
  opentelemetry_trace_LIBRARY
  opentelemetry_version_LIBRARY
  opentelemetry_common_LIBRARY
  absl_INCLUDE_DIR
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(opentelemetry REQUIRED_VARS opentelemetry_INCLUDE_DIR ${OTEL_LIBRARIES})

if(opentelemetry_FOUND)
  set(opentelemetry_INCLUDE_DIRS "${opentelemetry_INCLUDE_DIR}")
endif()

if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_exporter_ostream_span)
  add_library(opentelemetry::opentelemetry_exporter_ostream_span STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_exporter_ostream_span
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}"
               IMPORTED_LOCATION "${opentelemetry_exporter_ostream_span_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_exporter_otlp_http)
  add_library(opentelemetry::opentelemetry_exporter_otlp_http STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_exporter_otlp_http
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}"
               IMPORTED_LOCATION "${opentelemetry_exporter_otlp_http_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_exporter_otlp_http_client)
  add_library(opentelemetry::opentelemetry_exporter_otlp_http_client STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_exporter_otlp_http_client
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}"
               IMPORTED_LOCATION "${opentelemetry_exporter_otlp_http_client_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_http_client_curl)
  add_library(opentelemetry::opentelemetry_http_client_curl STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_http_client_curl
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                            "${opentelemetry_http_client_curl_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_logs)
  add_library(opentelemetry::opentelemetry_logs STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_logs PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}"
                                                 IMPORTED_LOCATION "${opentelemetry_logs_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_metrics)
  add_library(opentelemetry::opentelemetry_metrics STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_metrics PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}"
                                                    IMPORTED_LOCATION "${opentelemetry_metrics_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_otlp_recordable)
  add_library(opentelemetry::opentelemetry_otlp_recordable STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_otlp_recordable
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                            "${opentelemetry_otlp_recordable_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_proto)
  add_library(opentelemetry::opentelemetry_proto STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_proto PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}"
                                                  IMPORTED_LOCATION "${opentelemetry_proto_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_resources)
  add_library(opentelemetry::opentelemetry_resources STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_resources PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}"
                                                      IMPORTED_LOCATION "${opentelemetry_resources_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_trace)
  add_library(opentelemetry::opentelemetry_trace STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_trace PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}"
                                                  IMPORTED_LOCATION "${opentelemetry_trace_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_version)
  add_library(opentelemetry::opentelemetry_version STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_version PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}"
                                                    IMPORTED_LOCATION "${opentelemetry_version_LIBRARY}"
  )
endif()
if(opentelemetry_FOUND AND NOT TARGET opentelemetry::opentelemetry_common)
  add_library(opentelemetry::opentelemetry_common STATIC IMPORTED)
  set_target_properties(
    opentelemetry::opentelemetry_common PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${opentelemetry_INCLUDE_DIR}"
                                                   IMPORTED_LOCATION "${opentelemetry_common_LIBRARY}"
  )
endif()
