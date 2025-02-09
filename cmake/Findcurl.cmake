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

# Findcurl.cmake
#
# This will define the following variables
#
#     curl_FOUND
#     curl_LIBRARY
#     curl_INCLUDE_DIRS
#
# and the following imported targets
#
#     curl::curl
#

find_library(curl_LIBRARY NAMES curl)
find_path(curl_INCLUDE_DIR NAMES curl/curl.h)

mark_as_advanced(curl_FOUND curl_LIBRARY curl_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(curl REQUIRED_VARS curl_LIBRARY curl_INCLUDE_DIR)

if(curl_FOUND)
  set(curl_INCLUDE_DIRS "${curl_INCLUDE_DIR}")
endif()

if(curl_FOUND AND NOT TARGET curl::curl)
  add_library(curl::curl STATIC IMPORTED)
  set_target_properties(
    curl::curl PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${curl_INCLUDE_DIRS}" IMPORTED_LOCATION "${curl_LIBRARY}"
  )
endif()
