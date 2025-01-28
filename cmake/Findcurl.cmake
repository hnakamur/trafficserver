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

set(CURL_LIBS
    curl
)

find_path(curl_INCLUDE_DIR NAMES curl/curl.h)

foreach(CURLLIB ${CURL_LIBS})
  set(CURLLIB_NAME ${CURLLIB}_LIBRARY)
  find_library(${CURLLIB_NAME} NAMES ${CURLLIB})
  list(APPEND CURL_LIBRARIES ${CURLLIB_NAME})
endforeach()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(curl REQUIRED_VARS curl_INCLUDE_DIR ${CURL_LIBRARIES})

if(curl_FOUND)
  mark_as_advanced(curl_FOUND ${CURL_LIBRARIES})
  set(curl_INCLUDE_DIRS "${curl_INCLUDE_DIR}")

  foreach(OTELLIB ${CURL_LIBRARIES})
    list(APPEND curl_LIBRARIES ${${OTELLIB}})
  endforeach()
  message(STATUS "curl found: ${curl_LIBRARIES}")
  message(STATUS "curl include: ${curl_INCLUDE_DIRS}")

  if(NOT TARGET curl::curl)
    add_library(curl::curl INTERFACE IMPORTED)
    target_include_directories(curl::curl INTERFACE ${curl_INCLUDE_DIRS})
    target_link_libraries(curl::curl INTERFACE ${curl_LIBRARIES})
  endif()
endif()
