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

# Findutf8.cmake
#
# This will define the following variables
#
#     utf8_FOUND
#     utf8_range_LIBRARY
#     utf8_validity_LIBRARY
#     utf8_INCLUDE_DIRS
#
# and the following imported targets
#
#     utf8::utf8_range
#     utf8::utf8_validity
#

find_library(utf8_range_LIBRARY NAMES utf8_range)
find_library(utf8_validity_LIBRARY NAMES utf8_validity)
find_path(utf8_INCLUDE_DIR NAMES utf8_validity.h)

mark_as_advanced(utf8_FOUND utf8_range_LIBRARY utf8_validity_LIBRARY utf8_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(utf8 REQUIRED_VARS utf8_INCLUDE_DIR ${UTF8_LIBRARIES})

if(utf8_FOUND)
  set(utf8_INCLUDE_DIRS "${utf8_INCLUDE_DIR}")
endif()

if(utf8_FOUND AND NOT TARGET utf8::utf8_range)
  add_library(utf8::utf8_range STATIC IMPORTED)
  set_target_properties(
    utf8::utf8_range PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${utf8_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                    "${utf8_range_LIBRARY}"
  )
endif()
if(utf8_FOUND AND NOT TARGET utf8::utf8_validity)
  add_library(utf8::utf8_validity STATIC IMPORTED)
  set_target_properties(
    utf8::utf8_validity PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${utf8_INCLUDE_DIR}" IMPORTED_LOCATION
                                                                                       "${utf8_validity_LIBRARY}"
  )
endif()
