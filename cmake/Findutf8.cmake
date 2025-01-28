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
#     utf8_LIBRARY
#     utf8_INCLUDE_DIRS
#
# and the following imported targets
#
#     utf8::utf8
#

set(UTF8_LIBS
    utf8_range
    utf8_validity
)

find_path(utf8_INCLUDE_DIR NAMES utf8_validity.h)

foreach(UTF8LIB ${UTF8_LIBS})
  set(UTF8LIB_NAME ${UTF8LIB}_LIBRARY)
  find_library(${UTF8LIB_NAME} NAMES ${UTF8LIB})
  list(APPEND UTF8_LIBRARIES ${UTF8LIB_NAME})
endforeach()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(utf8 REQUIRED_VARS utf8_INCLUDE_DIR ${UTF8_LIBRARIES})

if(utf8_FOUND)
  mark_as_advanced(utf8_FOUND ${UTF8_LIBRARIES})
  set(utf8_INCLUDE_DIRS "${utf8_INCLUDE_DIR}")

  foreach(OTELLIB ${UTF8_LIBRARIES})
    list(APPEND utf8_LIBRARIES ${${OTELLIB}})
  endforeach()
  message(STATUS "utf8 found: ${utf8_LIBRARIES}")
  message(STATUS "utf8 include: ${utf8_INCLUDE_DIRS}")

  if(NOT TARGET utf8::utf8)
    add_library(utf8::utf8 INTERFACE IMPORTED)
    target_include_directories(utf8::utf8 INTERFACE ${utf8_INCLUDE_DIRS})
    target_link_libraries(utf8::utf8 INTERFACE ${utf8_LIBRARIES})
  endif()
endif()
