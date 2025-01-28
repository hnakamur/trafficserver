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

# Findprotobuf.cmake
#
# This will define the following variables
#
#     protobuf_FOUND
#     protobuf_LIBRARY
#     protobuf_INCLUDE_DIRS
#
# and the following imported targets
#
#     protobuf::protobuf
#

set(PROTOBUF_LIBS
    protobuf
)

find_path(protobuf_INCLUDE_DIR NAMES google/protobuf/any.h)

foreach(PROTOBUFLIB ${PROTOBUF_LIBS})
  set(PROTOBUFLIB_NAME ${PROTOBUFLIB}_LIBRARY)
  find_library(${PROTOBUFLIB_NAME} NAMES ${PROTOBUFLIB})
  list(APPEND PROTOBUF_LIBRARIES ${PROTOBUFLIB_NAME})
endforeach()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(protobuf REQUIRED_VARS protobuf_INCLUDE_DIR ${PROTOBUF_LIBRARIES})

if(protobuf_FOUND)
  mark_as_advanced(protobuf_FOUND ${PROTOBUF_LIBRARIES})
  set(protobuf_INCLUDE_DIRS "${protobuf_INCLUDE_DIR}")

  foreach(OTELLIB ${PROTOBUF_LIBRARIES})
    list(APPEND protobuf_LIBRARIES ${${OTELLIB}})
  endforeach()
  message(STATUS "protobuf found: ${protobuf_LIBRARIES}")
  message(STATUS "protobuf include: ${protobuf_INCLUDE_DIRS}")

  if(NOT TARGET protobuf::protobuf)
    add_library(protobuf::protobuf INTERFACE IMPORTED)
    target_include_directories(protobuf::protobuf INTERFACE ${protobuf_INCLUDE_DIRS})
    target_link_libraries(protobuf::protobuf INTERFACE ${protobuf_LIBRARIES})
  endif()
endif()
