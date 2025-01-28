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

# Findupb.cmake
#
# This will define the following variables
#
#     upb_FOUND
#     upb_LIBRARY
#     upb_INCLUDE_DIRS
#
# and the following imported targets
#
#     upb::upb
#

set(UPB_LIBS
    upb
)

find_path(upb_INCLUDE_DIR NAMES upb/generated_code_support.h)

foreach(UPBLIB ${UPB_LIBS})
  set(UPBLIB_NAME ${UPBLIB}_LIBRARY)
  find_library(${UPBLIB_NAME} NAMES ${UPBLIB})
  list(APPEND UPB_LIBRARIES ${UPBLIB_NAME})
endforeach()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(upb REQUIRED_VARS upb_INCLUDE_DIR ${UPB_LIBRARIES})

if(upb_FOUND)
  mark_as_advanced(upb_FOUND ${UPB_LIBRARIES})
  set(upb_INCLUDE_DIRS "${upb_INCLUDE_DIR}")

  foreach(OTELLIB ${UPB_LIBRARIES})
    list(APPEND upb_LIBRARIES ${${OTELLIB}})
  endforeach()
  message(STATUS "upb found: ${upb_LIBRARIES}")
  message(STATUS "upb include: ${upb_INCLUDE_DIRS}")

  if(NOT TARGET upb::upb)
    add_library(upb::upb INTERFACE IMPORTED)
    target_include_directories(upb::upb INTERFACE ${upb_INCLUDE_DIRS})
    target_link_libraries(upb::upb INTERFACE ${upb_LIBRARIES})
  endif()
endif()
