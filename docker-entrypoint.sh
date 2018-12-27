#!/bin/sh
set -e

cd ~/dev/trafficserver
autoreconf -if
./configure
/bin/grep HAVE_BROTLI_ENCODE_H /home/build/dev/trafficserver/include/ink_autoconf.h
