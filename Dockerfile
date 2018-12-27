FROM ubuntu:18.04

RUN ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime \
 && sed -i 's/^# deb-src/deb-src/' /etc/apt/sources.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get build-dep -y trafficserver \
 && useradd -r -m -s /bin/bash build

USER build
RUN mkdir -p ~/dev/trafficserver
COPY --chown=build:build . /home/build/dev/trafficserver/

RUN cd ~/dev/trafficserver \
 && autoreconf -if \
 && ./configure --with-brotli=/usr/include

CMD ["/bin/grep", "HAVE_BROTLI_ENCODE_H", "/home/build/dev/trafficserver/include/ink_autoconf.h"]
