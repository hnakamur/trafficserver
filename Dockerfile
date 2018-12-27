FROM ubuntu:18.04

# Install packages to build trafficserver
RUN ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime \
 && sed -i 's/^# deb-src/deb-src/' /etc/apt/sources.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get build-dep -y trafficserver \
 && useradd -r -m -s /bin/bash build

USER build

# Get the source and configure trafficserver
RUN mkdir -p ~/dev/trafficserver

# Copy trafficserver source
COPY --chown=build:build . /home/build/dev/trafficserver/

USER root
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER build
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
