FROM ubuntu:20.04

ENV LANG C

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      git build-essential autoconf libtool pkg-config \
      libssl-dev libpcre3-dev libcap-dev libluajit-5.1-dev libbrotli-dev python3 pipenv curl

#RUN git clone --depth 1 --branch json_access_log https://github.com/hnakamur/trafficserver
COPY . /trafficserver/

WORKDIR /trafficserver
RUN autoreconf -if
RUN ./configure --prefix=/usr
RUN make -j
RUN make install

WORKDIR /trafficserver/tests
RUN pipenv install
RUN pipenv run autest --ats-bin /usr/local/bin -f log-field
