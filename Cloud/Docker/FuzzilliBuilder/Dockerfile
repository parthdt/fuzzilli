FROM swift:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV SHELL=bash

RUN apt-get -y update && apt-get -y upgrade
RUN useradd -m builder

WORKDIR /home/builder

ADD fuzzilli fuzzilli

ENV LD_LIBRARY_PATH=/home/builder/fuzzilli/Sources/libafl/

RUN cd fuzzilli && swift build -c release
