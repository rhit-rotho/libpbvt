FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update
RUN apt install -y build-essential cmake docutils-common git python3 pkg-config libdwarf-dev libelf-dev

RUN git clone https://github.com/antoyo/libelfin && cd libelfin && make && make install && cd ..
RUN git clone https://github.com/plasma-umass/coz && cd coz && cmake . && make && make install && cd ..
RUN ldconfig
