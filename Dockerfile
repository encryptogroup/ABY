FROM debian:13 AS build

RUN apt-get update -y
RUN apt-get install -y build-essential cmake libgmp-dev libssl-dev doxygen libboost-all-dev

COPY . aby

RUN cd aby && mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DABY_BUILD_EXE=On && make

ENTRYPOINT ["/aby/entrypoint.sh"]
