#!/usr/bin/env bash

cd ..
mkdir -p build && cd build
cmake .. -DABY_BUILD_EXE=On
make