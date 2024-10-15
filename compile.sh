#!/bin/bash

rm -rf build sniffer
mkdir build
cd build
cmake ..
make