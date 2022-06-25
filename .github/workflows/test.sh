#!/bin/bash
#
# Just a one-liner script to avoid repeating so many parameters in many `run` sections of the test.yml
# Assumes the current directory is ${{ github.workspace }}.

docker run -e LISP -e LIB_LOAD_MODE -e OPENSSL -e BITS -u "$(id -u):$(id -g)" -i --mount type=bind,source=./docker-home,target=/home/cl/ clfoundation/cl-devel:2022-02-09 /home/cl/cl-plus-ssl/test/run-for-ci.sh
