#!/bin/bash

# safe mode
set -euo pipefail

# verbose
set -v

cd "`dirname $0`"

if [ ! -v OPENSSL_RELEASES_BIN_DIR ]
then
    # assume it's not a container, but the dev machine and the openssl binaries
    # are built right in this subdirectory
    export OPENSSL_RELEASES_BIN_DIR=run-on-many-lisps-and-openssls/openssl-releases/bin
fi

#~/unpacked/ccl-1.11/lx86cl64 --load run-for-ci.lisp
ccl --load run-for-ci.lisp
