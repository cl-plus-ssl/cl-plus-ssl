#!/bin/bash

curdir="`dirname $0`"
mkdir "${curdir}/bin"
cd bin
bindirabs=`pwd -P` # absolute path to bindir
cd ..

for srcdir in openssl-0.9.8zh openssl-1.0.0s openssl-1.0.2q openssl-1.1.0j openssl-1.1.1a
do
  cd $srcdir
  make clean
  ./config shared --prefix="${bindirabs}/${srcdir}" --openssldir="${bindirabs}/${srcdir}"
  make && make install
  cd ..
done


