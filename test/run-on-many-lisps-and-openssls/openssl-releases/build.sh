#!/bin/sh

curdir="$(dirname "$0")"
mkdir "${curdir}/bin"
cd "${curdir}/bin"
bindirabs=`pwd -P` # absolute path to bindir

cd ../src

VERSIONS="$1"
if [ -z "$VERSIONS" ]
then
  VERSIONS="openssl-0.9.8zh openssl-1.0.0s openssl-1.0.2q openssl-1.1.0j openssl-1.1.1a"
fi

ARCH="$2"
if [ -z "$ARCH" ]
then
  ARCH="x86_64"
fi

for srcdir in $VERSIONS
do
  cd $srcdir
  ./Configure shared --prefix="${bindirabs}/${srcdir}-${ARCH}" --openssldir="${bindirabs}/${srcdir}-${ARCH}" "linux-${ARCH}"
  make clean
  make && make install
  cd ..
done


