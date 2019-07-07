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

BITNESSES="$2"
if [ -z "$BITNESSES" ]
then
  BITNESSES="32 64"
fi

for srcdir in $VERSIONS
do
  cd $srcdir
  for bits in $BITNESSES
  do
    if [ "$bits" = "32" ]
    then
      extraflags="-m32 -L-m32"
      target="linux-generic32"
    else
      extraflags=""
      target="linux-x86_64"
    fi
    ./Configure "$extraflags" shared --prefix="${bindirabs}/${srcdir}-${bits}bit" --openssldir="${bindirabs}/${srcdir}-${bits}bit" "$target"
    make clean
    make && make install
  done
  cd ..
done


