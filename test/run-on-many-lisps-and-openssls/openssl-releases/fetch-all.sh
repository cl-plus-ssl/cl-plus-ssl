#!/bin/sh
cd "$(dirname "$0")"

mkdir src
cd src

VERSIONS="$1"
if [ -z "$VERSIONS" ]
then
  VERSIONS="openssl-0.9.8zh openssl-1.0.0s openssl-1.0.2q openssl-1.1.0j openssl-1.1.1a"
fi

downloadUrl() {
  version="$1"
  case $version in
      openssl-1.0.2q|openssl-1.1.0j|openssl-1.1.1a)
          echo "https://www.openssl.org/source/${version}.tar.gz";;
      openssl-1.0.0s)
          echo "https://www.openssl.org/source/old/1.0.0/openssl-1.0.0s.tar.gz";;
      openssl-0.9.8zh)
          echo "https://www.openssl.org/source/old/0.9.x/openssl-0.9.8zh.tar.gz";;
  esac
}

for version in $VERSIONS
do
  wget $(downloadUrl "$version")
  tar -xzf "${version}.tar.gz"
done
