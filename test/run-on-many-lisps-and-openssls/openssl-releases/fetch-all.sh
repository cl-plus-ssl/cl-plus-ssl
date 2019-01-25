#!/bin/sh
cd "`dirname $0`"

wget https://www.openssl.org/source/openssl-1.0.2q.tar.gz
tar -xzf openssl-1.0.2q.tar.gz
wget https://www.openssl.org/source/openssl-1.1.0j.tar.gz
tar -xzf openssl-1.1.0j.tar.gz
wget https://www.openssl.org/source/openssl-1.1.1a.tar.gz
tar -xzf openssl-1.1.1a.tar.gz
wget https://www.openssl.org/source/old/1.0.0/openssl-1.0.0s.tar.gz
tar -xzf openssl-1.0.0s.tar.gz
wget https://www.openssl.org/source/old/0.9.x/openssl-0.9.8zh.tar.gz
tar -xzf openssl-0.9.8zh.tar.gz
