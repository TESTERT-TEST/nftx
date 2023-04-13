#!/bin/bash
export HOST=x86_64-w64-mingw32
CXX=x86_64-w64-mingw32-g++-posix
CC=x86_64-w64-mingw32-gcc-posix
PREFIX="$(pwd)/depends/$HOST"

set -eu -o pipefail

UTIL_DIR="$(dirname "$(readlink -f "$0")")"
BASE_DIR="$(dirname "$(readlink -f "$UTIL_DIR")")"
PREFIX="$BASE_DIR/depends/$HOST"

# disable for code audit
# If --enable-websockets is the next argument, enable websockets support for nspv clients:
WEBSOCKETS_ARG=''
# if [ "x${1:-}" = 'x--enable-websockets' ]
# then
# WEBSOCKETS_ARG='--enable-websockets=yes'
# shift
# fi

# make dependences
cd depends/ && make HOST=$HOST V=1 NO_QT=1
cd ../

cd $BASE_DIR/depends
make HOST=$HOST NO_QT=1 "$@"
cd $BASE_DIR

./autogen.sh
CONFIG_SITE=$BASE_DIR/depends/$HOST/share/config.site CXXFLAGS="-DPTW32_STATIC_LIB -DCURL_STATICLIB -DCURVE_ALT_BN128 -fopenmp -pthread" ./configure --prefix=$PREFIX --host=$HOST --enable-static --disable-shared "$WEBSOCKETS_ARG" \
  --with-custom-bin=yes CUSTOM_BIN_NAME=nftx CUSTOM_BRAND_NAME=NFTX \
  CUSTOM_SERVER_ARGS="'-ac_name=NFTX -ac_supply=0 -ac_reward=100000000 -ac_halving=72000 -ac_adaptivepow=6 -ac_cc=111 -ac_staked=50 -addnode=node.nftx.pw -addnode=node1.nftx.pw -addnode=node2.nftx.pw -addnode=node3.nftx.pw -addnode=node4.nftx.pw -addnode=node5.nftx.pw -addnode=electrum.nftx.pw -addnode=electrum2.nftx.pw -addnode=electrum3.nftx.pw -nspv_msg=1'" \
  CUSTOM_CLIENT_ARGS='-ac_name=NFTX'
sed -i 's/-lboost_system-mt /-lboost_system-mt-s /' configure 
  
cd src/
# note: to build alysidesd, alysides-cli it should not exist 'komodod.exe komodo-cli.exe' param here:
CC="${CC} -g " CXX="${CXX} -g " make V=1    
