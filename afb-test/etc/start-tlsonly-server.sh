#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/lib64
pkill afb-iso15118
cynagora-admin set '' 'HELLO' '' '*' yes
clear

# build test config dirname
DIRNAME=`dirname $0`
cd $DIRNAME/..
ROOTDIR=`pwd`
CONFDIR=`pwd`/etc
mkdir -p /tmp/api

if test -z "$DEVTOOL_PORT"; then
    DEVTOOL_PORT=1235
fi

if test -z "$IFACE"; then
export IFACE=veth-dbg
fi

if test -z "$PKI_TLS_DIR"; then
export PKI_TLS_DIR=$CONFDIR
fi

echo iso15118 debug mode iface=$IFACE config=$CONFDIR/*.json port=$DEVTOOL_PORT

afb-binder --name=afb-iso15118 --port=$DEVTOOL_PORT -v \
  --config=$ROOTDIR/../afb-binding/etc/binder-iso15118.json \
  --config=$ROOTDIR/../afb-binding/etc/binding-iso15118.json \
  --config=$CONFDIR/binding-iso15118-loopbk.json \
  $*