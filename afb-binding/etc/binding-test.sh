#!/bin/bash

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"
clear

if ! test -f $CARGO_TARGET_DIR/debug/libafb_iso15118.so; then
    echo "FATAL: missing libafb_iso15118.so use: cargo build"
    exit 1
fi

# start binder with test config
afb-binder -v \
   --config=afb-binding/etc/binder-iso15118.json \
   --config=afb-binding/etc/binding-iso15118.json \
   $*
