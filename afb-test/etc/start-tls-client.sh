#!/bin/sh

cd `dirname $0`

REMOTE='[::1]'
PORT=64109

SVR_CERT="server-cert.crt"
CLT_CERT="client-cert.pem"

echo "IPV6 TLS client test REMOTE=$REMOTE PORT=$PORT"
#socat -v -6 "OPENSSL-CONNECT:$REMOTE:$PORT,cert=$CLT_CERT,cafile=$SVR_CERT" stdio
socat -v -6 "OPENSSL-CONNECT:$REMOTE:$PORT,cert=$CLT_CERT" stdio
