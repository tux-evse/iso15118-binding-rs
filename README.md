## Resources:

https://www.typhoon-hil.com/documentation/typhoon-hil-software-manual/References/iso15118_protocol.html

iso15118-schemas: https://standards.iso.org/iso/15118/

## Debug

Sending multicast IPV6

Note: will only work from an other station connected in locallink
```
echo "Hi there, IPV6!" | socat STDIO UDP6-DATAGRAM:[ff02::01]:15118
```

Send TCP data
```
socat -6 'TCP-CONNECT:[::1]:61341' stdio
```

Sending TLS data
```
socat -6 'OPENSSL-CONNECT:[::1]:64109,cert=_client-cert.pem,verify=0' stdio```

## Fulup TBD



GNUTLS

