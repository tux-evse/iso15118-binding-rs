Testing tls certificate:

1) With a valid server certificate
  # in this case server CN should match remote hostname/ip
  socat -v 'OPENSSL-CONNECT:localhost:4443,cert=_client-cert.pem,cafile=_server-cert.crt' stdio

2) ignore server certificate
  # server certificate not needed
  socat -v 'OPENSSL-CONNECT:localhost:4443,cert=_client-cert.pem,verify=0' stdio