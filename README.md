## Resources:

https://www.typhoon-hil.com/documentation/typhoon-hil-software-manual/References/iso15118_protocol.html
iso15118-schemas: https://standards.iso.org/iso/15118/

## Set up tls/pki configuration

TLS requires private/public keys certificate. You may use afb-test/etc/tlspki-cert-gen.sh to generate
development certificates. Depending on corticate/keys location you may have to update testing config.json
files. Before starting afb-binder

```
./afb-test/etc/pkitls-cert-gen.sh
./afb-test/etc/server-iso-start.sh
```

## Debug natively your remote target

In order to do so, you should tunnel codico/eth2 interface from the target
to your development desktop. Tunneling configuration is and corresponding
scripts are available from slac-binding-rs/afb-test/etc directory.

```
target  => sudo ./afb-test/etc/server-eth2-tap.sh
desktop => sudo ./afb-test/etc/client-eth2-tap.sh
```

IPV6 local-link. For ISO15118 remote debug to work you need a valid ipv6 addr
on you desktop veth-dbg that should be ping able from your bord.
```
desktop =>  ip -6 addr show dev veth-dbg | grep inet6
target  =>  ping -I br0-tun fe80::xxxxxxxx
```


When configuration is in place on your desktop
```
wireshark -i veth-dbg
./afb-test/etc/start-iso15118-server.sh
```

Warning:
 * Slac require CAP_NET_RAW capability, check slac-binding-rs/README.md
for further information.
 * Firewall: you should open USP port 15118 and allow ipv6:multicast both on your target and on your development Desktop.
```
sudo setcap cap_net_raw+eip /usr/local/bin/afb-binder
```
## Using Socat to send IPV6 probes

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
socat -6 'OPENSSL-CONNECT:[::1]:64109,cert=_client-cert.pem,verify=0' stdio
```


