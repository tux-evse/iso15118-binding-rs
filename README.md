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

check ipv6 multicast routes
```
export IFACE=ethX
ip -6 route show table all type multicast table local
sudo ip route add multicast ff00::/8 dev $IFACE table local metric 100
ip -6 route get ff02::01
```

Sending multicast IPV6

Note: will only work from an other station connected in locallink
```
# mock SDP request TCP/TLS
echo -e '\x01\xfe\x90\x00\x00\x00\x00\x02\x00\x00' | socat STDIO UDP6-DATAGRAM:'[ff02::01]':15118
```

Testing IPV6 multicast listeners
```
export IFACE=ethX
socat -u UDP6-RECV:15118,ipv6-add-membership='[ff02::01]':$IFACE -
```

Send TCP data
```
socat -6 'TCP-CONNECT:[::1]:61341' stdio
```

Sending TLS data
```
socat -6 'OPENSSL-CONNECT:[::1]:64109,cert=_client-cert.pem,verify=0' stdio
```

Debugging target eth2
```
ssh root@phytec-power.tuxevse.vpn "tcpdump -s0 -U -n -w - -i eth2" | wireshark -i -
```
