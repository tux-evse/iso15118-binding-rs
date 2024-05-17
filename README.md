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
desktop =>  echo "VETH_IPV6=$(ip -6 addr show dev veth-dbg | grep inet6 | awk '{print $2}' | awk -F '/' '{print $1}')"
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
### Firewall
You need to open:
* 1 UDP port for service discovery
* 2 TCP port for TCP & TLS

If using firewalld use following commands
```
firewall-cmd --list-all-zones # check in which zone your IFACE is located
firewall-cmd --zone=public --add-port=15118/udp --permanent
firewall-cmd --zone=public --add-port=:61341/tcp --permanent
firewall-cmd --zone=public --add-port=:64109/tcp --permanent
firewall-cmd  --reload
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

Send TCP data on loopback
```
socat -6 'TCP-CONNECT:[::1]:61341' stdio
```

Sending TLS data on loopback k (TCP/TLS only test)
```
# Do not check server certificate (sni require but not used)
socat -6 "OPENSSL-CONNECT:[::1]:64109,snihost=xxx,key=afb-test/certs/_client_key.pem,verify=0" stdio

# check server certificate (require /etc/hosts=> '::1 ipv6-localhost tux-evse-secure-by-iot-bzh')
socat -6 "OPENSSL-CONNECT:tux-evse-secure-by-iot-bzh:64109,snihost=tux-evse-secure-by-iot-bzh,key=afb-test/certs/_client_key.pem,cafile=afb-test/certs/_server_chain.pem,verify=1" stdio

# enforce tls 1.2 with server certificate check
socat -6 "OPENSSL-CONNECT:tux-evse-secure-by-iot-bzh:64109,snihost=tux-evse-secure-by-iot-bzh,key=afb-test/certs/_client_key.pem,cafile=afb-tt/certs/_server_chain.pem,verify=1,openssl-max-proto-version=TLS1.2" stdio

# enforce tls 1.3 with server certificate check
socat -6 "OPENSSL-CONNECT:tux-evse-secure-by-iot-bzh:64109,snihost=tux-evse-secure-by-iot-bzh,key=afb-test/certs/_client_key.pem,cafile=afb-tt/certs/_server_chain.pem,verify=1,openssl-min-proto-version=TLS1.3" stdio


# Fulup TBD check with Stephane to fix bash
export IFACE_EVSE=eth-xxx
export VETH_IPV6=`ip -6 addr show dev ${IFACE_EVSE} | grep inet6| grep fe80 | awk '{print $2}' | awk -F '/' '{print $1}'`; echo "VETH_IPV6=$VETH_IPV6"
socat -6 "OPENSSL-CONNECT:[${VETH_IPV6}%${IFACE_EVSE}]:64109,cert=afb-test/etc/_client-cert.pem,verify=0,openssl-min-proto-version=TLS1.3,snihost=tux-evse-secure-by-iot-bzh" stdio
socat -6 OPENSSL-CONNECT:[${VETH_IPV6}%${IFACE_EVSE}]:64109,cert=afb-test/etc/_client-cert.pem,cert=afb-test/etc/_trialog-oem-cert.pem,openssl-min-proto-version=TLS1.3 stdio

socat -6 "OPENSSL-CONNECT:[${VETH_IPV6}%${IFACE_EVSE}]:64109,cert=_trialog/vehicle20-chain.pem,verify=1,openssl-min-proto-version=TLS1.3,cafile=_trialog/v2g20RootCA.pem" stdio
```

Debugging target eth2
```
# ssh root@phytec-power.tuxevse.vpn "tcpdump -s0 -U -n -w - -i eth2" | wireshark -i -
```

Saving TLS preshare key with pcap file
```
editcap --inject-secrets tls,hello-tls-1.3.keylog  hello-tls-1.3.pcapng tls-hello-w-keys.pcapng
```

Create development testing certificate

Create a list of testing certificates. Certificate are prefix by '_' which prevent from uploading then with git.

```
./afb-test/certs/mkcerts.sh dest_dir
```


Trialog

Note: I had to unconnect/reconnect my ethernet laptop to get combo starting talking IPV6

```
# curl -X POST http://trialog-ipv4:15110/api/iec-1/bcb # Simulate BtoC toggle
# curl -X POST http://trialog-ipv4:15110/api/plugout # Simulate plugout
# curl -X POST http://trialog-ipv4:15110/api/plugin # Send SDP as IPV6 localink multicast```

Gnu Allocate credential  gnutls_certificate_allocate_credentials

# check certificate
 # reference: http://gnu.ist.utl.pt/software/gnutls/manual/html_node/Invoking-certtool.html
 certtool --load-certificate Trialog/certificates/certs/secc20Cert.pem -i

 # list cypher suite

 # default config 1.2+1.3
 gnutls-cli -l --priority "SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-ARCFOUR-128:+PSK:+DHE-PSK"

 # retrict to tls-1.2 only
 gnutls-cli -l --priority "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2:-VERS-TLS1.3"

# create chain of true from certificate list

# assemble chain of trust as a unique .pem
cat _trialog/secc20Cert.pem _trialog/cpo20SubCA2.pem _trialog/cpo20SubCA1.pem > _trialog/secc-chain.pem

# generate pk7s certificate chain
certtool --p7-generate --load-certificate _trialog/secc-chain.pem  >_trialog/secc-chain.pks7

# sign certificate chain
certtool --p7-sign --load-privkey _trialog/secc20Cert_key  --load-certificate _trialog/secc-chain.pks7  >_trialog/sess_chain.cert

# Generating a new certificate for Trialog
```
# generate private key
certtool --generate-privkey --outfile tux-evese-key.pem

# generate certificate request
certtool --generate-request --load-privkey tux-evese-key.pem --outfile tux-evese-csr.pem

# sign certificate
certtool --generate-certificate --load-request tux-evese-csr.pem --load-ca-certificate _trialog/v2g20RootCA.pem --load-ca-privkey _trialog/v2g20RootCA_key --outfile tux-evese-cert.pem

# verify generated certificate
 certtool --certificate-info --infile _trialog/secc-chain.pem
```
