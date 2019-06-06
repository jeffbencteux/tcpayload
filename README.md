# tcpayload

A small TCP wrapper around Scapy

# What is it for ?

Send TCP payloads with custom parameters.

# What can I customize ?

* Payload, as an ASCII string or bytestring with escaped characters
* Size and number of segments sent via the `--mss` option
* Source and destination ports
* Initial segment number (ISN) via the `--isn` option
* Connection ending : either with FIN segment `--endswith-fin` or with RST segment `--endswith-rst`
* Delay between the segments via `--sleep` option

# Exemples

Send an Hello world to a local HTTP server: 

`./tcpayload.py -p "Hello world" 127.0.0.1 127.0.0.1 80`

Send a payload in a very customized way:

`./tcpayload.py -p "my_payload" --endswith-rst --isn 1234 --sleeptime 5 --mss 5 192.168.0.1 192.168.0.2 6666`

# Troubleshooting

## I have a python stacktrace with an "Operation not permitted" error

Scapy needs to open a raw socket, either you grant privileges to the script to do so with capabilities (see [here](https://stackoverflow.com/questions/36215201/python-scapy-sniff-without-root)) or you execute it as root.

## I get unwanted RST packets when using the script

The kernel stack does not keep Scapy's opened connections and so send these unwanted packets (see [here](https://stackoverflow.com/questions/9058052/unwanted-rst-tcp-packet-with-scapy)), you can add an iptables rules to avoid these.
