# UDP-over-TCP

Sandhole has experimental support for UDP over SSH, with a thin TCP-based protocol.

Provided that the Sandhole instance that you wish to connect to has UDP enabled, the quickest way to get UDP running is with the [`udp_over_tcp.py` client provided in the Sandhole repository](https://github.com/EpicEric/sandhole/blob/main/udp_over_tcp.py):

```bash
wget https://raw.githubusercontent.com/EpicEric/sandhole/refs/heads/main/udp_over_tcp.py
python3 udp_over_tcp.py --udp-port 12345 --tcp-port 6789
```

This will create a TCP server listening on port 6789 which proxies UDP-over-TCP data to port 12345.

In order to create an UDP socket on port 9999 of Sandhole, use the reserved `udp.sandhole` remote host:

```bash
ssh -p 2222 -R udp.sandhole:9999:localhost:6789 sandhole.com.br
```

Make sure that you're pointing to the local TCP port created from teh script above.

## Limitations

Common issues associated with UDP-over-TCP (increased latency and jitter, TCP Meltdown) apply to Sandhole as well.

## Technical details

Since UDP is a protocol based on datagrams, the only extra information added by the translation layer is the number of bytes in the datagram, to ensure that it's reassembled correctly on both ends even if TCP splits or merges data.

State is handled by associating each UDP socket with an SSH forwarding channel. As such, a compatible client can translate TCP listeners to UDP socket connections one-to-one.
