#!/usr/bin/env python3
import argparse
import asyncio


# -- Proxying protocol --
class TcpProxyProtocol(asyncio.Protocol):
    udp_transport = None
    data_len = (0, 0)
    data = b""
    buffered_data = None
    udp_address = None

    def data_received(self, data):
        # Re-assemble datagrams from TCP data
        while data:
            # Compute datagram length
            if self.data_len[0] < 2:
                self.data_len = (
                    self.data_len[0] + 1,
                    (self.data_len[1] << 8) + data[0],
                )
                data = data[1:]
                continue

            # Consume data to fill the datagram
            data_to_take = min(self.data_len[1] - len(self.data), len(data))
            self.data += data[:data_to_take]
            data = data[data_to_take:]

            # Check whether we have a full datagram
            if len(self.data) == self.data_len[1]:
                if self.udp_transport:
                    self.udp_transport.sendto(self.data, self.udp_address)
                elif self.buffered_data is not None:
                    # UDP is not connected yet; save to buffer
                    self.buffered_data.append(self.data)
                self.data_len = (0, 0)
                self.data = b""


class UdpProxyProtocol(asyncio.Protocol):
    tcp_transport = None
    buffered_data = None
    last_addr = None

    def datagram_received(self, data, addr):
        self.last_addr = addr
        # Add datagram size to start of data
        datagram = bytes((len(data) >> 8, len(data) & 0xFF)) + data
        # Send to the connected TCP socket
        if self.tcp_transport:
            self.tcp_transport.write(datagram)
        elif self.buffered_data is not None:
            # TCP is not connected yet; save to buffer
            self.buffered_data.append(datagram)


# -- Remote forwarding --
class TcpServerProtocol(TcpProxyProtocol):
    def __init__(self, udp_address, udp_port):
        self.udp_address = udp_address
        self.udp_port = udp_port
        self.task = None
        self.tcp_transport = None
        self.on_connection_lost = asyncio.get_running_loop().create_future()
        self.buffered_data = []

    def connection_made(self, transport):
        self.tcp_transport = transport
        self.task = asyncio.get_running_loop().create_task(self._connect_to_udp())

    def connection_lost(self, exc):
        if self.task:
            self.task.cancel()
        if not self.on_connection_lost.done():
            self.on_connection_lost.set_result(True)

    async def _connect_to_udp(self):
        loop = asyncio.get_running_loop()
        udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: UdpClientProtocol(self.tcp_transport),
            remote_addr=(self.udp_address, self.udp_port),
        )
        self.udp_transport = udp_transport

        for buffered in self.buffered_data:
            self.udp_transport.sendto(buffered)
        self.buffered_data = []

        try:
            await self.on_connection_lost
        finally:
            udp_transport.close()


class UdpClientProtocol(UdpProxyProtocol):
    def __init__(self, tcp_transport):
        self.tcp_transport = tcp_transport
        self.buffered_data = []


# -- Local forwarding --
class TcpClientProtocol(TcpProxyProtocol):
    def __init__(self, udp_protocol, udp_transport, udp_address):
        self.udp_protocol = udp_protocol
        self.udp_transport = udp_transport
        self.udp_address = udp_address

    def connection_made(self, transport):
        # Signal that this client is ready to receive messages
        self.udp_protocol.tcp_transport = transport
        for buffered in self.udp_protocol.buffered_data:
            transport.write(buffered)
        self.udp_protocol.buffered_data = []

    def connection_lost(self, exc):
        # Signal that this client can no longer receive messages
        self.udp_protocol.tcp_transport = None
        self.udp_protocol.tcp_transport_closed.set_result(True)


class UdpServerProtocol(UdpProxyProtocol):
    def __init__(self, tcp_address, tcp_port):
        self.tcp_address = tcp_address
        self.tcp_port = tcp_port
        self.task = None
        self.udp_transport = None
        self.tcp_transport = None
        self.tcp_transport_closed = asyncio.get_running_loop().create_future()
        self.buffered_data = []

    def connection_made(self, transport):
        self.udp_transport = transport

    def datagram_received(self, data, addr):
        super().datagram_received(data, addr)
        if not self.task or self.task.done():
            self.task = asyncio.get_running_loop().create_task(self._connect_to_tcp())

    # Create a TCP connection that's connected to the UDP proxy
    async def _connect_to_tcp(self):
        loop = asyncio.get_running_loop()
        while True:
            last_addr = self.last_addr
            udp_transport = self.udp_transport
            tcp_transport, _ = await loop.create_connection(
                lambda: TcpClientProtocol(self, udp_transport, last_addr),
                self.tcp_address,
                self.tcp_port,
            )

            try:
                await self.tcp_transport_closed
            finally:
                tcp_transport.close()
            self.tcp_transport_closed = loop.create_future()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--udp-address", help="UDP address to proxy")
    parser.add_argument("--udp-port", type=int, help="UDP port to proxy")
    parser.add_argument("--tcp-address", help="TCP address to bind to")
    parser.add_argument("--tcp-port", type=int, help="TCP port to bind to")
    parser.add_argument(
        "--local-forwarding",
        action="store_true",
        help="Start a UDP server for local forwarding",
    )
    args = parser.parse_args()

    # Start TCP server
    loop = asyncio.get_running_loop()
    if args.local_forwarding:
        udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: UdpServerProtocol(args.tcp_address or "127.0.0.1", args.tcp_port),
            local_addr=(args.udp_address or "0.0.0.0", args.udp_port),
        )
        try:
            await asyncio.Event().wait()
        finally:
            udp_transport.close()
    else:
        server = await loop.create_server(
            lambda: TcpServerProtocol(args.udp_address or "127.0.0.1", args.udp_port),
            args.tcp_address or "0.0.0.0",
            args.tcp_port,
        )
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
