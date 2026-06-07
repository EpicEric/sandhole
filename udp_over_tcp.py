#!/usr/bin/env python3
import argparse
import asyncio


class UdpClientProtocol(asyncio.Protocol):
    def __init__(self, tcp_transport):
        self.tcp_transport = tcp_transport

    def datagram_received(self, data, addr):
        # Add datagram size to start of data
        data_len = bytes((len(data) >> 8, len(data) & 0xFF))
        # Send to the connected TCP socket
        self.tcp_transport.writelines((data_len, data))


class TcpProxyProtocol(asyncio.Protocol):
    def __init__(self, udp_address, udp_port):
        self.udp_address = udp_address
        self.udp_port = udp_port
        self.task = None
        self.tcp_transport = None
        self.udp_transport = None
        self.data_len = (0, 0)
        self.data = b""
        self.buffered_data = []
        self.on_connection_lost = asyncio.get_running_loop().create_future()

    def connection_made(self, transport):
        self.tcp_transport = transport
        loop = asyncio.get_running_loop()

        # Create an UDP socket that's connected to the TCP proxy
        async def connect_to_udp(self):
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

        self.task = loop.create_task(connect_to_udp(self))

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
                    self.udp_transport.sendto(self.data)
                else:
                    # UDP is not connected yet; save to buffer
                    self.buffered_data.append(self.data)
                self.data_len = (0, 0)
                self.data = b""

    def connection_lost(self, exc):
        self.on_connection_lost.set_result(True)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--udp-address", default="127.0.0.1", help="UDP address to proxy"
    )
    parser.add_argument("--udp-port", type=int, help="UDP port to proxy")
    parser.add_argument("--tcp-address", default="::1", help="TCP address to bind to")
    parser.add_argument("--tcp-port", type=int, help="TCP port to bind to")
    args = parser.parse_args()

    # Start TCP server
    server = await asyncio.get_running_loop().create_server(
        lambda: TcpProxyProtocol(args.udp_address, args.udp_port),
        args.tcp_address,
        args.tcp_port,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
