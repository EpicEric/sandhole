use std::{io, net::ToSocketAddrs};

use socket2::{Domain, Socket, Type};
use tokio::net::UdpSocket;

// Create an async UDP listener.
pub(crate) fn get_udp_socket<A: ToSocketAddrs>(addr: A) -> io::Result<UdpSocket> {
    let addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any address",
        )
    })?;
    let is_ipv6 = addr.is_ipv6();

    let socket = Socket::new(
        if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 },
        Type::DGRAM,
        None,
    )?;

    socket.set_nonblocking(true)?;
    if is_ipv6 {
        socket.set_only_v6(false)?;
    }

    socket.set_reuse_address(true)?;
    #[cfg(not(windows))]
    socket.set_reuse_port(true)?;

    socket.bind(&addr.into())?;

    UdpSocket::from_std(socket.into())
}
