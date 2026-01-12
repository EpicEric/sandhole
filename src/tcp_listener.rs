use std::{io, net::ToSocketAddrs};

use socket2::{Domain, Socket, Type};
use tokio::net::TcpListener;

// Create an async TCP listener with Nagle's algorithm disabled
// and any necessary configurations for dualstack.
pub(crate) fn get_tcp_listener<A: ToSocketAddrs>(addr: A) -> io::Result<TcpListener> {
    let addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any address",
        )
    })?;
    let is_ipv6 = addr.is_ipv6();

    let socket = Socket::new(
        if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 },
        Type::STREAM,
        None,
    )?;

    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    if is_ipv6 {
        socket.set_only_v6(false)?;
    }

    // On platforms with Berkeley-derived sockets, this allows to quickly
    // rebind a socket, without needing to wait for the OS to clean up the
    // previous one.
    //
    // On Windows, this allows rebinding sockets which are actively in use,
    // which allows “socket hijacking”, so we explicitly don't set it here.
    // https://docs.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;

    socket.bind(&addr.into())?;
    socket.listen({
        #[cfg(not(windows))]
        {
            -1
        }
        #[cfg(windows)]
        {
            128
        }
    })?;

    TcpListener::from_std(socket.into())
}
