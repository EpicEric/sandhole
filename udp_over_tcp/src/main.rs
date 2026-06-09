use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    pin::{Pin, pin},
    sync::Arc,
};

use ahash::RandomState;
use clap::Parser;
use color_eyre::eyre::eyre;
use dashmap::DashMap;
use sandhole_socket::{
    tcp_listener::get_tcp_listener,
    udp_listener::get_udp_socket,
    udp_over_tcp::{datagram_buffer, deserialize_datagram, serialize_datagram},
};
use tokio::{io::AsyncWriteExt, net::TcpSocket, select, sync::mpsc};

#[doc(hidden)]
#[derive(Debug, Parser, PartialEq)]
#[command(version, about, long_about = None)]
struct Cli {
    /// UDP address to proxy.
    #[arg(long, value_name = "IP_ADDRESS")]
    udp_address: Option<IpAddr>,

    /// UDP port to proxy.
    #[arg(long, value_name = "PORT")]
    udp_port: NonZeroU16,

    /// TCP address to bind to.
    #[arg(long, value_name = "IP_ADDRESS")]
    tcp_address: Option<IpAddr>,

    /// TCP port to bind to.
    #[arg(long, value_name = "PORT")]
    tcp_port: NonZeroU16,

    /// Start a UDP server for local forwarding.
    #[arg(long)]
    local_forwarding: bool,
}

type FutType = Pin<Box<dyn Future<Output = color_eyre::Result<()>> + Send + Sync + 'static>>;

// Starts a TCP server that redirects requests to the UDP socket.
async fn remote_forwarding(args: Cli) -> color_eyre::Result<()> {
    let listener = get_tcp_listener((
        args.tcp_address
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        u16::from(args.tcp_port),
    ))?;
    let udp_address = (
        args.udp_address.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        u16::from(args.udp_port),
    );
    loop {
        let (stream, _) = listener.accept().await?;
        let udp_socket_read = Arc::new(get_udp_socket((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?);
        udp_socket_read.connect(udp_address).await?;
        let udp_socket_write = Arc::clone(&udp_socket_read);
        tokio::spawn(async move {
            let (read_stream, write_stream) = stream.into_split();

            let read_fut: FutType = Box::pin(async move {
                let mut read_stream = pin!(read_stream);
                let mut buf = datagram_buffer();
                loop {
                    let len = deserialize_datagram(&mut buf[..], &mut read_stream).await?;
                    udp_socket_write.send(&buf[..len]).await?;
                }
            });

            let write_fut: FutType = Box::pin(async move {
                let mut write_stream = pin!(write_stream);
                let mut datagram_buf = datagram_buffer();
                let mut buf = datagram_buffer();
                loop {
                    let datagram_len = udp_socket_read.recv(&mut datagram_buf[..]).await?;
                    let len = serialize_datagram(&mut buf[..], &datagram_buf[..datagram_len]);
                    write_stream.write_all(&buf[..len]).await?;
                }
            });

            select! {
                result = read_fut => if let Err(error) = result {
                    eprintln!("{error}");
                },
                result = write_fut => if let Err(error) = result {
                    eprintln!("{error}");
                },
            }
        });
    }
}

// Starts an UDP socket that redirects datagrams to the TCP client.
async fn local_forwarding(args: Cli) -> color_eyre::Result<()> {
    let udp_socket_read = Arc::new(get_udp_socket((
        args.udp_address
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        u16::from(args.udp_port),
    ))?);

    let read_fut: FutType = Box::pin(async move {
        let mut datagram_buf = datagram_buffer();
        let mut buf = datagram_buffer();
        let conns: Arc<DashMap<SocketAddr, mpsc::Sender<Vec<u8>>, RandomState>> = Arc::default();
        loop {
            let (datagram_len, address) = udp_socket_read.recv_from(&mut datagram_buf[..]).await?;
            let len = serialize_datagram(&mut buf[..], &datagram_buf[..datagram_len]);

            // Attempt to send data
            let mut data = buf[..len].to_vec();
            if let Some(conn) = conns.get(&address) {
                let conn = conn.clone();
                match conn.send(data).await {
                    Ok(_) => continue,
                    Err(error) => {
                        data = error.0;
                        conns.remove(&address);
                    }
                }
            }

            // No valid TCP connection; create a new one
            let (serialized_datagram_tx, mut serialized_datagram_rx) =
                mpsc::channel::<Vec<u8>>(128);
            serialized_datagram_tx
                .send(data)
                .await
                .expect("empty channel");
            conns.entry(address).insert_entry(serialized_datagram_tx);
            let conns = Arc::clone(&conns);
            let udp_socket_write = Arc::clone(&udp_socket_read);
            tokio::spawn(async move {
                let tcp_socket = if args.tcp_address.is_some_and(|address| address.is_ipv6()) {
                    TcpSocket::new_v6()
                } else {
                    TcpSocket::new_v4()
                }
                .expect("should create TCP socket");
                tcp_socket
                    .set_nodelay(true)
                    .expect("should disable Nagle's algorithm");
                let tcp_stream = match tcp_socket
                    .connect(SocketAddr::new(
                        args.tcp_address.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        u16::from(args.tcp_port),
                    ))
                    .await
                {
                    Ok(tcp_stream) => tcp_stream,
                    Err(error) => {
                        eprintln!("Failed to connect to TCP address: {error}");
                        conns.remove(&address);
                        return;
                    }
                };
                let (read_stream, write_stream) = tcp_stream.into_split();

                let mut write_fut: FutType = Box::pin(async move {
                    let mut write_stream = pin!(write_stream);
                    while let Some(data) = serialized_datagram_rx.recv().await {
                        write_stream.write_all(&data[..]).await?;
                    }
                    Ok(())
                });

                let mut read_fut: FutType = Box::pin(async move {
                    let mut buf = datagram_buffer();
                    let mut read_stream = pin!(read_stream);
                    loop {
                        let len = deserialize_datagram(&mut buf[..], &mut read_stream).await?;
                        udp_socket_write.send_to(&buf[..len], address).await?;
                    }
                });

                select! {
                    result = &mut write_fut => if let Err(error) = result {
                        eprintln!("Error writing to TCP client: {error}");
                    },
                    result = &mut read_fut => if let Err(error) = result {
                        eprintln!("Error writing to UDP socket: {error}");
                    },
                }

                conns.remove(&address);
            });
        }
    });

    read_fut.await
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();

    if args.local_forwarding {
        select! {
            result = local_forwarding(args) => result?,
            signal = wait_for_signal() => {
                return Err(eyre!("Received {signal}, terminating..."));
            }
        }
    } else {
        select! {
            result = remote_forwarding(args) => result?,
            signal = wait_for_signal() => {
                return Err(eyre!("Received {signal}, terminating..."));
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn wait_for_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};

    let mut signal_terminate = signal(SignalKind::terminate()).expect("valid signal");
    let mut signal_interrupt = signal(SignalKind::interrupt()).expect("valid signal");

    tokio::select! {
        _ = signal_terminate.recv() => {
            "SIGTERM"
        },
        _ = signal_interrupt.recv() => {
            "SIGINT"
        },
    }
}

#[cfg(windows)]
async fn wait_for_signal() -> &'static str {
    use tokio::signal::windows;

    let mut signal_c = windows::ctrl_c().expect("valid signal");
    let mut signal_break = windows::ctrl_break().expect("valid signal");
    let mut signal_close = windows::ctrl_close().expect("valid signal");
    let mut signal_shutdown = windows::ctrl_shutdown().expect("valid signal");

    tokio::select! {
        _ = signal_c.recv() => {
            "CTRL_C"
        },
        _ = signal_break.recv() => {
            "CTRL_BREAK"
        },
        _ = signal_close.recv() => {
            "CTRL_CLOSE"
        },
        _ = signal_shutdown.recv() => {
            "CTRL_SHUTDOWN"
        },
    }
}
