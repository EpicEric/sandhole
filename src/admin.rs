use std::{
    io,
    net::SocketAddr,
    ops::DerefMut,
    sync::{Arc, Mutex},
    time::Duration,
};

use human_bytes::human_bytes;
use itertools::Itertools;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Margin, Rect},
    prelude::CrosstermBackend,
    style::{Color, Modifier, Style, Stylize},
    symbols::border,
    text::{Line, Text},
    widgets::{
        Block, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget,
        Table, TableState, Tabs, Widget,
    },
    Terminal, TerminalOptions, Viewport,
};
use tokio::{
    sync::{mpsc::UnboundedSender, watch},
    time::sleep,
};

use crate::{droppable_handle::DroppableHandle, tcp_alias::TcpAlias, SandholeServer, SystemData};

struct BufferedSender {
    tx: UnboundedSender<Vec<u8>>,
    buf: Vec<u8>,
}

impl io::Write for BufferedSender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let result = self.tx.send(self.buf.drain(..).collect());
        if let Err(err) = result {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, err))
        } else {
            Ok(())
        }
    }
}

enum Tab {
    Http,
    Ssh,
    Tcp,
}

impl Tab {
    fn render(area: Rect, buf: &mut Buffer, selected: usize) {
        Tabs::new(vec![
            Line::from("  HTTP  ".black().bg(Tab::Http.color())),
            Line::from("  SSH  ".black().bg(Tab::Ssh.color())),
            Line::from("  TCP  ".black().bg(Tab::Tcp.color())),
        ])
        .select(selected)
        .highlight_style(Style::new().bold())
        .divider(" ")
        .render(area, buf);
    }

    fn index(&self) -> usize {
        match self {
            Tab::Http => 0,
            Tab::Ssh => 1,
            Tab::Tcp => 2,
        }
    }

    fn color(&self) -> Color {
        match self {
            Tab::Http => Color::Blue,
            Tab::Ssh => Color::Yellow,
            Tab::Tcp => Color::Green,
        }
    }
}

struct AdminState {
    server: Arc<SandholeServer>,
    is_pty: bool,
    tab: Tab,
    table_state: TableState,
    vertical_scroll: ScrollbarState,
}

fn remove_user_namespace(user: &str) -> &str {
    &user[2..]
}

fn to_socket_addr_string(addr: SocketAddr) -> String {
    let ip = addr.ip().to_canonical();
    if ip.is_ipv4() {
        format!("{}:{}", ip, addr.port())
    } else {
        addr.to_string()
    }
}

impl AdminState {
    // Render the admin interface
    fn render(&mut self, area: Rect, buf: &mut Buffer) {
        if self.is_pty {
            let title = Line::from(" Sandhole admin ".bold());
            let instructions = Line::from(vec![
                " Change tab".into(),
                " <Tab> ".blue().bold(),
                " Quit".into(),
                " <Ctrl-C> ".blue().bold(),
            ]);
            let block = Block::bordered()
                .title(title.centered())
                .title_bottom(instructions.centered())
                .border_set(border::THICK);
            block.render(area, buf);
            let [system_data_area, _, tabs_area, inner_area] = Layout::vertical([
                Constraint::Length(4),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(0),
            ])
            .areas(area.inner(Margin::new(2, 2)));
            Tab::render(tabs_area, buf, self.tab.index());
            self.render_system_data(system_data_area, buf);
            Block::bordered()
                .border_style(Style::new().fg(self.tab.color()))
                .border_set(border::PROPORTIONAL_TALL)
                .render(inner_area, buf);
            self.render_tab(inner_area.inner(Margin::new(2, 1)), buf);
        } else {
            let text = Text::from(vec![
                Line::from(
                    "PTY not detected! Make sure to connect with \"ssh -t ... admin\" instead."
                        .red(),
                ),
                Line::from("Press Ctrl-C to close this connection."),
            ]);
            let widget = Paragraph::new(text).left_aligned();
            widget.render(area, buf);
        }
    }

    // Render the selected tab's contents
    fn render_tab(&mut self, area: Rect, buf: &mut Buffer) {
        let color = self.tab.color();
        let table = match self.tab {
            Tab::Http => {
                let data = self.server.http_data.read().unwrap().clone();
                self.vertical_scroll = self.vertical_scroll.content_length(data.len());
                let rows = data.into_iter().map(|(host, (connections, req_per_min))| {
                    let len = connections.len() as u16;
                    let (peers, users): (Vec<_>, Vec<_>) = connections.into_iter().unzip();
                    Row::new(vec![
                        host,
                        req_per_min.to_string(),
                        users
                            .iter()
                            .map(|user| remove_user_namespace(user))
                            .join("\n"),
                        peers.into_iter().map(to_socket_addr_string).join("\n"),
                    ])
                    .height(len)
                });
                let constraints = [
                    Constraint::Min(25),
                    Constraint::Min(7),
                    Constraint::Length(50),
                    Constraint::Length(47),
                ];
                let header = Row::new(["Host", "Req/min", "User(s)", "Peer(s)"])
                    .add_modifier(Modifier::UNDERLINED);
                let title =
                    Block::new().title(Line::from("HTTP services".fg(color).bold()).centered());
                Table::new(rows, constraints)
                    .header(header)
                    .column_spacing(1)
                    .block(title)
                    .row_highlight_style(Style::new().fg(color).reversed())
            }
            Tab::Ssh => {
                let data = self.server.ssh_data.read().unwrap().clone();
                self.vertical_scroll = self.vertical_scroll.content_length(data.len());
                let rows = data.into_iter().map(|(host, connections)| {
                    let len = connections.len() as u16;
                    let (peers, users): (Vec<_>, Vec<_>) = connections.into_iter().unzip();
                    Row::new(vec![
                        host,
                        users
                            .iter()
                            .map(|user| remove_user_namespace(user))
                            .join("\n"),
                        peers.into_iter().map(to_socket_addr_string).join("\n"),
                    ])
                    .height(len)
                });
                let constraints = [
                    Constraint::Min(25),
                    Constraint::Length(50),
                    Constraint::Length(47),
                ];
                let header =
                    Row::new(["Host", "User(s)", "Peer(s)"]).add_modifier(Modifier::UNDERLINED);
                let title =
                    Block::new().title(Line::from("SSH services".fg(color).bold()).centered());
                Table::new(rows, constraints)
                    .header(header)
                    .column_spacing(1)
                    .block(title)
                    .row_highlight_style(Style::new().fg(color).reversed())
            }
            Tab::Tcp => {
                let data = self.server.tcp_data.read().unwrap().clone();
                self.vertical_scroll = self.vertical_scroll.content_length(data.len());
                let rows = data
                    .into_iter()
                    .map(|(TcpAlias(alias, port), connections)| {
                        let len = connections.len() as u16;
                        let (peers, users): (Vec<_>, Vec<_>) = connections.into_iter().unzip();
                        Row::new(vec![
                            alias,
                            port.to_string(),
                            users
                                .iter()
                                .map(|user| remove_user_namespace(user))
                                .join("\n"),
                            peers.into_iter().map(to_socket_addr_string).join("\n"),
                        ])
                        .height(len)
                    });
                let constraints = [
                    Constraint::Min(25),
                    Constraint::Length(5),
                    Constraint::Length(50),
                    Constraint::Length(47),
                ];
                let header =
                    Row::new(["Alias", "Port", "Peer(s)"]).add_modifier(Modifier::UNDERLINED);
                let title =
                    Block::new().title(Line::from("TCP services".fg(color).bold()).centered());
                Table::new(rows, constraints)
                    .header(header)
                    .column_spacing(1)
                    .block(title)
                    .row_highlight_style(Style::new().fg(color).reversed())
            }
        };
        StatefulWidget::render(table, area, buf, &mut self.table_state);
        StatefulWidget::render(
            Scrollbar::default().orientation(ScrollbarOrientation::VerticalRight),
            area.inner(Margin::new(0, 2)),
            buf,
            &mut self.vertical_scroll,
        );
    }

    // Render the system information box
    fn render_system_data(&mut self, area: Rect, buf: &mut Buffer) {
        let SystemData {
            used_memory,
            total_memory,
            network_tx,
            network_rx,
            cpu_usage,
        } = self.server.system_data.read().unwrap().clone();
        let block = Block::bordered().title("System information");
        let [left_area, right_area] =
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                .areas(block.inner(area));
        let [cpu_area, memory_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(left_area);
        let [tx_area, rx_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(right_area);
        let cpu_usage = Line::from(vec![
            "  CPU%  ".bold().reversed(),
            format!(" {:.1} %", cpu_usage).into(),
        ]);
        let memory_usage = Line::from(vec![
            " Memory ".bold().reversed(),
            format!(
                " {} / {}",
                human_bytes(used_memory as f64),
                human_bytes(total_memory as f64)
            )
            .into(),
        ]);
        let network_tx = Line::from(vec![
            "   TX   ".bold().reversed(),
            format!(" {}/s", human_bytes(network_tx as f64)).into(),
        ]);
        let network_rx = Line::from(vec![
            "   RX   ".bold().reversed(),
            format!(" {}/s", human_bytes(network_rx as f64)).into(),
        ]);
        Widget::render(block, area, buf);
        Widget::render(cpu_usage, cpu_area, buf);
        Widget::render(memory_usage, memory_area, buf);
        Widget::render(network_tx, tx_area, buf);
        Widget::render(network_rx, rx_area, buf);
    }
}

struct AdminTerminal {
    terminal: Terminal<CrosstermBackend<BufferedSender>>,
    state: AdminState,
}

pub(crate) struct AdminInterface {
    interface: Arc<Mutex<AdminTerminal>>,
    _join_handle: DroppableHandle<()>,
    change_notifier: watch::Sender<()>,
}

impl AdminInterface {
    // Create an admin interface and send its output to the provided UnboundedSender
    pub(crate) fn new(tx: UnboundedSender<Vec<u8>>, server: Arc<SandholeServer>) -> Self {
        let backend = CrosstermBackend::new(BufferedSender {
            tx,
            buf: Vec::new(),
        });
        let options = TerminalOptions {
            viewport: Viewport::Fixed(Rect::new(0, 0, 120, 60)),
        };
        let (change_notifier, mut subscriber) = watch::channel(());
        let interface = Arc::new(Mutex::new(AdminTerminal {
            terminal: Terminal::with_options(backend, options).unwrap(),
            state: AdminState {
                server,
                tab: Tab::Http,
                is_pty: false,
                table_state: Default::default(),
                vertical_scroll: Default::default(),
            },
        }));
        let interface_clone = Arc::clone(&interface);
        let join_handle = DroppableHandle(tokio::spawn(async move {
            loop {
                {
                    let mut interface = interface.lock().unwrap();
                    let AdminTerminal {
                        ref mut terminal,
                        ref mut state,
                    } = interface.deref_mut();
                    terminal
                        .draw(|frame| {
                            state.render(frame.area(), frame.buffer_mut());
                            frame.set_cursor_position((0, 0));
                        })
                        .unwrap();
                    drop(interface);
                }
                tokio::select! {
                    _ = sleep(Duration::from_millis(1_000)) => (),
                    _ = subscriber.changed() => ()
                }
            }
        }));
        Self {
            interface: interface_clone,
            _join_handle: join_handle,
            change_notifier,
        }
    }

    // Adjust to a window resize event
    pub(crate) fn resize(&mut self, width: u16, height: u16) -> anyhow::Result<()> {
        let rect = ratatui::prelude::Rect {
            x: 0,
            y: 0,
            width,
            height,
        };
        {
            let mut interface = self.interface.lock().unwrap();
            interface.terminal.resize(rect)?;
            interface.state.is_pty = true;
            drop(interface);
        }
        let _ = self.change_notifier.send(());
        Ok(())
    }

    // Advance one tab
    pub(crate) fn next_tab(&mut self) {
        {
            let mut interface = self.interface.lock().unwrap();
            match interface.state.tab {
                Tab::Http => {
                    interface.state.tab = Tab::Ssh;
                }
                Tab::Ssh => {
                    interface.state.tab = Tab::Tcp;
                }
                Tab::Tcp => {
                    interface.state.tab = Tab::Http;
                }
            }
            interface.state.table_state = Default::default();
            interface.state.vertical_scroll = Default::default();
            drop(interface);
        }
        let _ = self.change_notifier.send(());
    }

    // Go back one tab
    pub(crate) fn previous_tab(&mut self) {
        {
            let mut interface = self.interface.lock().unwrap();
            match interface.state.tab {
                Tab::Http => {
                    interface.state.tab = Tab::Tcp;
                }
                Tab::Ssh => {
                    interface.state.tab = Tab::Http;
                }
                Tab::Tcp => {
                    interface.state.tab = Tab::Ssh;
                }
            }
            interface.state.table_state = Default::default();
            interface.state.vertical_scroll = Default::default();
            drop(interface);
        }
        let _ = self.change_notifier.send(());
    }

    // Move down in the selected tab's table
    pub(crate) fn move_down(&mut self) {
        {
            let mut interface = self.interface.lock().unwrap();
            interface.state.table_state.select_next();
            interface.state.vertical_scroll.next();
            drop(interface);
        }
        let _ = self.change_notifier.send(());
    }

    // Move up in the selected tab's table
    pub(crate) fn move_up(&mut self) {
        {
            let mut interface = self.interface.lock().unwrap();
            interface.state.table_state.select_previous();
            interface.state.vertical_scroll.prev();
            drop(interface);
        }
        let _ = self.change_notifier.send(());
    }

    // Move left in the selected tab's table
    pub(crate) fn move_left(&mut self) {
        {
            let mut interface = self.interface.lock().unwrap();
            interface.state.table_state.select_previous_column();
            drop(interface);
        }
        let _ = self.change_notifier.send(());
    }

    // Move right in the selected tab's table
    pub(crate) fn move_right(&mut self) {
        {
            let mut interface = self.interface.lock().unwrap();
            interface.state.table_state.select_next_column();
            drop(interface);
        }
        let _ = self.change_notifier.send(());
    }
}
