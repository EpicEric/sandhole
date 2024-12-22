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
    layout::{Constraint, Flex, Layout, Margin, Rect},
    prelude::CrosstermBackend,
    style::{Color, Modifier, Style, Stylize},
    symbols::border,
    text::{Line, Text},
    widgets::{
        Block, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        StatefulWidget, Table, TableState, Tabs, Widget, Wrap,
    },
    Terminal, TerminalOptions, Viewport,
};
use ssh_key::Fingerprint;
use tokio::{
    sync::{mpsc::UnboundedSender, watch},
    time::sleep,
};

use crate::{
    droppable_handle::DroppableHandle,
    fingerprints::{AuthenticationType, KeyData},
    tcp_alias::TcpAlias,
    SandholeServer, SystemData,
};

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

enum AdminPrompt {
    Infobox(String),
    SelectUser(Vec<String>, TableState),
    UserDetails(String, Option<(Fingerprint, KeyData)>),
    RemoveUser(String, Option<(Fingerprint, KeyData)>),
}

struct AdminState {
    server: Arc<SandholeServer>,
    is_pty: bool,
    tab: Tab,
    table_state: TableState,
    vertical_scroll: ScrollbarState,
    prompt: Option<AdminPrompt>,
}

fn to_socket_addr_string(addr: &SocketAddr) -> String {
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
            let title =
                Line::from(concat!(" Sandhole admin v", env!("CARGO_PKG_VERSION"), " ").bold());
            let instructions = Line::from(vec![
                " Change tab".into(),
                " <Tab> ".blue().bold(),
                " Details".into(),
                " <Enter> ".blue().bold(),
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
            self.render_prompt(area, buf);
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

    fn render_prompt(&mut self, area: Rect, buf: &mut Buffer) {
        if let Some(ref mut prompt) = self.prompt {
            let vertical = Layout::vertical([Constraint::Max(8)]).flex(Flex::Center);
            let horizontal = Layout::horizontal([Constraint::Length(60)]).flex(Flex::Center);
            let [area] = vertical.areas(area);
            let [area] = horizontal.areas(area);
            let block = Block::bordered().black().on_white();
            let inner = block.inner(area);
            Widget::render(Clear, area, buf);
            match prompt {
                AdminPrompt::Infobox(text) => {
                    let block = block.title_bottom(Line::raw(" <Enter> Close ").centered());
                    let text = Paragraph::new(text.as_str())
                        .centered()
                        .wrap(Wrap { trim: true });
                    Widget::render(block, area, buf);
                    Widget::render(text, inner, buf);
                }
                AdminPrompt::SelectUser(users, table_state) => {
                    let block = block
                        .title(Line::raw("Connected users"))
                        .title_bottom(Line::raw(" <Enter> Details ").centered());
                    let users = Table::new(
                        users.iter().map(|user| Row::new([user.as_str()])),
                        [Constraint::Fill(1)],
                    )
                    .row_highlight_style(Style::new().black().on_blue());
                    Widget::render(block, area, buf);
                    StatefulWidget::render(users, inner, buf, table_state);
                }
                AdminPrompt::UserDetails(user, data) => {
                    let block = block.title(Line::raw("User details")).title_bottom(
                        Line::raw(
                            if data
                                .as_ref()
                                .is_none_or(|(_, data)| data.auth == AuthenticationType::User)
                            {
                                " <Esc> Close  <Delete> Remove "
                            } else {
                                " <Esc> Close "
                            },
                        )
                        .centered(),
                    );
                    let (user_type, comment) = data
                        .as_ref()
                        .map(|(_, data)| {
                            (
                                format!("Type: {}", data.auth),
                                format!("Key comment: {}", data.comment),
                            )
                        })
                        .unwrap_or(("Type: User".into(), "(authenticated with password)".into()));
                    let text = Paragraph::new(vec![
                        Line::from(user.as_str()).centered(),
                        Line::from(user_type).centered(),
                        Line::from(comment).centered(),
                    ])
                    .wrap(Wrap { trim: true });
                    Widget::render(block, area, buf);
                    Widget::render(text, inner, buf);
                }
                AdminPrompt::RemoveUser(user, data) => {
                    let block = block
                        .title(Line::raw("Remove user?"))
                        .title_bottom(Line::raw(" <Esc> Cancel  <Enter> Confirm ").centered());
                    let text = Paragraph::new(vec![
                        Line::from("Are you sure you want to remove the following user?")
                            .centered(),
                        Line::from(user.as_str()).bold().centered(),
                        Line::from(if data.is_some() {
                            "They will lose all forwarding permissions!"
                        } else {
                            "They might still be able to reconnect via the login API!"
                        })
                        .centered(),
                    ])
                    .wrap(Wrap { trim: true });
                    Widget::render(block, area, buf);
                    Widget::render(text, inner, buf);
                }
            };
        }
    }

    // Render the selected tab's contents
    fn render_tab(&mut self, area: Rect, buf: &mut Buffer) {
        let color = self.tab.color();
        let table = match self.tab {
            Tab::Http => {
                let data = self.server.http_data.read().unwrap().clone();
                self.vertical_scroll = self.vertical_scroll.content_length(data.len());
                let rows: Vec<Row<'_>> = data
                    .iter()
                    .map(|(host, (connections, req_per_min))| {
                        let len = connections.len() as u16;
                        let (peers, users): (Vec<_>, Vec<_>) = connections.iter().unzip();
                        Row::new(vec![
                            host.clone(),
                            req_per_min.to_string(),
                            users.iter().join("\n"),
                            peers.iter().map(to_socket_addr_string).join("\n"),
                        ])
                        .height(len)
                    })
                    .collect();
                let constraints = [
                    Constraint::Min(25),
                    Constraint::Length(7),
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
                let rows: Vec<Row<'_>> = data
                    .iter()
                    .map(|(host, connections)| {
                        let len = connections.len() as u16;
                        let (peers, users): (Vec<_>, Vec<_>) = connections.iter().unzip();
                        Row::new(vec![
                            host.clone(),
                            users.iter().join("\n"),
                            peers.iter().map(to_socket_addr_string).join("\n"),
                        ])
                        .height(len)
                    })
                    .collect();
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
                let rows: Vec<Row<'_>> = data
                    .iter()
                    .map(|(TcpAlias(alias, port), connections)| {
                        let len = connections.len() as u16;
                        let (peers, users): (Vec<_>, Vec<_>) = connections.iter().unzip();
                        Row::new(vec![
                            alias.clone(),
                            port.to_string(),
                            users.iter().join("\n"),
                            peers.iter().map(to_socket_addr_string).join("\n"),
                        ])
                        .height(len)
                    })
                    .collect();
                let constraints = [
                    Constraint::Min(25),
                    Constraint::Length(5),
                    Constraint::Length(50),
                    Constraint::Length(47),
                ];
                let header = Row::new(["Alias", "Port", "User(s)", "Peer(s)"])
                    .add_modifier(Modifier::UNDERLINED);
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
                prompt: None,
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
        }
        let _ = self.change_notifier.send(());
    }

    // Move down in the selected tab's table
    pub(crate) fn move_down(&mut self) {
        let notify = {
            let mut interface = self.interface.lock().unwrap();
            match interface.state.prompt {
                Some(AdminPrompt::SelectUser(_, ref mut state)) => {
                    state.select_next();
                    true
                }
                Some(_) => false,
                None => {
                    interface.state.table_state.select_next();
                    interface.state.vertical_scroll = interface
                        .state
                        .vertical_scroll
                        .position(interface.state.table_state.selected().unwrap());
                    true
                }
            }
        };
        if notify {
            let _ = self.change_notifier.send(());
        }
    }

    // Move up in the selected tab's table
    pub(crate) fn move_up(&mut self) {
        let notify = {
            let mut interface = self.interface.lock().unwrap();
            match interface.state.prompt {
                Some(AdminPrompt::SelectUser(_, ref mut state)) => {
                    state.select_previous();
                    true
                }
                Some(_) => false,
                None => {
                    interface.state.table_state.select_previous();
                    interface.state.vertical_scroll = interface
                        .state
                        .vertical_scroll
                        .position(interface.state.table_state.selected().unwrap());
                    true
                }
            }
        };
        if notify {
            let _ = self.change_notifier.send(());
        }
    }

    // Cancel current selection in the table or prompt
    pub(crate) fn cancel(&mut self) {
        let notify = {
            let mut interface = self.interface.lock().unwrap();
            match interface.state.prompt {
                Some(_) => {
                    interface.state.prompt = None;
                    true
                }
                None => {
                    if interface.state.table_state.selected().is_some() {
                        interface.state.table_state = Default::default();
                        interface.state.vertical_scroll = Default::default();
                        true
                    } else {
                        false
                    }
                }
            }
        };
        if notify {
            let _ = self.change_notifier.send(());
        }
    }

    // Confirm current selection, which might be an entry in a table or a prompt
    pub(crate) fn enter(&mut self) {
        let notify = {
            let mut interface = self.interface.lock().unwrap();
            match interface.state.prompt.take() {
                Some(AdminPrompt::Infobox(_)) => {
                    interface.state.prompt = None;
                    true
                }
                Some(AdminPrompt::RemoveUser(user, data)) => {
                    let mut text = "User removed successfully!".into();
                    if let Some(fingerprint) = data.map(|(fingerprint, _)| fingerprint) {
                        if let Err(err) = interface
                            .state
                            .server
                            .fingerprints_validator
                            .remove_user_key(&fingerprint)
                        {
                            text = format!("Error: {}", err);
                        }
                        if let Some(sessions) = interface
                            .state
                            .server
                            .sessions_publickey
                            .lock()
                            .unwrap()
                            .remove(&fingerprint)
                        {
                            sessions.values().for_each(|tx| {
                                let _ = tx.send(());
                            });
                        }
                    } else if let Some(sessions) = interface
                        .state
                        .server
                        .sessions_password
                        .lock()
                        .unwrap()
                        .remove(&user)
                    {
                        sessions.values().for_each(|tx| {
                            let _ = tx.send(());
                        });
                    }
                    interface.state.prompt = Some(AdminPrompt::Infobox(text));
                    true
                }
                Some(AdminPrompt::SelectUser(users, table_state)) => {
                    if let Some(user) = table_state
                        .selected()
                        .and_then(|selected| users.get(selected))
                    {
                        let user = user.clone();
                        let fingerprint = user.parse().ok();
                        let key_data = fingerprint.as_ref().and_then(|fingerprint| {
                            interface
                                .state
                                .server
                                .fingerprints_validator
                                .get_data_for_fingerprint(fingerprint)
                        });
                        interface.state.prompt =
                            Some(AdminPrompt::UserDetails(user, fingerprint.zip(key_data)));
                        true
                    } else {
                        interface.state.prompt = Some(AdminPrompt::SelectUser(users, table_state));
                        false
                    }
                }
                Some(prompt) => {
                    interface.state.prompt = Some(prompt);
                    false
                }
                None => {
                    if let Some(row) = interface.state.table_state.selected() {
                        let users: Option<Vec<String>> = match interface.state.tab {
                            Tab::Http => interface
                                .state
                                .server
                                .http_data
                                .read()
                                .unwrap()
                                .values()
                                .nth(row)
                                .map(|value| value.0.values().cloned().collect()),
                            Tab::Ssh => interface
                                .state
                                .server
                                .ssh_data
                                .read()
                                .unwrap()
                                .values()
                                .nth(row)
                                .map(|value| value.values().cloned().collect()),
                            Tab::Tcp => interface
                                .state
                                .server
                                .tcp_data
                                .read()
                                .unwrap()
                                .values()
                                .nth(row)
                                .map(|value| value.values().cloned().collect()),
                        };
                        match users {
                            None => {
                                interface.state.prompt =
                                    Some(AdminPrompt::Infobox("No users found!".into()));
                            }
                            Some(users) if users.is_empty() => {
                                interface.state.prompt =
                                    Some(AdminPrompt::Infobox("No users found!".into()));
                            }
                            Some(mut users) if users.len() == 1 => {
                                let user = users.remove(0);
                                let fingerprint = user.parse().ok();
                                let key_data = fingerprint.as_ref().and_then(|fingerprint| {
                                    interface
                                        .state
                                        .server
                                        .fingerprints_validator
                                        .get_data_for_fingerprint(fingerprint)
                                });
                                interface.state.prompt =
                                    Some(AdminPrompt::UserDetails(user, fingerprint.zip(key_data)));
                            }
                            Some(users) => {
                                interface.state.prompt =
                                    Some(AdminPrompt::SelectUser(users, TableState::default()));
                            }
                        }
                        true
                    } else {
                        interface.state.prompt =
                            Some(AdminPrompt::Infobox("No row selected!".into()));
                        true
                    }
                }
            }
        };
        if notify {
            let _ = self.change_notifier.send(());
        }
    }

    pub(crate) fn delete(&mut self) {
        let notify = {
            let mut interface = self.interface.lock().unwrap();
            match interface.state.prompt.take() {
                Some(AdminPrompt::UserDetails(user, data)) => {
                    if data
                        .as_ref()
                        .is_none_or(|(_, data)| data.auth == AuthenticationType::User)
                    {
                        interface.state.prompt = Some(AdminPrompt::RemoveUser(user, data));
                        true
                    } else {
                        interface.state.prompt = Some(AdminPrompt::UserDetails(user, data));
                        false
                    }
                }
                Some(prompt) => {
                    interface.state.prompt = Some(prompt);
                    false
                }
                None => false,
            }
        };
        if notify {
            let _ = self.change_notifier.send(());
        }
    }
}
