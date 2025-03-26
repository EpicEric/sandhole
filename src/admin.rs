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
    Terminal, TerminalOptions, Viewport,
    buffer::Buffer,
    layout::{Constraint, Flex, Layout, Margin, Position, Rect},
    prelude::CrosstermBackend,
    style::{Color, Modifier, Style, Stylize},
    symbols::border,
    text::{Line, Text},
    widgets::{
        Block, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        StatefulWidget, Table, TableState, Tabs, Widget, Wrap,
    },
};
use russh::keys::ssh_key::Fingerprint;
use tokio::{sync::watch, time::sleep};

use crate::{
    SandholeServer, SystemData,
    droppable_handle::DroppableHandle,
    fingerprints::{AuthenticationType, KeyData},
    ssh::ServerHandlerSender,
    tcp_alias::TcpAlias,
};

struct BufferedSender {
    tx: ServerHandlerSender,
    buf: Vec<u8>,
}

impl io::Write for BufferedSender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tx.send(self.buf.drain(..).collect())
    }
}

#[derive(Clone, Copy)]
enum Tab {
    Http,
    Sni,
    Ssh,
    Tcp,
    Alias,
}

impl Tab {
    fn color(&self) -> Color {
        match self {
            Tab::Http => Color::Blue,
            Tab::Sni => Color::Cyan,
            Tab::Ssh => Color::Yellow,
            Tab::Tcp => Color::Green,
            Tab::Alias => Color::Red,
        }
    }
}

struct TabData {
    tabs: Vec<Tab>,
    current: usize,
}

impl TabData {
    // Render the tabs at the top of the table
    fn render(&self, area: Rect, buf: &mut Buffer) {
        Tabs::new(
            self.tabs
                .iter()
                .map(|tab| match tab {
                    Tab::Http => Line::from("  HTTP  ".black().bg(Tab::Http.color())),
                    Tab::Sni => Line::from("  SNI  ".black().bg(Tab::Sni.color())),
                    Tab::Ssh => Line::from("  SSH  ".black().bg(Tab::Ssh.color())),
                    Tab::Tcp => Line::from("  TCP  ".black().bg(Tab::Tcp.color())),
                    Tab::Alias => Line::from("  Alias  ".black().bg(Tab::Alias.color())),
                })
                .collect::<Vec<_>>(),
        )
        .select(self.index())
        .highlight_style(Style::new().bold())
        .divider(" ")
        .render(area, buf);
    }

    fn index(&self) -> usize {
        self.current
    }

    fn current_tab(&self) -> Tab {
        self.tabs[self.current]
    }

    fn previous(&mut self) {
        if self.current == 0 {
            self.current = self.tabs.len() - 1;
        } else {
            self.current -= 1;
        }
    }

    fn next(&mut self) {
        if self.current == self.tabs.len() - 1 {
            self.current = 0;
        } else {
            self.current += 1;
        }
    }
}

// Pop-up window displaying detailed information
enum AdminPrompt {
    // General information
    Infobox(String),
    // User selection
    SelectUser(Vec<String>, TableState),
    // User details
    UserDetails(String, Option<(Fingerprint, KeyData)>),
    // Prompt to remove a user
    RemoveUser(String, Option<(Fingerprint, KeyData)>),
}

// Data used to render the admin interface.
struct AdminState {
    // Reference to the server for collecting data and interacting with user keys.
    server: Arc<SandholeServer>,
    // Whether data should be rendered to the terminal.
    enabled: bool,
    // Whether this is rendered in a pseudo-terminal or not.
    is_pty: bool,
    // Currently selected tab.
    tab: TabData,
    // State of the selected tab's table.
    table_state: TableState,
    // State of the scrollbar for the selected tab's table.
    vertical_scroll: ScrollbarState,
    // Which pop-up to show, if any.
    prompt: Option<AdminPrompt>,
}

// Helper utility to display canonical socket addresses.
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
            // Display the title at the top
            let title =
                Line::from(concat!(" Sandhole admin v", env!("CARGO_PKG_VERSION"), " ").bold());
            // Display the commands at the bottom
            let instructions = Line::from(vec![
                " <Tab> ".blue().bold(),
                "Change tab ".into(),
                " <Enter> ".blue().bold(),
                "Details ".into(),
                " <Ctrl-C> ".blue().bold(),
                "Quit ".into(),
            ]);
            let block = Block::bordered()
                .title(title.centered())
                .title_bottom(instructions.centered())
                .border_set(border::THICK);
            block.render(area, buf);
            // Break the layout vertically for system info and the selected tab
            let [system_data_area, _, tabs_area, inner_area] = Layout::vertical([
                Constraint::Length(4),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(0),
            ])
            .areas(area.inner(Margin::new(2, 2)));
            self.tab.render(tabs_area, buf);
            self.render_system_data(system_data_area, buf);
            Block::bordered()
                .border_style(Style::new().fg(self.tab.current_tab().color()))
                .border_set(border::PROPORTIONAL_TALL)
                .render(inner_area, buf);
            self.render_tab(inner_area.inner(Margin::new(2, 1)), buf);
            self.render_prompt(area, buf);
        } else {
            // If this is not a pseudo-terminal, show some information on how to allocate one
            let text = Text::from(vec![
                Line::from(
                    r#"PTY not detected! Make sure to connect with "ssh -t" instead."#.red(),
                ),
                Line::from("Press Ctrl-C to close this connection."),
            ]);
            let widget = Paragraph::new(text).left_aligned();
            widget.render(area, buf);
        }
    }

    // Render the prompt over other data
    fn render_prompt(&mut self, area: Rect, buf: &mut Buffer) {
        if let Some(ref mut prompt) = self.prompt {
            let vertical = Layout::vertical([Constraint::Max(8)]).flex(Flex::Center);
            let horizontal = Layout::horizontal([Constraint::Length(60)]).flex(Flex::Center);
            let [area] = vertical.areas(area);
            let [area] = horizontal.areas(area);
            let block = Block::bordered().black().on_white();
            let inner = block.inner(area);
            // Clear area underneath the prompt
            Widget::render(Clear, area, buf);
            match prompt {
                // Show the infobox
                AdminPrompt::Infobox(text) => {
                    let block = block.title_bottom(
                        Line::from(vec![" <Enter> ".bold(), "Close ".into()]).centered(),
                    );
                    let text = Paragraph::new(text.as_str())
                        .centered()
                        .wrap(Wrap { trim: true });
                    Widget::render(block, area, buf);
                    Widget::render(text, inner, buf);
                }
                // Show the user selection prompt
                AdminPrompt::SelectUser(users, table_state) => {
                    let block = block.title(Line::raw("Connected users")).title_bottom(
                        Line::from(vec![" <Enter> ".bold(), "Details ".into()]).centered(),
                    );
                    let users = Table::new(
                        users.iter().map(|user| Row::new([user.as_str()])),
                        [Constraint::Fill(1)],
                    )
                    .row_highlight_style(Style::new().black().on_blue());
                    Widget::render(block, area, buf);
                    StatefulWidget::render(users, inner, buf, table_state);
                }
                // Show the user details pop-up
                AdminPrompt::UserDetails(user, data) => {
                    let block = block.title(Line::raw("User details")).title_bottom(
                        if data
                            .as_ref()
                            .is_none_or(|(_, data)| data.auth == AuthenticationType::User)
                        {
                            Line::from(vec![
                                " <Esc> ".bold(),
                                "Close ".into(),
                                " <Delete> ".bold(),
                                "Remove ".into(),
                            ])
                            .centered()
                        } else {
                            Line::from(vec![" <Esc> ".bold(), "Close ".into()]).centered()
                        },
                    );
                    let user_data = data
                        .as_ref()
                        // If fingerprint, get key data
                        .map(|(_, data)| {
                            vec![
                                Line::from(user.as_str()).centered(),
                                Line::from(format!("Type: {}", data.auth)).centered(),
                                Line::from(format!("Key comment: {}", data.comment)).centered(),
                                Line::from(format!("Algorithm: {}", data.algorithm.as_str()))
                                    .centered(),
                            ]
                        })
                        // If not, get generic user data
                        .unwrap_or_else(|| {
                            vec![
                                Line::from(user.as_str()).centered(),
                                Line::from("Type: User").centered(),
                                Line::from("(authenticated with password)").centered(),
                            ]
                        });
                    let text = Paragraph::new(user_data).wrap(Wrap { trim: true });
                    Widget::render(block, area, buf);
                    Widget::render(text, inner, buf);
                }
                // Show the user removal confirmation prompt
                AdminPrompt::RemoveUser(user, data) => {
                    let block = block.title(Line::raw("Remove user?")).title_bottom(
                        Line::from(vec![
                            " <Esc> ".bold(),
                            "Cancel ".into(),
                            " <Enter> ".bold(),
                            "Confirm ".into(),
                        ])
                        .centered(),
                    );
                    let text = Paragraph::new(vec![
                        Line::from("Are you sure you want to remove the following user?")
                            .centered(),
                        Line::from(user.as_str()).centered(),
                        Line::from(if data.is_some() {
                            "Any keys in the given file will lose all forwarding permissions!"
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
        let color = self.tab.current_tab().color();
        let table = match self.tab.current_tab() {
            Tab::Http => {
                // Get data for HTTP
                let data = self.server.http_data.read().unwrap().clone();
                self.vertical_scroll = self.vertical_scroll.content_length(data.len());
                // Create rows for each host
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
            Tab::Sni => {
                // Get data for aliases
                let data = self.server.sni_data.read().unwrap().clone();
                self.vertical_scroll = self.vertical_scroll.content_length(data.len());
                // Create rows for each socket or alias
                let rows: Vec<Row<'_>> = data
                    .iter()
                    .map(|(host, (connections, conns_per_min))| {
                        let len = connections.len() as u16;
                        let (peers, users): (Vec<_>, Vec<_>) = connections.iter().unzip();
                        Row::new(vec![
                            host.clone(),
                            conns_per_min.to_string(),
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
                let header = Row::new(["Alias", "Con/min", "User(s)", "Peer(s)"])
                    .add_modifier(Modifier::UNDERLINED);
                let title =
                    Block::new().title(Line::from("SNI proxies".fg(color).bold()).centered());
                Table::new(rows, constraints)
                    .header(header)
                    .column_spacing(1)
                    .block(title)
                    .row_highlight_style(Style::new().fg(color).reversed())
            }
            Tab::Ssh => {
                // Get data for SSH
                let data = self.server.ssh_data.read().unwrap().clone();
                self.vertical_scroll = self.vertical_scroll.content_length(data.len());
                // Create rows for each alias
                let rows: Vec<Row<'_>> = data
                    .iter()
                    .map(|(host, (connections, conns_per_min))| {
                        let len = connections.len() as u16;
                        let (peers, users): (Vec<_>, Vec<_>) = connections.iter().unzip();
                        Row::new(vec![
                            host.clone(),
                            conns_per_min.to_string(),
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
                let header = Row::new(["Alias", "Con/min", "User(s)", "Peer(s)"])
                    .add_modifier(Modifier::UNDERLINED);
                let title =
                    Block::new().title(Line::from("SSH services".fg(color).bold()).centered());
                Table::new(rows, constraints)
                    .header(header)
                    .column_spacing(1)
                    .block(title)
                    .row_highlight_style(Style::new().fg(color).reversed())
            }
            Tab::Tcp => {
                // Get data for TCP
                let data = self.server.tcp_data.read().unwrap().clone();
                self.vertical_scroll = self.vertical_scroll.content_length(data.len());
                // Create rows for each socket or alias
                let rows: Vec<Row<'_>> = data
                    .iter()
                    .map(|(port, (connections, conns_per_min))| {
                        let len = connections.len() as u16;
                        let (peers, users): (Vec<_>, Vec<_>) = connections.iter().unzip();
                        Row::new(vec![
                            port.to_string(),
                            conns_per_min.to_string(),
                            users.iter().join("\n"),
                            peers.iter().map(to_socket_addr_string).join("\n"),
                        ])
                        .height(len)
                    })
                    .collect();
                let constraints = [
                    Constraint::Length(5),
                    Constraint::Length(7),
                    Constraint::Length(50),
                    Constraint::Length(47),
                ];
                let header = Row::new(["Port", "Con/min", "User(s)", "Peer(s)"])
                    .add_modifier(Modifier::UNDERLINED);
                let title =
                    Block::new().title(Line::from("TCP services".fg(color).bold()).centered());
                Table::new(rows, constraints)
                    .header(header)
                    .column_spacing(1)
                    .block(title)
                    .row_highlight_style(Style::new().fg(color).reversed())
            }
            Tab::Alias => {
                // Get data for aliases
                let data = self.server.alias_data.read().unwrap().clone();
                self.vertical_scroll = self.vertical_scroll.content_length(data.len());
                // Create rows for each socket or alias
                let rows: Vec<Row<'_>> = data
                    .iter()
                    .map(|(TcpAlias(alias, port), (connections, conns_per_min))| {
                        let len = connections.len() as u16;
                        let (peers, users): (Vec<_>, Vec<_>) = connections.iter().unzip();
                        Row::new(vec![
                            format!("{}:{}", alias, port),
                            conns_per_min.to_string(),
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
                let header = Row::new(["Alias", "Con/min", "User(s)", "Peer(s)"])
                    .add_modifier(Modifier::UNDERLINED);
                let title =
                    Block::new().title(Line::from("Alias services".fg(color).bold()).centered());
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
        // Break into four areas, first horizontally then vertically
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

// Data for a terminal interface
struct AdminTerminal {
    // The underlying terminal backend used by Ratatui
    terminal: Terminal<CrosstermBackend<BufferedSender>>,
    // Stateful data for the terminal
    state: AdminState,
}

// Instance of the displayed admin interface
pub(crate) struct AdminInterface {
    // Reference to the terminal interface
    interface: Arc<Mutex<AdminTerminal>>,
    // Task that updates the interface
    _join_handle: DroppableHandle<()>,
    // Handler for change events, such as key presses
    change_notifier: watch::Sender<()>,
}

impl AdminInterface {
    // Create an admin interface and send its output to the provided UnboundedSender
    pub(crate) fn new(tx: ServerHandlerSender, server: Arc<SandholeServer>) -> Self {
        let backend = CrosstermBackend::new(BufferedSender {
            tx,
            buf: Vec::new(),
        });
        let options = TerminalOptions {
            viewport: Viewport::Fixed(Rect::new(0, 0, 120, 60)),
        };
        // Create a channel to listen for user-generated events
        let (change_notifier, mut subscriber) = watch::channel(());
        let mut tabs = Vec::new();
        if !server.disable_http {
            tabs.push(Tab::Http);
            if !server.disable_sni {
                tabs.push(Tab::Sni);
            }
        }
        if !server.disable_aliasing {
            tabs.push(Tab::Ssh);
        }
        if !server.disable_tcp {
            tabs.push(Tab::Tcp);
        }
        if !server.disable_aliasing {
            tabs.push(Tab::Alias);
        }
        let interface = Arc::new(Mutex::new(AdminTerminal {
            terminal: Terminal::with_options(backend, options).unwrap(),
            state: AdminState {
                server,
                enabled: true,
                tab: TabData { tabs, current: 0 },
                is_pty: false,
                table_state: Default::default(),
                vertical_scroll: Default::default(),
                prompt: None,
            },
        }));
        let interface_clone = Arc::clone(&interface);
        // Start task to update the admin interface
        let join_handle = DroppableHandle(tokio::spawn(async move {
            loop {
                {
                    let mut interface = interface.lock().unwrap();
                    let AdminTerminal { terminal, state } = interface.deref_mut();
                    if state.enabled
                        && terminal
                            .draw(|frame| {
                                // Render the terminal
                                state.render(frame.area(), frame.buffer_mut());
                            })
                            .is_err()
                    {
                        break;
                    }
                }
                // Wait one second or for an user-generated event to refresh the interface
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
            interface.state.tab.next();
            interface.state.table_state = Default::default();
            interface.state.vertical_scroll = Default::default();
        }
        let _ = self.change_notifier.send(());
    }

    // Go back one tab
    pub(crate) fn previous_tab(&mut self) {
        {
            let mut interface = self.interface.lock().unwrap();
            interface.state.tab.previous();
            interface.state.table_state = Default::default();
            interface.state.vertical_scroll = Default::default();
        }
        let _ = self.change_notifier.send(());
    }

    // Move down in the prompt or selected tab's table
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

    // Move up in the prompt or selected tab's table
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

    // Cancel current selection in the prompt or table
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
                // Close the infobox
                Some(AdminPrompt::Infobox(_)) => {
                    interface.state.prompt = None;
                    true
                }
                // Confirm removal of the user
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
                            sessions.values().for_each(|cancellation_token| {
                                cancellation_token.cancel();
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
                        sessions.values().for_each(|cancellation_token| {
                            cancellation_token.cancel();
                        });
                    }
                    interface.state.prompt = Some(AdminPrompt::Infobox(text));
                    true
                }
                // Select a user
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
                // No prompt, select from table
                None => match interface.state.table_state.selected() {
                    Some(row) => {
                        let users: Option<Vec<String>> = match interface.state.tab.current_tab() {
                            Tab::Http => interface
                                .state
                                .server
                                .http_data
                                .read()
                                .unwrap()
                                .values()
                                .nth(row)
                                .map(|value| value.0.values().cloned().collect()),
                            Tab::Sni => interface
                                .state
                                .server
                                .sni_data
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
                                .map(|value| value.0.values().cloned().collect()),
                            Tab::Tcp => interface
                                .state
                                .server
                                .tcp_data
                                .read()
                                .unwrap()
                                .values()
                                .nth(row)
                                .map(|value| value.0.values().cloned().collect()),
                            Tab::Alias => interface
                                .state
                                .server
                                .alias_data
                                .read()
                                .unwrap()
                                .values()
                                .nth(row)
                                .map(|value| value.0.values().cloned().collect()),
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
                    }
                    _ => {
                        interface.state.prompt =
                            Some(AdminPrompt::Infobox("No row selected!".into()));
                        true
                    }
                },
            }
        };
        if notify {
            let _ = self.change_notifier.send(());
        }
    }

    // Mark user to prompt for deletion
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

    // Disable updates to the terminal for shutdown
    pub(crate) fn disable(&mut self) {
        let mut interface = self.interface.lock().unwrap();
        let _ = interface.terminal.show_cursor();
        let _ = interface.terminal.set_cursor_position(Position::ORIGIN);
        let _ = interface.terminal.flush();
        interface.state.enabled = false;
    }
}
