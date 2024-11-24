use std::{
    io,
    ops::DerefMut,
    sync::{Arc, Mutex},
    time::Duration,
};

use log::debug;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Margin, Rect},
    prelude::CrosstermBackend,
    style::{Style, Stylize},
    symbols::border,
    text::{Line, Text},
    widgets::{Block, Paragraph, Row, StatefulWidget, Table, TableState, Tabs, Widget},
    Terminal, TerminalOptions, Viewport,
};
use tokio::{
    sync::{mpsc::UnboundedSender, watch},
    task::JoinHandle,
    time::sleep,
};

use crate::SandholeServer;

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
            Line::from("  HTTP  ".black().on_blue()),
            Line::from("  SSH  ".black().on_yellow()),
            Line::from("  TCP  ".black().on_green()),
        ])
        .select(selected)
        .highlight_style(Style::new().bold())
        .divider(" ")
        .render(area, buf);
    }
}

impl Tab {
    fn index(&self) -> usize {
        match self {
            Tab::Http => 0,
            Tab::Ssh => 1,
            Tab::Tcp => 2,
        }
    }
}

struct AdminState {
    server: Arc<SandholeServer>,
    is_pty: bool,
    tab: Tab,
    table_state: TableState,
}

impl AdminState {
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
            let [tabs_area, inner_area] =
                Layout::vertical([Constraint::Length(1), Constraint::Min(0)])
                    .areas(area.inner(Margin::new(2, 2)));
            Tab::render(tabs_area, buf, self.tab.index());
            Block::bordered()
                .border_style(match self.tab {
                    Tab::Http => Style::new().blue(),
                    Tab::Ssh => Style::new().yellow(),
                    Tab::Tcp => Style::new().green(),
                })
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

    fn render_tab(&mut self, area: Rect, buf: &mut Buffer) {
        match self.tab {
            Tab::Http => {
                let data = self.server.http_data.read().unwrap().clone();
                let rows = data.into_iter().map(|(k, v)| {
                    let len = v.len() as u16;
                    Row::new(vec![
                        k,
                        v.into_iter()
                            .map(|addr| addr.to_string())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ])
                    .height(len)
                });
                let constraints = [Constraint::Fill(2), Constraint::Fill(5)];
                let header = Row::new(["Host", "Peer(s)"]);
                let title =
                    Block::new().title(Line::from("HTTP services".blue().bold()).centered());
                let table = Table::new(rows, constraints)
                    .header(header)
                    .column_spacing(1)
                    .block(title)
                    .row_highlight_style(Style::new().blue().reversed());
                StatefulWidget::render(table, area, buf, &mut self.table_state);
            }
            Tab::Ssh => {
                let data = self.server.ssh_data.read().unwrap().clone();
                let rows = data.into_iter().map(|(k, v)| {
                    let len = v.len() as u16;
                    Row::new(vec![
                        k,
                        v.into_iter()
                            .map(|addr| addr.to_string())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ])
                    .height(len)
                });
                let constraints = [Constraint::Fill(2), Constraint::Fill(5)];
                let header = Row::new(["Host", "Peer(s)"]);
                let title =
                    Block::new().title(Line::from("SSH services".yellow().bold()).centered());
                let table = Table::new(rows, constraints)
                    .header(header)
                    .column_spacing(1)
                    .block(title)
                    .row_highlight_style(Style::new().yellow().reversed());
                StatefulWidget::render(table, area, buf, &mut self.table_state);
            }
            Tab::Tcp => {
                let data = self.server.tcp_data.read().unwrap().clone();
                let rows = data.into_iter().map(|(k, v)| {
                    let len = v.len() as u16;
                    Row::new(vec![
                        k.0,
                        k.1.to_string(),
                        v.into_iter()
                            .map(|addr| addr.to_string())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ])
                    .height(len)
                });
                let constraints = [
                    Constraint::Fill(2),
                    Constraint::Length(5),
                    Constraint::Fill(5),
                ];
                let header = Row::new(["Alias", "Port", "Peer(s)"]);
                let title =
                    Block::new().title(Line::from("TCP services".green().bold()).centered());
                let table = Table::new(rows, constraints)
                    .header(header)
                    .column_spacing(1)
                    .block(title)
                    .row_highlight_style(Style::new().green().reversed());
                StatefulWidget::render(table, area, buf, &mut self.table_state);
            }
        }
    }
}

struct AdminTerminal {
    terminal: Terminal<CrosstermBackend<BufferedSender>>,
    state: AdminState,
}

pub(crate) struct AdminInterface {
    interface: Arc<Mutex<AdminTerminal>>,
    jh: JoinHandle<()>,
    change_notifier: watch::Sender<()>,
}

//struct TerminalApp(Terminal<CrosstermBackend<BufferedSender>>);

impl AdminInterface {
    pub(crate) fn new(tx: UnboundedSender<Vec<u8>>, server: Arc<SandholeServer>) -> Self {
        let backend = CrosstermBackend::new(BufferedSender {
            tx,
            buf: Vec::new(),
        });
        let options = TerminalOptions {
            viewport: Viewport::Fullscreen,
        };
        let (change_notifier, mut subscriber) = watch::channel(());
        let interface = Arc::new(Mutex::new(AdminTerminal {
            terminal: Terminal::with_options(backend, options).unwrap(),
            state: AdminState {
                server,
                tab: Tab::Http,
                is_pty: false,
                table_state: Default::default(),
            },
        }));
        let interface_clone = Arc::clone(&interface);
        let jh = tokio::spawn(async move {
            let interface = interface;
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
                        })
                        .unwrap();
                    terminal.show_cursor().unwrap();
                    drop(interface);
                }
                tokio::select! {
                    _ = sleep(Duration::from_millis(1_000)) => (),
                    _ = subscriber.changed() => ()
                }
            }
        });
        Self {
            interface: interface_clone,
            jh,
            change_notifier,
        }
    }

    pub(crate) fn resize(&mut self, width: u16, height: u16) -> anyhow::Result<()> {
        debug!("resize");
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

    pub(crate) fn next_tab(&mut self) {
        debug!("next_tab");
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
            drop(interface);
        }
        let _ = self.change_notifier.send(());
    }

    pub(crate) fn previous_tab(&mut self) {
        debug!("previous_tab");
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
            drop(interface);
        }
        let _ = self.change_notifier.send(());
    }

    pub(crate) fn move_down(&mut self) {
        {
            let mut interface = self.interface.lock().unwrap();
            interface.state.table_state.select_next();
            drop(interface);
        }
        let _ = self.change_notifier.send(());
    }

    pub(crate) fn move_up(&mut self) {
        {
            let mut interface = self.interface.lock().unwrap();
            interface.state.table_state.select_previous();
            drop(interface);
        }
        let _ = self.change_notifier.send(());
    }
}

impl Drop for AdminInterface {
    fn drop(&mut self) {
        self.jh.abort();
    }
}
