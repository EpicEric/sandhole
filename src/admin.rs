use std::{
    io,
    ops::DerefMut,
    sync::{Arc, Mutex},
    time::Duration,
};

use log::debug;
use ratatui::{
    layout::{Constraint, Margin},
    prelude::CrosstermBackend,
    style::{Style, Stylize},
    symbols::border,
    text::{Line, Text},
    widgets::{Block, Paragraph, Row, Table, TableState},
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

struct AdminState {
    is_pty: bool,
    tab: Tab,
    table_state: TableState,
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
                tab: Tab::Http,
                is_pty: false,
                table_state: Default::default(),
            },
        }));
        let interface_clone = Arc::clone(&interface);
        let jh = tokio::spawn(async move {
            let interface = interface;
            let server = server;
            loop {
                {
                    let mut interface = interface.lock().unwrap();
                    let AdminTerminal {
                        ref mut terminal,
                        ref mut state,
                    } = interface.deref_mut();
                    terminal
                        .draw(|frame| {
                            if state.is_pty {
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
                                let area = frame.area();
                                let inner = block.inner(area).inner(Margin::new(0, 1));
                                frame.render_widget(block, area);
                                match state.tab {
                                    Tab::Http => {
                                        let data = server.http_data.read().unwrap().clone();
                                        let rows = data.into_iter().map(|(k, v)| {
                                            let len = v.len() as u16;
                                            Row::new(vec![k, v.into_iter().map(|addr| addr.to_string()).collect::<Vec<_>>().join("\n")]).height(len)
                                        });
                                        let constraints = [
                                            Constraint::Fill(2),
                                            Constraint::Fill(5),
                                        ];
                                        let header = Row::new(["Host", "Peer(s)"]);
                                        let title = Block::new().title(Line::from("HTTP services".blue().bold()).centered());
                                        let style = Style::new().blue();
                                        let table = Table::new(rows, constraints)
                                            .style(style)
                                            .header(header)
                                            .column_spacing(1)
                                            .block(title)
                                            .row_highlight_style(Style::new().reversed());
                                        frame.render_stateful_widget(table, inner, &mut state.table_state);
                                    },
                                    Tab::Ssh => {
                                        let data = server.ssh_data.read().unwrap().clone();
                                        let rows = data.into_iter().map(|(k, v)| {
                                            let len = v.len() as u16;
                                            Row::new(vec![k, v.into_iter().map(|addr| addr.to_string()).collect::<Vec<_>>().join("\n")]).height(len)
                                        });
                                        let constraints = [
                                            Constraint::Fill(2),
                                            Constraint::Fill(5),
                                        ];
                                        let header = Row::new(["Host", "Peer(s)"]);
                                        let title = Block::new().title(Line::from("SSH services".yellow().bold()).centered());
                                        let style = Style::new().yellow();
                                        let table = Table::new(rows, constraints)
                                            .style(style)
                                            .header(header)
                                            .column_spacing(1)
                                            .block(title)
                                            .row_highlight_style(Style::new().reversed());
                                        frame.render_stateful_widget(table, inner, &mut state.table_state);
                                    },
                                    Tab::Tcp => {
                                        let data = server.tcp_data.read().unwrap().clone();
                                        let rows = data.into_iter().map(|(k, v)| {
                                            let len = v.len() as u16;
                                            Row::new(vec![k.0, k.1.to_string(), v.into_iter().map(|addr| addr.to_string()).collect::<Vec<_>>().join("\n")]).height(len)
                                        });
                                        let constraints = [
                                            Constraint::Fill(2),
                                            Constraint::Fill(1),
                                            Constraint::Fill(10),
                                        ];
                                        let header = Row::new(["Alias", "Port", "Peer(s)"]);
                                        let title = Block::new().title(Line::from("TCP services".green().bold()).centered());
                                        let style = Style::new().green();
                                        let table = Table::new(rows, constraints)
                                            .style(style)
                                            .header(header)
                                            .column_spacing(1)
                                            .block(title)
                                            .row_highlight_style(Style::new().reversed());
                                        frame.render_stateful_widget(table, inner, &mut state.table_state);
                                    },
                                }
                            } else {
                                let text = Text::from(vec![
                                    Line::from(
                                        "PTY not detected! Make sure to connect with \"ssh -t ... admin\" instead."
                                            .red(),
                                    ),
                                    Line::from(
                                        "Press Ctrl-C to close this connection."
                                    )]);
                                let widget = Paragraph::new(text).left_aligned();
                                let area = frame.area();
                                frame.render_widget(widget, area);
                            }
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

    pub(crate) fn advance_tab(&mut self) {
        debug!("advance_tab");
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
