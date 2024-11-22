use std::{
    io,
    ops::DerefMut,
    sync::{Arc, Mutex},
    time::Duration,
};

use log::debug;
use ratatui::{
    prelude::CrosstermBackend,
    style::Stylize,
    symbols::border,
    text::{Line, Text},
    widgets::{Block, Paragraph},
    Terminal, TerminalOptions, Viewport,
};
use tokio::{
    sync::{mpsc::UnboundedSender, watch},
    task::JoinHandle,
    time::sleep,
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
    Main,
    Test,
}

struct AdminState {
    is_pty: bool,
    tab: Tab,
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
    pub(crate) fn new(tx: UnboundedSender<Vec<u8>>) -> Self {
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
                tab: Tab::Main,
                is_pty: false,
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
                        ref state,
                    } = interface.deref_mut();
                    terminal
                        .draw(|frame| {
                            if state.is_pty {
                                let title = Line::from(" Sandhole admin ".bold());
                                let instructions = Line::from(vec![
                                    " <Tab> ".blue().bold(),
                                    "Change tab ".into(),
                                    " <Ctrl-C> ".blue().bold(),
                                    " Quit ".into(),
                                ]);
                                let block = Block::bordered()
                                    .title(title.centered())
                                    .title_bottom(instructions.centered())
                                    .border_set(border::THICK);
                                let text = Text::from(vec![Line::from(match state.tab {
                                    Tab::Main => "Hello, world!".yellow(),
                                    Tab::Test => "Hello, world!".red(),
                                })]);
                                let widget = Paragraph::new(text).centered().block(block);
                                let area = frame.area();
                                frame.render_widget(widget, area);
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
                Tab::Main => {
                    interface.state.tab = Tab::Test;
                }
                Tab::Test => {
                    interface.state.tab = Tab::Main;
                }
            }
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
