use std::io::Write;

use ratatui::{
    backend::{Backend, ClearType, CrosstermBackend, WindowSize},
    buffer::Cell,
    layout::{Position, Size},
};

pub(crate) struct PtyBackend<W: Write> {
    inner: CrosstermBackend<W>,
    size: Size,
}

impl<W: Write> PtyBackend<W> {
    pub(crate) fn new(writer: W, size: Size) -> Self {
        Self {
            inner: CrosstermBackend::new(writer),
            size,
        }
    }

    pub(crate) fn set_size(&mut self, size: Size) {
        self.size = size;
    }
}

impl<W: Write> Backend for PtyBackend<W> {
    type Error = std::io::Error;

    fn draw<'a, I>(&mut self, content: I) -> std::io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        self.inner.draw(content)
    }
    fn hide_cursor(&mut self) -> std::io::Result<()> {
        self.inner.hide_cursor()
    }
    fn show_cursor(&mut self) -> std::io::Result<()> {
        self.inner.show_cursor()
    }
    fn get_cursor_position(&mut self) -> std::io::Result<Position> {
        self.inner.get_cursor_position()
    }
    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> std::io::Result<()> {
        self.inner.set_cursor_position(position)
    }
    fn clear(&mut self) -> std::io::Result<()> {
        self.inner.clear()
    }
    fn clear_region(&mut self, clear_type: ClearType) -> std::io::Result<()> {
        self.inner.clear_region(clear_type)
    }
    fn size(&self) -> std::io::Result<Size> {
        Ok(self.size)
    }
    fn window_size(&mut self) -> std::io::Result<WindowSize> {
        self.inner.window_size()
    }
    fn flush(&mut self) -> std::io::Result<()> {
        <CrosstermBackend<W> as Backend>::flush(&mut self.inner)
    }
}

impl<W: Write> Write for PtyBackend<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        <CrosstermBackend<W> as Write>::flush(&mut self.inner)
    }
}
