pub(crate) struct SandholeHandle(pub(crate) tokio::task::JoinHandle<color_eyre::Result<()>>);

impl Drop for SandholeHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}
