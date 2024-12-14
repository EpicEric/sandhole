use tokio::task::JoinHandle;

#[derive(Debug)]
// Join handle that aborts when it's dropped.
pub(crate) struct DroppableHandle<T>(pub(crate) JoinHandle<T>);

impl<T> Drop for DroppableHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
