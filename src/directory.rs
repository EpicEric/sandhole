use std::{path::Path, time::Duration};

use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::watch::{self, Receiver};

// Listen to events in a directory, and send relevant updates in a watch channel.
pub(crate) fn watch_directory<W: Watcher>(
    directory: &Path,
    poll_interval: Duration,
) -> color_eyre::Result<(W, Receiver<()>)> {
    let (tx, rx) = watch::channel(());
    let mut watcher = W::new(
        move |res: notify::Result<Event>| {
            if let Ok(res) = res {
                match res.kind {
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                        tx.send_replace(());
                    }
                    _ => (),
                }
            };
        },
        notify::Config::default()
            .with_follow_symlinks(true)
            .with_poll_interval(poll_interval),
    )?;
    watcher.watch(directory, RecursiveMode::Recursive)?;
    Ok((watcher, rx))
}
