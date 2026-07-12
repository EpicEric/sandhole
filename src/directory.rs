// sandhole: Expose HTTP/SSH/TCP services through SSH port forwarding
// Copyright (C) 2024-2026 Eric Rodrigues Pires
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

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
