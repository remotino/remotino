//! Runs a blocking [`Repository`] on its own dedicated OS thread.
//!
//! `SqlRepo` owns a private tokio runtime and calls `block_on` on every operation. That
//! panics if it happens on a thread that is already inside another tokio runtime - which a
//! Tauri command thread may be. Rather than gamble on Tauri's threading, we own the repo on a
//! plain std thread (no ambient runtime) and forward each `Repository` call to it over a
//! channel. The calling thread just blocks on a reply, which is always safe.
//!
//! The local `SqliteRepo` doesn't need this (it's synchronous with no runtime), so it is used
//! directly; only the SQL backend is wrapped.

use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;

use remotino_crypto::chain::{Entry, Head, Seq};
use remotino_crypto::repository::Repository;
use remotino_crypto::{Error as CryptoError, Result as CryptoResult};

/// One request to the worker thread, carrying a reply channel.
enum Op {
    Append(Vec<Entry>, Sender<CryptoResult<Head>>),
    ReadFrom(Option<Seq>, Sender<CryptoResult<Vec<Entry>>>),
    Head(Sender<CryptoResult<Option<Head>>>),
}

/// A `Repository` whose actual work happens on a dedicated thread.
#[derive(Debug)]
pub struct ThreadedRepo {
    tx: Sender<Op>,
    _handle: JoinHandle<()>,
}

impl ThreadedRepo {
    /// Spawns the worker, building the repository inside it with `make`. Blocks until the
    /// repository is built (so connection/migration errors surface here), then serves calls.
    pub fn spawn<F>(make: F) -> Result<Self, String>
    where
        F: FnOnce() -> Result<Box<dyn Repository + Send>, String> + Send + 'static,
    {
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (op_tx, op_rx) = mpsc::channel::<Op>();

        let handle = std::thread::spawn(move || {
            let mut repo = match make() {
                Ok(repo) => {
                    let _ = ready_tx.send(Ok(()));
                    repo
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            // Serve until the sender is dropped (session closed).
            while let Ok(op) = op_rx.recv() {
                match op {
                    Op::Append(entries, reply) => {
                        let _ = reply.send(repo.append(&entries));
                    }
                    Op::ReadFrom(after, reply) => {
                        let _ = reply.send(repo.read_from(after));
                    }
                    Op::Head(reply) => {
                        let _ = reply.send(repo.head());
                    }
                }
            }
        });

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self { tx: op_tx, _handle: handle }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("repository worker thread failed to start".to_owned()),
        }
    }

    fn call<T>(&self, make_op: impl FnOnce(Sender<CryptoResult<T>>) -> Op) -> CryptoResult<T> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(make_op(reply_tx))
            .map_err(|_| CryptoError::Encoding("repository worker gone"))?;
        reply_rx
            .recv()
            .map_err(|_| CryptoError::Encoding("repository worker dropped the reply"))?
    }
}

impl Repository for ThreadedRepo {
    fn append(&mut self, entries: &[Entry]) -> CryptoResult<Head> {
        let owned = entries.to_vec();
        self.call(|reply| Op::Append(owned, reply))
    }

    fn read_from(&self, after: Option<Seq>) -> CryptoResult<Vec<Entry>> {
        self.call(|reply| Op::ReadFrom(after, reply))
    }

    fn head(&self) -> CryptoResult<Option<Head>> {
        self.call(Op::Head)
    }
}
