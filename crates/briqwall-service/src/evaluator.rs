//! Gathers the facts about newly started programs on worker threads.
//!
//! Checking a file – its signature (possibly through the catalogs), who may
//! write to it, its version resource – takes from a few to a few hundred
//! milliseconds. Done on the core thread, every new program held up
//! everything else in the meantime: answers to the interface, filter updates,
//! the next program. So the process watcher hands paths to a few workers,
//! and the core receives a path together with the finished facts.
//!
//! The workers decide whether there is anything to gather from a shared table
//! of known files. That table is a hint, nothing depends on it being right:
//! the core checks again and gathers itself if it gets a path without facts.

use crate::core::Msg;
use crate::trust::{self, Facts};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};

/// App key (lower-case path) → size and time of the file as last gathered.
#[derive(Clone, Default)]
pub struct KnownFiles(Arc<RwLock<HashMap<String, Option<(u64, u64)>>>>);

impl KnownFiles {
    pub fn set(&self, key: &str, stamp: Option<(u64, u64)>) {
        if let Ok(mut m) = self.0.write() {
            m.insert(key.to_string(), stamp);
        }
    }

    pub fn remove(&self, key: &str) {
        if let Ok(mut m) = self.0.write() {
            m.remove(key);
        }
    }

    fn get(&self, key: &str) -> Option<Option<(u64, u64)>> {
        self.0.read().ok()?.get(key).copied()
    }
}

/// Is there something to gather for a file with this stamp? Not if the app is
/// known and the file is the one last looked at – the same test the core uses.
pub fn needs_facts(known: Option<Option<(u64, u64)>>, now: Option<(u64, u64)>) -> bool {
    match known {
        None => true,
        Some(then) => now.is_some() && now != then,
    }
}

/// Facts for a program that just started, if there is anything new to say.
/// Files off the local disks are left alone (see [`trust::is_local_path`]).
fn prepare(path: &str, known: &KnownFiles, win_dir: &str) -> Option<Facts> {
    if !trust::is_local_path(path) {
        return None;
    }
    let stamp = trust::file_stamp(path);
    needs_facts(known.get(&path.to_lowercase()), stamp).then(|| trust::gather(path, win_dir))
}

/// Start the workers. They take paths from `paths` and send each on to the
/// core, with facts where needed.
pub fn spawn(paths: Receiver<String>, core: Sender<Msg>, known: KnownFiles, win_dir: String) {
    let paths = Arc::new(Mutex::new(paths));
    // A program often starts several times at once (compilers, browsers).
    // One worker looks at the file; the others have nothing to add.
    let busy: Arc<Mutex<HashSet<String>>> = Arc::default();
    for i in 0..worker_count().min(4) {
        let (paths, core, known, win_dir, busy) = (paths.clone(), core.clone(), known.clone(), win_dir.clone(), busy.clone());
        let res = std::thread::Builder::new().name(format!("evaluate-{i}")).spawn(move || loop {
            let next = paths.lock().map(|rx| rx.recv());
            let Ok(Ok(path)) = next else { return };
            let key = path.to_lowercase();
            if !busy.lock().map(|mut b| b.insert(key.clone())).unwrap_or(true) {
                continue;
            }
            let facts = prepare(&path, &known, &win_dir);
            let sent = core.send(Msg::Process { path, facts });
            if let Ok(mut b) = busy.lock() {
                b.remove(&key);
            }
            if sent.is_err() {
                return;
            }
        });
        if let Err(e) = res {
            log::error!("Bewertungs-Thread konnte nicht gestartet werden: {e}");
        }
    }
}

fn worker_count() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2)
}

/// Gather the facts for many files at once (service start: everything that
/// is already running). `None` where `wanted` is false. Results are in the
/// order of `paths`.
pub fn gather_all(paths: &[String], wanted: &[bool], win_dir: &str) -> Vec<Option<Facts>> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out: Vec<Mutex<Option<Facts>>> = paths.iter().map(|_| Mutex::new(None)).collect();
    let jobs = wanted.iter().filter(|w| **w).count();
    std::thread::scope(|scope| {
        for _ in 0..worker_count().min(8).min(jobs) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(path) = paths.get(i) else { return };
                if wanted[i] {
                    let facts = trust::gather(path, win_dir);
                    if let Ok(mut slot) = out[i].lock() {
                        *slot = Some(facts);
                    }
                }
            });
        }
    });
    out.into_iter().map(|slot| slot.into_inner().unwrap_or(None)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_new_or_changed_files_are_looked_at() {
        let stamp = Some((10, 20));
        assert!(needs_facts(None, stamp), "unknown program");
        assert!(needs_facts(None, None), "unknown program whose file is gone");
        assert!(!needs_facts(Some(stamp), stamp), "known and unchanged");
        assert!(needs_facts(Some(stamp), Some((10, 21))), "known, file replaced");
        assert!(needs_facts(Some(None), stamp), "known, never stamped");
        assert!(!needs_facts(Some(stamp), None), "known, file not readable right now");
    }

    #[test]
    fn workers_send_facts_only_where_needed() {
        let win = trust::windows_dir();
        let notepad = format!(r"{win}\system32\notepad.exe");
        let known = KnownFiles::default();
        let (path_tx, path_rx) = std::sync::mpsc::channel();
        let (core_tx, core_rx) = std::sync::mpsc::channel();
        spawn(path_rx, core_tx, known.clone(), win.clone());

        let recv = || match core_rx.recv_timeout(std::time::Duration::from_secs(60)) {
            Ok(Msg::Process { path, facts }) => (path, facts),
            _ => panic!("no answer from the workers"),
        };
        // Unknown: comes with facts.
        path_tx.send(notepad.clone()).unwrap();
        let (path, facts) = recv();
        let facts = facts.expect("facts for an unknown program");
        assert_eq!(path, notepad);
        assert!(facts.protected && facts.signature.is_valid());
        // Known and unchanged: just the path.
        known.set(&notepad.to_lowercase(), facts.stamp);
        path_tx.send(notepad.clone()).unwrap();
        assert!(recv().1.is_none());
        // Forgotten again: facts again.
        known.remove(&notepad.to_lowercase());
        path_tx.send(notepad.clone()).unwrap();
        assert!(recv().1.is_some());
        // Not on a local disk: never opened here.
        path_tx.send(r"\\server\share\tool.exe".to_string()).unwrap();
        assert!(recv().1.is_none());
    }

    #[test]
    fn many_files_are_gathered_in_order() {
        let win = trust::windows_dir();
        let paths: Vec<String> =
            ["notepad.exe", "cmd.exe", "svchost.exe", "no-such-file.exe"].iter().map(|f| format!(r"{win}\system32\{f}")).collect();
        let facts = gather_all(&paths, &[true, false, true, true], &win);
        assert_eq!(facts.len(), 4);
        assert!(facts[0].as_ref().is_some_and(|f| f.exists && f.protected));
        assert!(facts[1].is_none(), "not wanted");
        assert!(facts[2].as_ref().is_some_and(|f| f.exists));
        assert!(facts[3].as_ref().is_some_and(|f| !f.exists));
        assert!(gather_all(&[], &[], &win).is_empty());
    }
}
