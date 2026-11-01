//! Bound live workers and serialize expensive startup work in this GUI.
use std::sync::{Arc, Mutex, OnceLock};

const MAX_WORKERS: usize = 4;

#[derive(Default)]
struct State { active: usize, starting: bool }

#[derive(Default)]
struct Gate(Arc<Mutex<State>>);

pub struct Permit { gate: Arc<Mutex<State>>, starting: bool }

impl Gate {
    fn acquire(&self) -> anyhow::Result<Permit> {
        let mut state = self.0.lock().map_err(|_| anyhow::anyhow!("Worker admission is unavailable; restart the app."))?;
        anyhow::ensure!(!state.starting, "Wait for the current vault operation to finish starting.");
        anyhow::ensure!(state.active < MAX_WORKERS, "Four vault workers are already running. Lock a vault before opening another.");
        state.active += 1;
        state.starting = true;
        Ok(Permit { gate: self.0.clone(), starting: true })
    }
}

pub fn acquire() -> anyhow::Result<Permit> {
    static GATE: OnceLock<Gate> = OnceLock::new();
    GATE.get_or_init(Gate::default).acquire()
}

impl Permit {
    pub fn ready(&mut self) {
        if self.starting {
            if let Ok(mut state) = self.gate.lock() { state.starting = false; }
            self.starting = false;
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.lock() {
            state.active -= 1;
            if self.starting { state.starting = false; }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_serializes_startup_and_tracks_live_workers() {
        let gate = Gate::default();
        let mut workers = Vec::new();
        for _ in 0..MAX_WORKERS {
            let mut permit = gate.acquire().unwrap();
            assert!(gate.acquire().is_err());
            permit.ready();
            permit.ready();
            workers.push(permit);
        }
        assert!(gate.acquire().is_err());
        workers.pop();
        assert!(gate.acquire().is_ok());
        drop(workers);
        assert_eq!(gate.0.lock().unwrap().active, 0);
    }
    #[test]
    fn failed_startup_releases_admission() {
        let gate = Gate::default();
        let result = std::panic::catch_unwind(|| {
            let _permit = gate.acquire().unwrap();
            panic!("startup failed");
        });
        assert!(result.is_err());
        assert!(gate.acquire().is_ok());
    }
}
