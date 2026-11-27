//! Pre-sleep / hibernate locking via systemd-logind, as an UNPRIVILEGED D-Bus client.
//!
//! The previous implementation shelled out to `busctl --system monitor`, which needs the
//! root-only `BecomeMonitor` call and therefore silently never worked for a user daemon.
//!
//! This module instead:
//! 1. subscribes to `org.freedesktop.login1.Manager.PrepareForSleep` with an ordinary
//!    `AddMatch` rule pinned to logind's *unique* bus name (other system-bus clients cannot
//!    spoof the signal: the bus daemon stamps the real sender),
//! 2. holds a logind **delay inhibitor** (`Inhibit("sleep", …, "delay")`) so the kernel does not
//!    suspend/hibernate until we have wiped keys (bounded by logind's `InhibitDelayMaxSec`),
//! 3. on `PrepareForSleep(true)` runs the caller's lock callback, *then* releases the
//!    inhibitor so sleep proceeds; on `PrepareForSleep(false)` (resume) re-acquires it.
//!
//! Failures are never silent: the current state is observable via [`SleepMonitor::state`] and
//! the thread keeps retrying with backoff (e.g. if logind or the system bus restarts).

use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use dbus::blocking::Connection;
use dbus::message::MatchRule;
use dbus::strings::BusName;

const LOGIN1_NAME: &str = "org.freedesktop.login1";
const LOGIN1_PATH: &str = "/org/freedesktop/login1";
const LOGIN1_MANAGER: &str = "org.freedesktop.login1.Manager";
const DBUS_CALL_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_SLICE: Duration = Duration::from_millis(250);
const OWNER_RECHECK: Duration = Duration::from_secs(30);
const RETRY_BACKOFF: Duration = Duration::from_secs(5);

/// Observable health of the pre-sleep monitor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SleepMonitorState {
    Starting,
    /// Subscribed to `PrepareForSleep` and holding a sleep delay inhibitor.
    Active,
    /// Subscribed, but logind refused the delay inhibitor (locking still happens on the
    /// signal, but suspend may race the wipe).
    ActiveNoInhibitor(String),
    /// Not subscribed; retrying.
    Failed(String),
    Stopped,
}

impl SleepMonitorState {
    pub fn describe(&self) -> String {
        match self {
            Self::Starting => "starting".into(),
            Self::Active => "active (logind PrepareForSleep + delay inhibitor)".into(),
            Self::ActiveNoInhibitor(e) => format!("active WITHOUT sleep inhibitor ({e})"),
            Self::Failed(e) => format!("FAILED ({e}); retrying"),
            Self::Stopped => "stopped".into(),
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active | Self::ActiveNoInhibitor(_))
    }
}

/// Background pre-sleep monitor. Dropping it stops and joins the thread.
pub struct SleepMonitor {
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<SleepMonitorState>>,
    handle: Option<JoinHandle<()>>,
}

impl SleepMonitor {
    /// Spawn the monitor. `on_sleep` MUST synchronously finish wiping secrets before returning:
    /// the sleep inhibitor is released only after it returns.
    pub fn spawn<F>(on_sleep: F) -> Self
    where
        F: Fn() + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(SleepMonitorState::Starting));
        let t_stop = Arc::clone(&stop);
        let t_state = Arc::clone(&state);
        let handle = thread::Builder::new()
            .name("omavault-presleep".into())
            .spawn(move || {
                while !t_stop.load(Ordering::SeqCst) {
                    if let Err(e) = run_session(&on_sleep, &t_stop, &t_state) {
                        let msg = e.to_string();
                        crate::error::warn(&format!("pre-sleep monitor error: {msg}"));
                        set_state(&t_state, SleepMonitorState::Failed(msg));
                        sleep_unless_stopped(&t_stop, RETRY_BACKOFF);
                    }
                }
                set_state(&t_state, SleepMonitorState::Stopped);
            })
            .ok();
        if handle.is_none() {
            set_state(
                &state,
                SleepMonitorState::Failed("could not spawn monitor thread".into()),
            );
        }
        Self {
            stop,
            state,
            handle,
        }
    }

    pub fn state(&self) -> SleepMonitorState {
        self.state
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }

    /// Shared handle for reporting the state from other threads (e.g. daemon `Status`).
    pub fn state_handle(&self) -> Arc<Mutex<SleepMonitorState>> {
        Arc::clone(&self.state)
    }
}

impl Drop for SleepMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn set_state(state: &Mutex<SleepMonitorState>, s: SleepMonitorState) {
    match state.lock() {
        Ok(mut g) => *g = s,
        Err(e) => *e.into_inner() = s,
    }
}

fn sleep_unless_stopped(stop: &AtomicBool, total: Duration) {
    let deadline = Instant::now() + total;
    while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(PROCESS_SLICE);
    }
}

fn login1_owner(conn: &Connection) -> Result<String, dbus::Error> {
    let proxy = conn.with_proxy(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        DBUS_CALL_TIMEOUT,
    );
    let (owner,): (String,) =
        proxy.method_call("org.freedesktop.DBus", "GetNameOwner", (LOGIN1_NAME,))?;
    Ok(owner)
}

fn take_inhibitor(conn: &Connection) -> Result<OwnedFd, dbus::Error> {
    let proxy = conn.with_proxy(LOGIN1_NAME, LOGIN1_PATH, DBUS_CALL_TIMEOUT);
    let (fd,): (OwnedFd,) = proxy.method_call(
        LOGIN1_MANAGER,
        "Inhibit",
        (
            "sleep",
            "omavault",
            "Wipe password vault keys from RAM before sleep",
            "delay",
        ),
    )?;
    Ok(fd)
}

/// One connected session; returns `Err` to trigger a reconnect.
fn run_session<F: Fn()>(
    on_sleep: &F,
    stop: &AtomicBool,
    state: &Mutex<SleepMonitorState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::new_system()?;
    let owner = login1_owner(&conn)?;

    let pending: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let cb_pending = Arc::clone(&pending);
    let rule = MatchRule::new_signal(LOGIN1_MANAGER, "PrepareForSleep")
        .with_strict_sender(BusName::new(owner.clone())?)
        .with_path(LOGIN1_PATH);
    conn.add_match(rule, move |(start,): (bool,), _conn, _msg| {
        if let Ok(mut p) = cb_pending.lock() {
            // A `true` (going to sleep) must never be overwritten by a later `false`.
            if *p != Some(true) {
                *p = Some(start);
            }
        }
        true
    })?;

    let mut inhibitor = acquire_inhibitor(&conn, state);
    let mut last_owner_check = Instant::now();

    while !stop.load(Ordering::SeqCst) {
        conn.process(PROCESS_SLICE)?;

        let event = pending.lock().ok().and_then(|mut p| p.take());
        match event {
            Some(true) => {
                on_sleep();
                // Secrets are wiped: release the delay inhibitor so sleep can proceed.
                drop(inhibitor.take());
            }
            Some(false) if inhibitor.is_none() => {
                inhibitor = acquire_inhibitor(&conn, state);
            }
            _ => {}
        }

        if last_owner_check.elapsed() >= OWNER_RECHECK {
            last_owner_check = Instant::now();
            if login1_owner(&conn)? != owner {
                return Err("systemd-logind restarted; resubscribing".into());
            }
            if inhibitor.is_none() {
                inhibitor = acquire_inhibitor(&conn, state);
            }
        }
    }
    Ok(())
}

fn acquire_inhibitor(conn: &Connection, state: &Mutex<SleepMonitorState>) -> Option<OwnedFd> {
    match take_inhibitor(conn) {
        Ok(fd) => {
            set_state(state, SleepMonitorState::Active);
            Some(fd)
        }
        Err(e) => {
            let msg = e.message().unwrap_or("Inhibit call failed").to_string();
            set_state(state, SleepMonitorState::ActiveNoInhibitor(msg));
            None
        }
    }
}
