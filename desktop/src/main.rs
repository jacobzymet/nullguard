#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod paths;
mod protocol;
mod secret_input;
mod session;
mod tray;
mod worker;

fn main() {
    nullguard::platform::harden_process();
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--mount-worker")) {
        let success = worker::run().is_ok();
        std::process::exit(if success { 0 } else { 1 });
    }
    if let Err(error) = app::run() {
        eprintln!("Nullguard could not start: {error}");
        let _ = rfd::MessageDialog::new()
            .set_title("Nullguard could not start")
            .set_description(error.to_string())
            .set_level(rfd::MessageLevel::Error)
            .show();
    }
}
