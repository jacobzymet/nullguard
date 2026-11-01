#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
use nullguard_desktop::{paths, protocol, session};
mod secret_input;
mod tray;

fn main() {
    if let Err(error) = nullguard::platform::harden_process() {
        let message = format!("Could not enable process memory protection: {error}");
        eprintln!("{message}");
        let _ = rfd::MessageDialog::new()
            .set_title("Nullguard could not start")
            .set_description(message)
            .set_level(rfd::MessageLevel::Error)
            .show();
        std::process::exit(1);
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
