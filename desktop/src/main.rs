#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod paths;
mod protocol;
mod secret_input;
mod session;
mod tray;
mod worker;

fn main() {
    let worker = std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--mount-worker"));
    if let Err(error) = nullguard::platform::harden_process() {
        let message = format!("Could not enable process memory protection: {error}");
        eprintln!("{message}");
        if worker {
            // No request or credentials have been read. Report the failure
            // on the existing worker protocol without starting the worker.
            let _ = serde_json::to_writer(std::io::stdout(), &protocol::Event::Error(message));
            println!();
        } else {
            let _ = rfd::MessageDialog::new()
                .set_title("Nullguard could not start")
                .set_description(message)
                .set_level(rfd::MessageLevel::Error)
                .show();
        }
        std::process::exit(1);
    }
    if worker {
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
