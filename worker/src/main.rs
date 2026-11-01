mod worker;
#[cfg(target_os = "linux")]
mod broker;
use nullguard_worker::protocol;

fn main() {
    #[cfg(target_os = "linux")]
    if std::env::args_os().nth(1).is_some_and(|arg| arg == "--unmount-broker") {
        let result = nullguard::platform::harden_process().map_err(anyhow::Error::from)
            .and_then(|_| broker::run());
        if let Err(error) = result { eprintln!("Unmount broker failed: {error:#}"); std::process::exit(1); }
        return;
    }
    if let Err(error) = nullguard::platform::harden_worker_process() {
        let _ = serde_json::to_writer(std::io::stdout(), &nullguard_worker::protocol::Event::Error(
            format!("Could not enable worker process protection: {error}")));
        println!();
        std::process::exit(1);
    }
    let result = worker::run();
    if let Err(error) = result {
        eprintln!("Vault worker failed: {error:#}");
        std::process::exit(1);
    }
}
