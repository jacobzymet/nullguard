mod worker;
use nullguard_worker::protocol;

fn main() {
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
