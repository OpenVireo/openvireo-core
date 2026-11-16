//! The `ov` binary. All the logic is in the `ov_cli` library.

fn main() {
    let argv: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ov: {e}");
            std::process::exit(1);
        }
    };
    let mut io = ov_cli::cli::Io::process();
    let code = runtime.block_on(ov_cli::cli::main(&argv, &mut io));
    std::process::exit(code);
}
