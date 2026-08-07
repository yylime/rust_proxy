//! rust-proxy-server: a minimal Rust proxy server implementing the
//! Hysteria2 and AnyTLS server-side protocols, based on cfal/shoes.

mod address;
mod anytls;
mod async_stream;
mod config;
mod copy_bidirectional;
mod dial;
mod hysteria2;
mod message_stream;
mod quic_stream;
mod resolver;
mod socket_util;
mod stream_reader;
mod tls_config;
mod udp_relay;
mod util;

use std::sync::Arc;
use std::time::Duration;

use config::{Config, ServerConfig};
use tokio::task::JoinHandle;

fn print_usage_and_exit(arg0: String) -> ! {
    eprintln!("{arg0} [OPTIONS]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    -c, --config PATH   Path to the YAML config file (default: config.yaml)");
    eprintln!("    -d, --dry-run       Parse the config and exit");
    eprintln!("    -h, --help          Print this help and exit");
    eprintln!();
    eprintln!("Supported server types: hysteria2, anytls");
    std::process::exit(1);
}

fn parse_log_level(level: &str) -> log::LevelFilter {
    match level.to_ascii_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" | "warning" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        "off" => log::LevelFilter::Off,
        other => {
            eprintln!("Unknown log_level '{other}', using info");
            log::LevelFilter::Info
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg0 = args[0].clone();
    let mut config_path = "config.yaml".to_string();
    let mut dry_run = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for {}", args[i - 1]);
                    print_usage_and_exit(arg0);
                }
                config_path = args[i].clone();
            }
            "-d" | "--dry-run" => dry_run = true,
            "-h" | "--help" => print_usage_and_exit(arg0),
            other => {
                eprintln!("Unknown option: {other}");
                print_usage_and_exit(arg0);
            }
        }
        i += 1;
    }

    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    env_logger::Builder::new()
        .filter_level(parse_log_level(&config.log_level))
        .format_timestamp_secs()
        .init();

    if config.servers.is_empty() {
        eprintln!("No servers configured in {config_path}");
        std::process::exit(1);
    }

    for server in &config.servers {
        match server {
            ServerConfig::Hysteria2(cfg) => {
                println!(
                    "hysteria2 server: listen={} udp_enabled={}",
                    cfg.listen, cfg.udp_enabled
                );
            }
            ServerConfig::Anytls(cfg) => {
                println!(
                    "anytls server: listen={} users={} udp_enabled={}",
                    cfg.listen,
                    cfg.users.len(),
                    cfg.udp_enabled
                );
            }
        }
    }

    if dry_run {
        println!("Config OK");
        return;
    }

    let resolver = Arc::new(resolver::Resolver::new());
    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for server in config.servers.clone() {
        let resolver = resolver.clone();
        let handle = match server {
            ServerConfig::Hysteria2(cfg) => {
                let runtime_cfg = hysteria2::Hysteria2ServerConfig {
                    listen: cfg.listen,
                    password: cfg.password,
                    udp_enabled: cfg.udp_enabled,
                    cert: cfg.cert,
                    key: cfg.key,
                    alpn: cfg.alpn,
                };
                match hysteria2::run_server(runtime_cfg, resolver).await {
                    Ok(h) => h,
                    Err(e) => {
                        log::error!("Failed to start hysteria2 server: {e}");
                        std::process::exit(1);
                    }
                }
            }
            ServerConfig::Anytls(cfg) => {
                let runtime_cfg = anytls::server::AnyTlsServerConfig {
                    listen: cfg.listen,
                    cert: cfg.cert,
                    key: cfg.key,
                    udp_enabled: cfg.udp_enabled,
                    users: cfg
                        .users
                        .into_iter()
                        .map(|u| (u.name, u.password))
                        .collect(),
                    padding_scheme: cfg.padding_scheme,
                    fallback: cfg.fallback,
                };
                match anytls::server::run_server(runtime_cfg, resolver).await {
                    Ok(h) => h,
                    Err(e) => {
                        log::error!("Failed to start anytls server: {e}");
                        std::process::exit(1);
                    }
                }
            }
        };
        handles.push(handle);
    }

    log::info!(
        "Started {} server(s). Press Ctrl+C to stop.",
        handles.len()
    );

    tokio::signal::ctrl_c().await.expect("failed to listen for Ctrl+C");
    log::info!("Received Ctrl+C, shutting down...");

    for handle in handles {
        handle.abort();
    }
    // Give tasks a brief moment to unwind.
    tokio::time::sleep(Duration::from_millis(200)).await;
    log::info!("Shutdown complete");
}
