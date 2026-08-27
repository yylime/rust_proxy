//! Minimal DNS resolver with a small cache, replacing shoes' hickory-based
//! resolver for the direct-connect server.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

use lru::LruCache;
use std::num::NonZeroUsize;

use crate::address::NetLocation;

const CACHE_SIZE: usize = 1024;
const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

struct CacheEntry {
    addr: SocketAddr,
    inserted: Instant,
}

pub struct Resolver {
    cache: Mutex<LruCache<String, CacheEntry>>,
    /// TCP congestion control algorithm for outbound connections
    /// (e.g. "bbr", "cubic", or "" for system default).
    tcp_congestion: String,
}

impl Resolver {

    pub fn with_tcp_congestion(algo: String) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(CACHE_SIZE).expect("CACHE_SIZE must be non-zero"),
            )),
            tcp_congestion: algo,
        }
    }

    /// Returns the configured TCP congestion control algorithm.
    pub fn tcp_congestion(&self) -> &str {
        &self.tcp_congestion
    }

    /// Resolve a location into a concrete socket address.
    ///
    /// IP literals resolve immediately; hostnames go through the system
    /// resolver (tokio's `lookup_host`), with a small TTL cache.
    pub async fn resolve(&self, location: &NetLocation) -> std::io::Result<SocketAddr> {
        if let Some(addr) = location.to_socket_addr_nonblocking() {
            return Ok(addr);
        }

        let (address, port) = location.components();
        let hostname = address.hostname().expect("non-IP location");
        let key = format!("{}:{port}", hostname);

        // Check cache (and drop stale entries).
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(&key) {
                if entry.inserted.elapsed() < CACHE_TTL {
                    return Ok(entry.addr);
                }
            }
        }

        let addr = lookup_host(hostname, port).await?;

        let mut cache = self.cache.lock().unwrap();
        cache.put(
            key,
            CacheEntry {
                addr,
                inserted: Instant::now(),
            },
        );
        Ok(addr)
    }
}

async fn lookup_host(hostname: &str, port: u16) -> std::io::Result<SocketAddr> {
    let addrs = tokio::net::lookup_host((hostname, port)).await?;
    let mut addrs = addrs.collect::<Vec<_>>();
    // Prefer IPv4 to match typical direct-connect behavior.
    addrs.sort_by_key(|a| !a.is_ipv4());
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::other(format!("no addresses for {hostname}:{port}")))
}
