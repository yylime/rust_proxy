//! Network address / location types, ported from shoes (src/address.rs).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Hostname(String),
}

impl Address {
    pub const UNSPECIFIED: Self = Address::Ipv4(Ipv4Addr::UNSPECIFIED);

    /// Parse an address string into an `Address`. IP literals are detected
    /// first; anything else is treated as a hostname.
    pub fn from(s: &str) -> std::io::Result<Self> {
        let mut dots = 0;
        let mut possible_ipv4 = true;
        let mut possible_ipv6 = true;
        let mut possible_hostname = true;
        for b in s.as_bytes().iter() {
            let c = *b;
            if c == b':' {
                possible_ipv4 = false;
                possible_hostname = false;
                break;
            } else if c == b'.' {
                possible_ipv6 = false;
                dots += 1;
                if dots > 3 {
                    // can only be a hostname.
                    break;
                }
            } else if (b'A'..=b'F').contains(&c) || (b'a'..=b'f').contains(&c) {
                possible_ipv4 = false;
            } else if !c.is_ascii_digit() {
                possible_ipv4 = false;
                possible_ipv6 = false;
                break;
            }
        }

        if possible_ipv4 && dots == 3 {
            if let Ok(addr) = s.parse::<Ipv4Addr>() {
                return Ok(Address::Ipv4(addr));
            }
        }

        if possible_ipv6 {
            if let Ok(addr) = s.parse::<Ipv6Addr>() {
                return Ok(Address::Ipv6(addr));
            }
        }

        if possible_hostname {
            return Ok(Address::Hostname(s.to_string()));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse address: {s}"),
        ))
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, Address::Ipv6(_))
    }

    pub fn hostname(&self) -> Option<&str> {
        match self {
            Address::Hostname(hostname) => Some(hostname),
            _ => None,
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Address::Ipv4(i) => write!(f, "{i}"),
            Address::Ipv6(i) => write!(f, "{i}"),
            Address::Hostname(h) => write!(f, "{h}"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct NetLocation {
    address: Address,
    port: u16,
}

impl NetLocation {
    pub const UNSPECIFIED: Self = NetLocation::new(Address::UNSPECIFIED, 0);

    pub const fn new(address: Address, port: u16) -> Self {
        Self { address, port }
    }

    pub fn is_unspecified(&self) -> bool {
        self == &Self::UNSPECIFIED
    }

    /// Parse "host:port" (or "[ipv6]:port") into a `NetLocation`.
    pub fn from_str(s: &str, default_port: Option<u16>) -> std::io::Result<Self> {
        let (address_str, port, expect_ipv6) = match s.rfind(':') {
            Some(i) => match s[i + 1..].parse::<u16>() {
                Ok(port) => (&s[0..i], Some(port), false),
                Err(_) => (s, default_port, true),
            },
            None => (s, default_port, false),
        };

        let address = Address::from(address_str)?;
        if expect_ipv6 && !address.is_ipv6() {
            return Err(std::io::Error::other("Invalid location"));
        }

        let port = port.ok_or_else(|| std::io::Error::other("No port"))?;

        Ok(Self { address, port })
    }

    pub fn components(&self) -> (&Address, u16) {
        (&self.address, self.port)
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn to_socket_addr_nonblocking(&self) -> Option<std::net::SocketAddr> {
        match self.address {
            Address::Ipv6(ref addr) => {
                Some(std::net::SocketAddr::new(IpAddr::V6(*addr), self.port))
            }
            Address::Ipv4(ref addr) => {
                Some(std::net::SocketAddr::new(IpAddr::V4(*addr), self.port))
            }
            Address::Hostname(_) => None,
        }
    }
}

impl std::fmt::Display for NetLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

impl<'de> serde::Deserialize<'de> for NetLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        NetLocation::from_str(&s, None).map_err(serde::de::Error::custom)
    }
}
