//! Shadowsocks target address encoding
//!
//! Implements the SOCKS5-style address format used by Shadowsocks:
//! - Type (1 byte): 0x01=IPv4, 0x03=Domain, 0x04=IPv6
//! - Address: 4 bytes (IPv4), 1+N bytes (Domain), 16 bytes (IPv6)
//! - Port: 2 bytes (big-endian)

use std::fmt;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

/// Address type constants
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Maximum domain name length
const MAX_DOMAIN_LEN: usize = 255;

/// Shadowsocks target address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// IPv4 socket address
    SocketAddrV4(SocketAddrV4),
    /// IPv6 socket address
    SocketAddrV6(SocketAddrV6),
    /// Domain name with port
    Domain(String, u16),
}

impl Address {
    /// Create address from a socket address
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Address::SocketAddrV4(v4),
            SocketAddr::V6(v6) => Address::SocketAddrV6(v6),
        }
    }

    /// Create address from domain name and port
    pub fn from_domain(domain: impl Into<String>, port: u16) -> Self {
        Address::Domain(domain.into(), port)
    }

    /// Get the port number
    pub fn port(&self) -> u16 {
        match self {
            Address::SocketAddrV4(addr) => addr.port(),
            Address::SocketAddrV6(addr) => addr.port(),
            Address::Domain(_, port) => *port,
        }
    }

    /// Convert to socket address (may require DNS resolution for domains)
    pub async fn to_socket_addr(&self) -> Result<SocketAddr> {
        match self {
            Address::SocketAddrV4(addr) => Ok(SocketAddr::V4(*addr)),
            Address::SocketAddrV6(addr) => Ok(SocketAddr::V6(*addr)),
            Address::Domain(domain, port) => {
                // Use tokio's DNS resolution
                let addr_str = format!("{}:{}", domain, port);
                let mut addrs = tokio::net::lookup_host(&addr_str).await?;
                addrs.next().ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        format!("No addresses found for {}", domain),
                    )
                })
            }
        }
    }

    /// Convert to socket address synchronously (blocking DNS resolution)
    pub fn to_socket_addr_sync(&self) -> Result<SocketAddr> {
        match self {
            Address::SocketAddrV4(addr) => Ok(SocketAddr::V4(*addr)),
            Address::SocketAddrV6(addr) => Ok(SocketAddr::V6(*addr)),
            Address::Domain(domain, port) => {
                let addr_str = format!("{}:{}", domain, port);
                addr_str.to_socket_addrs()?.next().ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        format!("No addresses found for {}", domain),
                    )
                })
            }
        }
    }

    /// Encode the address to bytes (Shadowsocks format)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            Address::SocketAddrV4(addr) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            Address::SocketAddrV6(addr) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            Address::Domain(domain, port) => {
                buf.push(ATYP_DOMAIN);
                let domain_bytes = domain.as_bytes();
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        buf
    }

    /// Decode address from bytes
    ///
    /// Returns the decoded address and the number of bytes consumed.
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Error::new(ErrorKind::InvalidData, "Empty address data"));
        }

        let atyp = data[0];

        match atyp {
            ATYP_IPV4 => {
                // 1 (type) + 4 (ip) + 2 (port) = 7 bytes
                if data.len() < 7 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Incomplete IPv4 address",
                    ));
                }
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((Address::SocketAddrV4(SocketAddrV4::new(ip, port)), 7))
            }
            ATYP_IPV6 => {
                // 1 (type) + 16 (ip) + 2 (port) = 19 bytes
                if data.len() < 19 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Incomplete IPv6 address",
                    ));
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[1..17]);
                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((Address::SocketAddrV6(SocketAddrV6::new(ip, port, 0, 0)), 19))
            }
            ATYP_DOMAIN => {
                if data.len() < 2 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Incomplete domain address",
                    ));
                }
                let domain_len = data[1] as usize;
                if domain_len == 0 || domain_len > MAX_DOMAIN_LEN {
                    return Err(Error::new(ErrorKind::InvalidData, "Invalid domain length"));
                }
                // 1 (type) + 1 (len) + domain_len + 2 (port)
                let total_len = 2 + domain_len + 2;
                if data.len() < total_len {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Incomplete domain address",
                    ));
                }
                let domain = String::from_utf8(data[2..2 + domain_len].to_vec()).map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "Invalid domain encoding")
                })?;
                let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
                Ok((Address::Domain(domain, port), total_len))
            }
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unknown address type: 0x{:02x}", atyp),
            )),
        }
    }

    /// Get encoded length without actually encoding
    pub fn encoded_len(&self) -> usize {
        match self {
            Address::SocketAddrV4(_) => 7,  // 1 + 4 + 2
            Address::SocketAddrV6(_) => 19, // 1 + 16 + 2
            Address::Domain(domain, _) => 1 + 1 + domain.len() + 2,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::SocketAddrV4(addr) => write!(f, "{}", addr),
            Address::SocketAddrV6(addr) => write!(f, "{}", addr),
            Address::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::from_socket_addr(addr)
    }
}

impl From<SocketAddrV4> for Address {
    fn from(addr: SocketAddrV4) -> Self {
        Address::SocketAddrV4(addr)
    }
}

impl From<SocketAddrV6> for Address {
    fn from(addr: SocketAddrV6) -> Self {
        Address::SocketAddrV6(addr)
    }
}

impl From<(IpAddr, u16)> for Address {
    fn from((ip, port): (IpAddr, u16)) -> Self {
        match ip {
            IpAddr::V4(v4) => Address::SocketAddrV4(SocketAddrV4::new(v4, port)),
            IpAddr::V6(v6) => Address::SocketAddrV6(SocketAddrV6::new(v6, port, 0, 0)),
        }
    }
}

impl From<(String, u16)> for Address {
    fn from((domain, port): (String, u16)) -> Self {
        Address::Domain(domain, port)
    }
}

impl From<(&str, u16)> for Address {
    fn from((domain, port): (&str, u16)) -> Self {
        Address::Domain(domain.to_string(), port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_ipv4() {
        let addr = Address::SocketAddrV4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 8080));
        let encoded = addr.encode();

        assert_eq!(encoded[0], ATYP_IPV4);
        assert_eq!(encoded.len(), 7);

        let (decoded, len) = Address::decode(&encoded).unwrap();
        assert_eq!(len, 7);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_encode_decode_ipv6() {
        let addr = Address::SocketAddrV6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));
        let encoded = addr.encode();

        assert_eq!(encoded[0], ATYP_IPV6);
        assert_eq!(encoded.len(), 19);

        let (decoded, len) = Address::decode(&encoded).unwrap();
        assert_eq!(len, 19);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_encode_decode_domain() {
        let addr = Address::Domain("www.example.com".to_string(), 80);
        let encoded = addr.encode();

        assert_eq!(encoded[0], ATYP_DOMAIN);
        assert_eq!(encoded[1], 15); // length of "www.example.com"

        let (decoded, len) = Address::decode(&encoded).unwrap();
        assert_eq!(len, 1 + 1 + 15 + 2);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_display() {
        let addr_v4 = Address::SocketAddrV4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        assert_eq!(format!("{}", addr_v4), "127.0.0.1:8080");

        let addr_domain = Address::Domain("example.com".to_string(), 443);
        assert_eq!(format!("{}", addr_domain), "example.com:443");
    }

    #[test]
    fn test_from_socket_addr() {
        let sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 22);
        let addr = Address::from_socket_addr(sock_addr);

        assert_eq!(addr.port(), 22);
        match addr {
            Address::SocketAddrV4(v4) => {
                assert_eq!(v4.ip(), &Ipv4Addr::new(10, 0, 0, 1));
            }
            _ => panic!("Expected SocketAddrV4"),
        }
    }

    #[test]
    fn test_encoded_len() {
        let addr_v4 = Address::SocketAddrV4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80));
        assert_eq!(addr_v4.encoded_len(), 7);
        assert_eq!(addr_v4.encode().len(), 7);

        let addr_v6 = Address::SocketAddrV6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0));
        assert_eq!(addr_v6.encoded_len(), 19);
        assert_eq!(addr_v6.encode().len(), 19);

        let addr_domain = Address::Domain("test.com".to_string(), 80);
        assert_eq!(addr_domain.encoded_len(), 1 + 1 + 8 + 2);
        assert_eq!(addr_domain.encode().len(), 1 + 1 + 8 + 2);
    }

    #[test]
    fn test_decode_errors() {
        // Empty data
        assert!(Address::decode(&[]).is_err());

        // Incomplete IPv4
        assert!(Address::decode(&[ATYP_IPV4, 1, 2, 3]).is_err());

        // Incomplete IPv6
        assert!(Address::decode(&[ATYP_IPV6, 1, 2, 3]).is_err());

        // Invalid domain length
        assert!(Address::decode(&[ATYP_DOMAIN, 0]).is_err());

        // Unknown type
        assert!(Address::decode(&[0xFF, 1, 2, 3]).is_err());
    }
}
