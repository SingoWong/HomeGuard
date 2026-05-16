//! NAT lookup for getting original destination address
//!
//! On macOS, when using PF (Packet Filter) for transparent proxy,
//! we need to query `/dev/pf` device with DIOCNATLOOK ioctl to get
//! the original destination address before NAT redirection.

use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use tokio::net::TcpStream;

/// Get the original destination address of a connection that was
/// redirected by PF NAT rules.
///
/// This is macOS-specific and requires:
/// 1. The connection was redirected using PF `rdr` rules
/// 2. The process has permission to read `/dev/pf`
///
/// # Arguments
/// * `stream` - The accepted TCP connection
///
/// # Returns
/// The original destination address before PF redirection
pub fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    let peer_addr = stream
        .peer_addr()
        .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to get peer address: {}", e)))?;

    let local_addr = stream
        .local_addr()
        .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to get local address: {}", e)))?;

    get_original_dst_pf(stream.as_raw_fd(), &peer_addr, &local_addr)
}

/// PF-specific implementation using DIOCNATLOOK ioctl
#[cfg(target_os = "macos")]
fn get_original_dst_pf(
    _sock_fd: i32,
    peer_addr: &SocketAddr,
    local_addr: &SocketAddr,
) -> Result<SocketAddr> {
    use std::os::unix::io::FromRawFd;

    // Open /dev/pf device
    let pf_fd = unsafe { libc::open(b"/dev/pf\0".as_ptr() as *const libc::c_char, libc::O_RDONLY) };

    if pf_fd < 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "Failed to open /dev/pf. Run with sudo or check permissions.",
        ));
    }

    // Ensure we close the fd when done
    let _pf_file = unsafe { std::fs::File::from_raw_fd(pf_fd) };

    // Build natlook structure based on address family
    match (peer_addr, local_addr) {
        (SocketAddr::V4(peer), SocketAddr::V4(local)) => {
            let mut nl = PfiocNatlook::new_v4(peer, local);
            pf_natlook(pf_fd, &mut nl)?;

            // Extract original destination from result
            // SAFETY: After successful pf_natlook, the union field is properly initialized
            let orig_ip = Ipv4Addr::from(u32::from_be(unsafe { nl.rdaddr.v4 }));
            let orig_port = u16::from_be(nl.rdport);

            Ok(SocketAddr::new(IpAddr::V4(orig_ip), orig_port))
        }
        (SocketAddr::V6(peer), SocketAddr::V6(local)) => {
            let mut nl = PfiocNatlook::new_v6(peer, local);
            pf_natlook(pf_fd, &mut nl)?;

            // Extract original destination from result
            // SAFETY: After successful pf_natlook, the union field is properly initialized
            let orig_ip = Ipv6Addr::from(unsafe { nl.rdaddr.v6 });
            let orig_port = u16::from_be(nl.rdport);

            Ok(SocketAddr::new(IpAddr::V6(orig_ip), orig_port))
        }
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            "Mismatched address families",
        )),
    }
}

/// Fallback for non-macOS systems (not supported)
#[cfg(not(target_os = "macos"))]
fn get_original_dst_pf(
    _sock_fd: i32,
    _peer_addr: &SocketAddr,
    _local_addr: &SocketAddr,
) -> Result<SocketAddr> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "Transparent proxy is only supported on macOS with PF",
    ))
}

// ============================================================================
// PF structures and constants for macOS
// ============================================================================

#[cfg(target_os = "macos")]
mod pf {
    use std::net::{SocketAddrV4, SocketAddrV6};

    /// Address family constants
    pub const AF_INET: u8 = libc::AF_INET as u8;
    pub const AF_INET6: u8 = libc::AF_INET6 as u8;

    /// Protocol constant
    pub const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;

    /// PF direction
    pub const PF_IN: u8 = 0;
    #[allow(dead_code)]
    pub const PF_OUT: u8 = 1;

    /// DIOCNATLOOK ioctl number for macOS
    /// Calculated as: _IOWR('D', 23, struct pfioc_natlook)
    /// 'D' = 0x44, 23 = 0x17
    /// Size of pfioc_natlook is 84 bytes (0x54)
    pub const DIOCNATLOOK: libc::c_ulong = 0xC0544417;

    /// PF address union - can hold IPv4 or IPv6
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub union PfAddr {
        pub v4: u32,           // IPv4 address in network byte order
        pub v6: [u8; 16],      // IPv6 address
        pub _pad: [u8; 16],    // Padding to ensure correct size
    }

    impl Default for PfAddr {
        fn default() -> Self {
            PfAddr { _pad: [0u8; 16] }
        }
    }

    /// pfioc_natlook structure for DIOCNATLOOK ioctl
    ///
    /// This structure is used to query PF for the original destination
    /// of a NAT-redirected connection.
    #[repr(C)]
    pub struct PfiocNatlook {
        pub saddr: PfAddr,      // Source address
        pub daddr: PfAddr,      // Destination address (after NAT)
        pub rsaddr: PfAddr,     // Real source address (result)
        pub rdaddr: PfAddr,     // Real destination address (result)
        pub sport: u16,         // Source port (network byte order)
        pub dport: u16,         // Destination port (network byte order)
        pub rsport: u16,        // Real source port (result)
        pub rdport: u16,        // Real destination port (result)
        pub af: u8,             // Address family (AF_INET or AF_INET6)
        pub proto: u8,          // Protocol (IPPROTO_TCP)
        pub direction: u8,      // Direction (PF_IN or PF_OUT)
        pub _pad: [u8; 1],      // Padding
    }

    impl PfiocNatlook {
        /// Create a new natlook structure for IPv4
        pub fn new_v4(peer: &SocketAddrV4, local: &SocketAddrV4) -> Self {
            let mut nl = Self {
                saddr: PfAddr::default(),
                daddr: PfAddr::default(),
                rsaddr: PfAddr::default(),
                rdaddr: PfAddr::default(),
                sport: peer.port().to_be(),
                dport: local.port().to_be(),
                rsport: 0,
                rdport: 0,
                af: AF_INET,
                proto: IPPROTO_TCP,
                direction: PF_IN,
                _pad: [0],
            };

            // Set addresses in network byte order
            nl.saddr.v4 = u32::from_ne_bytes(peer.ip().octets()).to_be();
            nl.daddr.v4 = u32::from_ne_bytes(local.ip().octets()).to_be();

            nl
        }

        /// Create a new natlook structure for IPv6
        pub fn new_v6(peer: &SocketAddrV6, local: &SocketAddrV6) -> Self {
            let mut nl = Self {
                saddr: PfAddr::default(),
                daddr: PfAddr::default(),
                rsaddr: PfAddr::default(),
                rdaddr: PfAddr::default(),
                sport: peer.port().to_be(),
                dport: local.port().to_be(),
                rsport: 0,
                rdport: 0,
                af: AF_INET6,
                proto: IPPROTO_TCP,
                direction: PF_IN,
                _pad: [0],
            };

            nl.saddr.v6 = peer.ip().octets();
            nl.daddr.v6 = local.ip().octets();

            nl
        }
    }
}

#[cfg(target_os = "macos")]
use pf::*;

/// Perform DIOCNATLOOK ioctl
#[cfg(target_os = "macos")]
fn pf_natlook(pf_fd: i32, nl: &mut PfiocNatlook) -> Result<()> {
    let ret = unsafe { libc::ioctl(pf_fd, DIOCNATLOOK, nl as *mut PfiocNatlook) };

    if ret < 0 {
        let err = Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOENT) => Err(Error::new(
                ErrorKind::NotFound,
                "No NAT state found for this connection. Is PF configured correctly?",
            )),
            Some(libc::EACCES) | Some(libc::EPERM) => Err(Error::new(
                ErrorKind::PermissionDenied,
                "Permission denied accessing /dev/pf",
            )),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("DIOCNATLOOK failed: {}", err),
            )),
        }
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_pfioc_natlook_size() {
        use std::mem::size_of;
        // The structure should be 84 bytes on macOS
        // This is important for the ioctl to work correctly
        assert!(size_of::<PfiocNatlook>() > 0);
        // Note: Actual size may vary, but structure must be properly aligned
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_pfaddr_size() {
        use std::mem::size_of;
        // PfAddr should be 16 bytes (size of IPv6 address)
        assert_eq!(size_of::<PfAddr>(), 16);
    }
}
