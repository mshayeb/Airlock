//! Post-DNS-resolution SSRF protection (`FR-NET-6`, `SEC-5`, `AT-6`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::BrokerError;

/// Validates that a resolved upstream IP address is strictly public routable space.
///
/// Rejects loopback, unspecified, RFC 1918 private, CGNAT (`100.64/10`),
/// link-local / cloud IMDS (`169.254.0.0/16`, `169.254.169.254`), multicast,
/// IPv6 ULA/link-local, and IPv4-mapped/compatible IPv6 bypass encodings.
pub fn validate_egress_ip(ip: IpAddr) -> Result<(), BrokerError> {
    match ip {
        IpAddr::V4(v4) => validate_v4(v4),
        IpAddr::V6(v6) => validate_v6(v6),
    }
}

fn validate_v4(v4: Ipv4Addr) -> Result<(), BrokerError> {
    let o = v4.octets();
    let blocked = o[0] == 0 // 0.0.0.0/8 ("this network")
        || v4.is_loopback() // 127.0.0.0/8
        || v4.is_private() // 10/8, 172.16/12, 192.168/16
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64) // 100.64.0.0/10 (CGNAT)
        || v4.is_link_local() // 169.254.0.0/16 (cloud IMDS 169.254.169.254)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // 192.0.2.0/24 TEST-NET-1
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || v4.is_multicast()
        || v4.is_broadcast()
        || o[0] >= 240; // 240.0.0.0/4 reserved

    if blocked {
        Err(BrokerError::SsrfBlocked(IpAddr::V4(v4)))
    } else {
        Ok(())
    }
}

fn validate_v6(v6: Ipv6Addr) -> Result<(), BrokerError> {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return validate_v4(mapped).map_err(|_| BrokerError::SsrfBlocked(IpAddr::V6(v6)));
    }
    let segs = v6.segments();
    // Handle deprecated IPv4-compatible IPv6 (`::a.b.c.d`) if non-zero.
    if segs[0..6] == [0, 0, 0, 0, 0, 0] && (segs[6] != 0 || segs[7] > 1) {
        let compat = Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        );
        return validate_v4(compat).map_err(|_| BrokerError::SsrfBlocked(IpAddr::V6(v6)));
    }

    let is_ula = (segs[0] & 0xfe00) == 0xfc00; // fc00::/7
    let is_link_local = (segs[0] & 0xffc0) == 0xfe80; // fe80::/10
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || is_ula || is_link_local {
        Err(BrokerError::SsrfBlocked(IpAddr::V6(v6)))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_imds_loopback_private_and_mapped_ipv6() {
        let blocked = [
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.10",
            "100.64.0.1",
            "169.254.169.254",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.5",
        ];
        for raw in blocked {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(
                matches!(validate_egress_ip(ip), Err(BrokerError::SsrfBlocked(_))),
                "expected {raw} to be blocked"
            );
        }
    }

    #[test]
    fn allows_public_routable_ips() {
        for raw in ["140.82.114.4", "1.1.1.1", "2606:4700:4700::1111"] {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(validate_egress_ip(ip).is_ok(), "expected {raw} allowed");
        }
    }
}
