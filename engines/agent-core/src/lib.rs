use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTarget {
    pub address: Ipv4Addr,
}

pub fn expand_cidr(cidr: &str, limit: usize) -> Result<Vec<ScanTarget>, String> {
    let (addr, prefix) = cidr.split_once('/').ok_or("CIDR must include a prefix")?;
    let base: Ipv4Addr = addr.parse().map_err(|_| "invalid IPv4 address")?;
    let prefix: u32 = prefix.parse().map_err(|_| "invalid prefix")?;
    if prefix > 32 { return Err("prefix must be <= 32".to_string()); }
    let host_bits = 32 - prefix;
    let total = 1u64.checked_shl(host_bits).unwrap_or(0).min(limit as u64);
    let base_u32 = u32::from(base) & (!0u32 << host_bits);
    let mut targets = Vec::with_capacity(total as usize);
    for offset in 0..total {
        targets.push(ScanTarget { address: Ipv4Addr::from(base_u32 + offset as u32) });
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_limited_cidr() {
        let targets = expand_cidr("192.168.1.0/30", 16).unwrap();
        assert_eq!(targets.len(), 4);
    }
}
