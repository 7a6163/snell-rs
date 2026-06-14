//! Outbound DNS resolution for the Snell server.
//!
//! Two backends:
//! - [`Backend::System`] (default): tokio's built-in resolver
//!   (`tokio::net::lookup_host`), honoring the host's system configuration.
//! - [`Backend::Custom`]: a hickory-resolver querying explicit upstream
//!   nameservers over UDP+TCP port 53, selected when the `DNS` env var lists
//!   one or more resolver IPs (e.g. `DNS=1.1.1.1,8.8.8.8`).
//!
//! Both honor the IPv6 egress toggle (mirrors official snell-server `ipv6`):
//! when `ipv6` is false, only IPv4 results are used. The custom backend further
//! restricts its query strategy to A-only so no AAAA query is even sent.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts};

/// Resolves target hostnames to a single outbound `SocketAddr`, honoring the
/// IPv6 egress toggle. Built once at startup and shared via `Arc`.
pub struct Resolver {
    backend: Backend,
    ipv6: bool,
}

enum Backend {
    System,
    // Boxed: TokioResolver is large; Backend::System is a unit. The resolver is
    // built once and shared behind an Arc, so the indirection is free.
    Custom(Box<TokioResolver>),
}

impl Resolver {
    /// Build from the `DNS` env var. When unset or empty, uses the system
    /// resolver. When set to a comma-separated list of IPs, builds a hickory
    /// resolver querying those servers. `ipv6` is the egress toggle (see module
    /// docs); it is captured here so callers resolve uniformly.
    pub fn from_env(ipv6: bool) -> Result<Self> {
        let backend = match std::env::var("DNS") {
            Ok(spec) if !spec.trim().is_empty() => {
                Backend::Custom(Box::new(build_custom(&spec, ipv6)?))
            }
            _ => Backend::System,
        };
        Ok(Self { backend, ipv6 })
    }

    /// Resolve `host:port` to one outbound address, or `None` when no address of
    /// the permitted family is available (e.g. an IPv6-only host while the IPv6
    /// toggle is off — the caller surfaces this as a DNS failure).
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Option<SocketAddr>> {
        // IP-literal targets skip DNS entirely (matches tokio::net::lookup_host).
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(pick_addr(
                std::iter::once(SocketAddr::new(ip, port)),
                self.ipv6,
            ));
        }
        match &self.backend {
            Backend::System => {
                let addrs = tokio::net::lookup_host((host, port))
                    .await
                    .with_context(|| format!("DNS resolution failed for {host}"))?;
                Ok(pick_addr(addrs, self.ipv6))
            }
            Backend::Custom(resolver) => {
                let lookup = resolver
                    .lookup_ip(host)
                    .await
                    .with_context(|| format!("DNS resolution failed for {host}"))?;
                Ok(pick_addr(
                    lookup.iter().map(|ip| SocketAddr::new(ip, port)),
                    self.ipv6,
                ))
            }
        }
    }
}

/// Build a custom hickory resolver from a comma-separated list of upstream IPs.
fn build_custom(spec: &str, ipv6: bool) -> Result<TokioResolver> {
    let mut name_servers = Vec::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let ip: IpAddr = token
            .parse()
            .with_context(|| format!("DNS: invalid resolver IP {token:?}"))?;
        name_servers.push(NameServerConfig::udp_and_tcp(ip));
    }
    if name_servers.is_empty() {
        anyhow::bail!("DNS set but no valid resolver IPs parsed");
    }
    let config = ResolverConfig::from_parts(None, vec![], name_servers);

    // ResolverOpts is #[non_exhaustive], so mutate a default rather than using
    // a struct literal. Only query the families we can actually use: with the
    // IPv6 toggle off we ask for A records exclusively (no wasted AAAA query).
    let mut opts = ResolverOpts::default();
    opts.ip_strategy = if ipv6 {
        LookupIpStrategy::Ipv4AndIpv6
    } else {
        LookupIpStrategy::Ipv4Only
    };

    // The provider type is pinned to TokioRuntimeProvider by the TokioResolver
    // return type, so Default::default() resolves without naming its path.
    let resolver = TokioResolver::builder_with_config(config, Default::default())
        .with_options(opts)
        .build()
        .context("failed to build custom DNS resolver")?;
    Ok(resolver)
}

/// Pick one outbound address honoring the IPv6 toggle. With `ipv6` false only
/// IPv4 addresses are eligible; with true the first address of any family wins.
fn pick_addr(mut addrs: impl Iterator<Item = SocketAddr>, ipv6: bool) -> Option<SocketAddr> {
    if ipv6 {
        addrs.next()
    } else {
        addrs.find(SocketAddr::is_ipv4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::from(([a, b, c, d], 443))
    }
    fn v6(s: &str) -> SocketAddr {
        SocketAddr::new(s.parse::<IpAddr>().unwrap(), 443)
    }

    #[test]
    fn ipv4_only_skips_ipv6_when_toggle_off() {
        let addrs = vec![v6("2606:4700:4700::1111"), v4(1, 1, 1, 1)];
        assert_eq!(pick_addr(addrs.into_iter(), false), Some(v4(1, 1, 1, 1)));
    }

    #[test]
    fn ipv4_only_returns_none_for_ipv6_only_host() {
        let addrs = vec![v6("2606:4700:4700::1111"), v6("2606:4700:4700::1001")];
        assert_eq!(pick_addr(addrs.into_iter(), false), None);
    }

    #[test]
    fn ipv6_enabled_takes_first_of_any_family() {
        let addrs = vec![v6("2606:4700:4700::1111"), v4(1, 1, 1, 1)];
        assert_eq!(
            pick_addr(addrs.into_iter(), true),
            Some(v6("2606:4700:4700::1111"))
        );
    }

    #[test]
    fn ipv4_only_keeps_first_ipv4_result() {
        let addrs = vec![v4(8, 8, 8, 8), v6("2001:4860:4860::8888")];
        assert_eq!(pick_addr(addrs.into_iter(), false), Some(v4(8, 8, 8, 8)));
    }

    #[test]
    fn empty_resolution_is_none() {
        let empty: Vec<SocketAddr> = vec![];
        assert_eq!(pick_addr(empty.clone().into_iter(), false), None);
        assert_eq!(pick_addr(empty.into_iter(), true), None);
    }

    #[test]
    fn build_custom_rejects_invalid_ip() {
        assert!(build_custom("not-an-ip", false).is_err());
    }

    #[test]
    fn build_custom_rejects_empty_after_trim() {
        assert!(build_custom("  , ,", false).is_err());
    }

    #[test]
    fn build_custom_accepts_valid_ip_list() {
        assert!(build_custom("1.1.1.1, 8.8.8.8", false).is_ok());
        assert!(build_custom("2606:4700:4700::1111", true).is_ok());
    }
}
