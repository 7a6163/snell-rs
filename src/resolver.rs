//! Outbound DNS resolution and address-family policy for the Snell server.
//!
//! Two backends:
//! - [`Backend::System`] (default): tokio's built-in resolver
//!   (`tokio::net::lookup_host`), honoring the host's system configuration.
//! - [`Backend::Custom`]: a hickory-resolver querying explicit upstream
//!   nameservers over UDP+TCP port 53, selected when the `DNS` env var lists
//!   one or more resolver IPs (e.g. `DNS=1.1.1.1,8.8.8.8`).
//!
//! Both honor [`IpPolicy`], the five-state address-family policy official
//! snell-server v6.0.0rc2 keeps in a single variable fed by `ipv6=` and
//! `dns-ip-preference=`. The custom backend additionally narrows its query
//! strategy for the `*-only` policies so no useless AAAA/A query is sent.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts};

/// Address-family policy for outbound targets. Discriminants match the official
/// server's internal policy values (`default=0 … ipv6-only=4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpPolicy {
    /// Use the first result of any family (`default` / `first-result`).
    #[default]
    Default = 0,
    /// First IPv4 result, falling back to the first result of any family.
    PreferIpv4 = 1,
    /// First IPv6 result, falling back to the first result of any family.
    PreferIpv6 = 2,
    /// IPv4 only; an IPv6-only target is refused.
    Ipv4Only = 3,
    /// IPv6 only; an IPv4-only target is refused.
    Ipv6Only = 4,
}

impl IpPolicy {
    /// Parse an `ipv6=` style flag the way official rc2 does: a leading
    /// `t`/`T`/`y`/`Y`/`1` enables both families ([`IpPolicy::Default`]), every
    /// other value — including `false`, `no`, `0` and the empty string — means
    /// [`IpPolicy::Ipv4Only`].
    pub fn from_ipv6_flag(value: &str) -> Self {
        match value.chars().next() {
            Some('t' | 'T' | 'y' | 'Y' | '1') => Self::Default,
            _ => Self::Ipv4Only,
        }
    }

    /// Parse a `dns-ip-preference=` value, including every official alias.
    /// Unknown values return `None`.
    pub fn parse_preference(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "default" | "first-result" => Some(Self::Default),
            "prefer-ipv4" | "ipv4-preferred" => Some(Self::PreferIpv4),
            "prefer-ipv6" | "ipv6-preferred" => Some(Self::PreferIpv6),
            "ipv4-only" | "only-ipv4" => Some(Self::Ipv4Only),
            "ipv6-only" | "only-ipv6" => Some(Self::Ipv6Only),
            _ => None,
        }
    }

    /// Resolve the policy from the environment. `DNS_IP_PREFERENCE` overrides
    /// `IPV6` whenever it is set, regardless of the order the two appear in —
    /// matching official rc2, where an explicit `dns-ip-preference` always wins.
    /// With neither set the policy is [`IpPolicy::Ipv4Only`].
    pub fn from_env() -> Result<Self> {
        if let Ok(pref) = std::env::var("DNS_IP_PREFERENCE")
            && !pref.trim().is_empty()
        {
            return Self::parse_preference(&pref).with_context(|| {
                format!(
                    "invalid DNS_IP_PREFERENCE '{pref}' (default|first-result|prefer-ipv4|\
                     ipv4-preferred|prefer-ipv6|ipv6-preferred|ipv4-only|only-ipv4|\
                     ipv6-only|only-ipv6)"
                )
            });
        }
        Ok(Self::from_ipv6_flag(
            &std::env::var("IPV6").unwrap_or_default(),
        ))
    }

    /// Whether an IP-literal target of this family may be used. Only the
    /// `*-only` policies reject a literal; `prefer-*` never does.
    pub fn allows(self, ip: IpAddr) -> bool {
        !matches!(
            (self, ip),
            (Self::Ipv4Only, IpAddr::V6(_)) | (Self::Ipv6Only, IpAddr::V4(_))
        )
    }

    /// True for `ipv4-only` / `ipv6-only`, the two policies that can turn a
    /// successful DNS lookup into a failure.
    pub fn is_only(self) -> bool {
        matches!(self, Self::Ipv4Only | Self::Ipv6Only)
    }

    fn lookup_strategy(self) -> LookupIpStrategy {
        match self {
            Self::Ipv4Only => LookupIpStrategy::Ipv4Only,
            Self::Ipv6Only => LookupIpStrategy::Ipv6Only,
            Self::Default | Self::PreferIpv4 | Self::PreferIpv6 => LookupIpStrategy::Ipv4AndIpv6,
        }
    }
}

impl fmt::Display for IpPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default => "default",
            Self::PreferIpv4 => "prefer-ipv4",
            Self::PreferIpv6 => "prefer-ipv6",
            Self::Ipv4Only => "ipv4-only",
            Self::Ipv6Only => "ipv6-only",
        })
    }
}

/// Parse a target host as an IP literal, accepting the bracketed (`[::1]`) and
/// zone-suffixed (`fe80::1%eth0`) IPv6 spellings alongside the bare forms. The
/// zone id is dropped — `std::net` can't carry it into a `SocketAddr`.
pub fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let host = host.split('%').next().unwrap_or(host);
    host.parse().ok()
}

/// Resolves target hostnames to a single outbound `SocketAddr` under an
/// [`IpPolicy`]. Built once at startup and shared via `Arc`.
pub struct Resolver {
    backend: Backend,
    policy: IpPolicy,
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
    /// resolver querying those servers. `policy` is captured here so callers
    /// resolve uniformly.
    pub fn from_env(policy: IpPolicy) -> Result<Self> {
        let backend = match std::env::var("DNS") {
            Ok(spec) if !spec.trim().is_empty() => {
                Backend::Custom(Box::new(build_custom(&spec, policy)?))
            }
            _ => Backend::System,
        };
        Ok(Self { backend, policy })
    }

    /// The address-family policy this resolver was built with.
    pub fn policy(&self) -> IpPolicy {
        self.policy
    }

    /// Resolve `host:port` to one outbound address, or `None` when no address of
    /// a permitted family is available (e.g. an IPv6-only host under
    /// `ipv4-only` — the caller surfaces this as a DNS failure).
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Option<SocketAddr>> {
        // IP-literal targets skip DNS entirely (matches tokio::net::lookup_host).
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(pick_addr(
                std::iter::once(SocketAddr::new(ip, port)),
                self.policy,
            ));
        }
        match &self.backend {
            Backend::System => {
                let addrs = tokio::net::lookup_host((host, port))
                    .await
                    .with_context(|| format!("DNS resolution failed for {host}"))?;
                Ok(self.pick_resolved(host, addrs))
            }
            Backend::Custom(resolver) => {
                let lookup = resolver
                    .lookup_ip(host)
                    .await
                    .with_context(|| format!("DNS resolution failed for {host}"))?;
                Ok(self.pick_resolved(host, lookup.iter().map(|ip| SocketAddr::new(ip, port))))
            }
        }
    }

    /// Apply the policy to a lookup's results, logging the official message when
    /// an `*-only` policy discards every answer.
    fn pick_resolved(
        &self,
        host: &str,
        addrs: impl Iterator<Item = SocketAddr>,
    ) -> Option<SocketAddr> {
        let picked = pick_addr(addrs, self.policy);
        if picked.is_none() && self.policy.is_only() {
            tracing::warn!(%host, "DNS result does not match preference: {}", self.policy);
        }
        picked
    }
}

/// Build a custom hickory resolver from a comma-separated list of upstream IPs.
fn build_custom(spec: &str, policy: IpPolicy) -> Result<TokioResolver> {
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
    // a struct literal. Only query the families we can actually use: under an
    // `*-only` policy that means a single query type, no wasted round trip.
    let mut opts = ResolverOpts::default();
    opts.ip_strategy = policy.lookup_strategy();

    // The provider type is pinned to TokioRuntimeProvider by the TokioResolver
    // return type, so Default::default() resolves without naming its path.
    let resolver = TokioResolver::builder_with_config(config, Default::default())
        .with_options(opts)
        .build()
        .context("failed to build custom DNS resolver")?;
    Ok(resolver)
}

/// Pick one outbound address under `policy`: the first result for `default`,
/// the first result of the wanted family (with any-family fallback) for
/// `prefer-*`, and strictly the wanted family for `*-only`.
fn pick_addr(mut addrs: impl Iterator<Item = SocketAddr>, policy: IpPolicy) -> Option<SocketAddr> {
    match policy {
        IpPolicy::Default => addrs.next(),
        IpPolicy::Ipv4Only => addrs.find(|a| a.is_ipv4()),
        IpPolicy::Ipv6Only => addrs.find(|a| a.is_ipv6()),
        IpPolicy::PreferIpv4 | IpPolicy::PreferIpv6 => {
            let want_ipv4 = policy == IpPolicy::PreferIpv4;
            let mut fallback = None;
            for addr in addrs {
                if addr.is_ipv4() == want_ipv4 {
                    return Some(addr);
                }
                fallback = fallback.or(Some(addr));
            }
            fallback
        }
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

    // ---- IpPolicy parsing ----------------------------------------------------

    #[test]
    fn ipv6_flag_true_like_values_enable_both_families() {
        for v in ["1", "true", "True", "yes", "Y", "t", "TRUE"] {
            assert_eq!(IpPolicy::from_ipv6_flag(v), IpPolicy::Default, "{v}");
        }
    }

    #[test]
    fn ipv6_flag_everything_else_is_ipv4_only() {
        for v in ["", "0", "false", "no", "off", "2", "bogus"] {
            assert_eq!(IpPolicy::from_ipv6_flag(v), IpPolicy::Ipv4Only, "{v}");
        }
    }

    #[test]
    fn preference_aliases_map_to_official_states() {
        let cases = [
            ("default", IpPolicy::Default),
            ("first-result", IpPolicy::Default),
            ("prefer-ipv4", IpPolicy::PreferIpv4),
            ("ipv4-preferred", IpPolicy::PreferIpv4),
            ("prefer-ipv6", IpPolicy::PreferIpv6),
            ("ipv6-preferred", IpPolicy::PreferIpv6),
            ("ipv4-only", IpPolicy::Ipv4Only),
            ("only-ipv4", IpPolicy::Ipv4Only),
            ("ipv6-only", IpPolicy::Ipv6Only),
            ("only-ipv6", IpPolicy::Ipv6Only),
            (" IPv6-Only ", IpPolicy::Ipv6Only),
        ];
        for (s, want) in cases {
            assert_eq!(IpPolicy::parse_preference(s), Some(want), "{s}");
        }
        assert_eq!(IpPolicy::parse_preference("v6"), None);
    }

    #[test]
    fn policy_discriminants_match_official_values() {
        assert_eq!(IpPolicy::Default as u8, 0);
        assert_eq!(IpPolicy::PreferIpv4 as u8, 1);
        assert_eq!(IpPolicy::PreferIpv6 as u8, 2);
        assert_eq!(IpPolicy::Ipv4Only as u8, 3);
        assert_eq!(IpPolicy::Ipv6Only as u8, 4);
    }

    #[test]
    fn policy_display_uses_config_spelling() {
        assert_eq!(IpPolicy::Default.to_string(), "default");
        assert_eq!(IpPolicy::PreferIpv4.to_string(), "prefer-ipv4");
        assert_eq!(IpPolicy::PreferIpv6.to_string(), "prefer-ipv6");
        assert_eq!(IpPolicy::Ipv4Only.to_string(), "ipv4-only");
        assert_eq!(IpPolicy::Ipv6Only.to_string(), "ipv6-only");
    }

    #[test]
    #[serial_test::serial]
    fn from_env_defaults_to_ipv4_only() {
        // SAFETY: serialized; no other test reads these vars concurrently.
        unsafe {
            std::env::remove_var("IPV6");
            std::env::remove_var("DNS_IP_PREFERENCE");
        }
        assert_eq!(IpPolicy::from_env().unwrap(), IpPolicy::Ipv4Only);
    }

    #[test]
    #[serial_test::serial]
    fn from_env_preference_overrides_ipv6_flag() {
        // SAFETY: serialized.
        unsafe {
            std::env::set_var("IPV6", "0");
            std::env::set_var("DNS_IP_PREFERENCE", "ipv6-only");
        }
        let got = IpPolicy::from_env();
        unsafe {
            std::env::remove_var("IPV6");
            std::env::remove_var("DNS_IP_PREFERENCE");
        }
        assert_eq!(got.unwrap(), IpPolicy::Ipv6Only);
    }

    #[test]
    #[serial_test::serial]
    fn from_env_rejects_unknown_preference() {
        // SAFETY: serialized.
        unsafe {
            std::env::set_var("DNS_IP_PREFERENCE", "ipv7");
        }
        let got = IpPolicy::from_env();
        unsafe {
            std::env::remove_var("DNS_IP_PREFERENCE");
        }
        assert!(got.is_err());
    }

    #[test]
    #[serial_test::serial]
    fn from_env_blank_preference_falls_back_to_ipv6_flag() {
        // SAFETY: serialized.
        unsafe {
            std::env::set_var("IPV6", "1");
            std::env::set_var("DNS_IP_PREFERENCE", "  ");
        }
        let got = IpPolicy::from_env();
        unsafe {
            std::env::remove_var("IPV6");
            std::env::remove_var("DNS_IP_PREFERENCE");
        }
        assert_eq!(got.unwrap(), IpPolicy::Default);
    }

    // ---- literal gate --------------------------------------------------------

    #[test]
    fn only_policies_gate_literals_prefer_policies_do_not() {
        let v4ip: IpAddr = "1.1.1.1".parse().unwrap();
        let v6ip: IpAddr = "2606:4700::1111".parse().unwrap();
        assert!(IpPolicy::Ipv4Only.allows(v4ip));
        assert!(!IpPolicy::Ipv4Only.allows(v6ip));
        assert!(IpPolicy::Ipv6Only.allows(v6ip));
        assert!(!IpPolicy::Ipv6Only.allows(v4ip));
        for p in [
            IpPolicy::Default,
            IpPolicy::PreferIpv4,
            IpPolicy::PreferIpv6,
        ] {
            assert!(p.allows(v4ip), "{p}");
            assert!(p.allows(v6ip), "{p}");
        }
    }

    #[test]
    fn parse_ip_literal_accepts_bracketed_and_zoned_forms() {
        assert_eq!(
            parse_ip_literal("1.2.3.4"),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(parse_ip_literal("::1"), Some("::1".parse().unwrap()));
        assert_eq!(parse_ip_literal("[::1]"), Some("::1".parse().unwrap()));
        assert_eq!(
            parse_ip_literal("fe80::1%eth0"),
            Some("fe80::1".parse().unwrap())
        );
        assert_eq!(parse_ip_literal("example.com"), None);
        assert_eq!(parse_ip_literal(""), None);
    }

    // ---- pick_addr -----------------------------------------------------------

    #[test]
    fn default_policy_takes_first_of_any_family() {
        let addrs = vec![v6("2606:4700:4700::1111"), v4(1, 1, 1, 1)];
        assert_eq!(
            pick_addr(addrs.into_iter(), IpPolicy::Default),
            Some(v6("2606:4700:4700::1111"))
        );
    }

    #[test]
    fn prefer_ipv4_reaches_past_leading_ipv6() {
        let addrs = vec![v6("2606:4700:4700::1111"), v4(1, 1, 1, 1)];
        assert_eq!(
            pick_addr(addrs.into_iter(), IpPolicy::PreferIpv4),
            Some(v4(1, 1, 1, 1))
        );
    }

    #[test]
    fn prefer_ipv4_falls_back_to_first_result() {
        let addrs = vec![v6("2606:4700:4700::1111"), v6("2606:4700:4700::1001")];
        assert_eq!(
            pick_addr(addrs.into_iter(), IpPolicy::PreferIpv4),
            Some(v6("2606:4700:4700::1111"))
        );
    }

    #[test]
    fn prefer_ipv6_reaches_past_leading_ipv4_and_falls_back() {
        let mixed = vec![v4(8, 8, 8, 8), v6("2001:4860:4860::8888")];
        assert_eq!(
            pick_addr(mixed.into_iter(), IpPolicy::PreferIpv6),
            Some(v6("2001:4860:4860::8888"))
        );
        let v4_only = vec![v4(8, 8, 8, 8), v4(8, 8, 4, 4)];
        assert_eq!(
            pick_addr(v4_only.into_iter(), IpPolicy::PreferIpv6),
            Some(v4(8, 8, 8, 8))
        );
    }

    #[test]
    fn ipv4_only_skips_ipv6_results() {
        let addrs = vec![v6("2606:4700:4700::1111"), v4(1, 1, 1, 1)];
        assert_eq!(
            pick_addr(addrs.into_iter(), IpPolicy::Ipv4Only),
            Some(v4(1, 1, 1, 1))
        );
    }

    #[test]
    fn ipv4_only_returns_none_for_ipv6_only_host() {
        let addrs = vec![v6("2606:4700:4700::1111"), v6("2606:4700:4700::1001")];
        assert_eq!(pick_addr(addrs.into_iter(), IpPolicy::Ipv4Only), None);
    }

    #[test]
    fn ipv6_only_returns_none_for_ipv4_only_host() {
        let addrs = vec![v4(1, 1, 1, 1), v4(8, 8, 8, 8)];
        assert_eq!(pick_addr(addrs.into_iter(), IpPolicy::Ipv6Only), None);
    }

    #[test]
    fn empty_resolution_is_none_under_every_policy() {
        for p in [
            IpPolicy::Default,
            IpPolicy::PreferIpv4,
            IpPolicy::PreferIpv6,
            IpPolicy::Ipv4Only,
            IpPolicy::Ipv6Only,
        ] {
            let empty: Vec<SocketAddr> = vec![];
            assert_eq!(pick_addr(empty.into_iter(), p), None, "{p}");
        }
    }

    #[test]
    fn lookup_strategy_narrows_only_for_only_policies() {
        assert_eq!(
            IpPolicy::Ipv4Only.lookup_strategy(),
            LookupIpStrategy::Ipv4Only
        );
        assert_eq!(
            IpPolicy::Ipv6Only.lookup_strategy(),
            LookupIpStrategy::Ipv6Only
        );
        for p in [
            IpPolicy::Default,
            IpPolicy::PreferIpv4,
            IpPolicy::PreferIpv6,
        ] {
            assert_eq!(p.lookup_strategy(), LookupIpStrategy::Ipv4AndIpv6, "{p}");
        }
    }

    // ---- resolver construction / resolution ----------------------------------

    #[test]
    fn build_custom_rejects_invalid_ip() {
        assert!(build_custom("not-an-ip", IpPolicy::Ipv4Only).is_err());
    }

    #[test]
    fn build_custom_rejects_empty_after_trim() {
        assert!(build_custom("  , ,", IpPolicy::Ipv4Only).is_err());
    }

    #[test]
    fn build_custom_accepts_valid_ip_list() {
        assert!(build_custom("1.1.1.1, 8.8.8.8", IpPolicy::Ipv4Only).is_ok());
        assert!(build_custom("2606:4700:4700::1111", IpPolicy::Default).is_ok());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_ipv4_literal_short_circuits() {
        // SAFETY: serialized; DNS unset selects the System backend.
        unsafe {
            std::env::remove_var("DNS");
        }
        let r = Resolver::from_env(IpPolicy::Ipv4Only).unwrap();
        assert_eq!(
            r.resolve("127.0.0.1", 80).await.unwrap(),
            Some("127.0.0.1:80".parse().unwrap())
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_ipv6_literal_filtered_under_ipv4_only() {
        // SAFETY: serialized.
        unsafe {
            std::env::remove_var("DNS");
        }
        let r = Resolver::from_env(IpPolicy::Ipv4Only).unwrap();
        assert_eq!(r.resolve("::1", 80).await.unwrap(), None);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_ipv6_literal_passes_under_prefer_ipv4() {
        // prefer-* must never filter a literal, only the *-only policies do.
        // SAFETY: serialized.
        unsafe {
            std::env::remove_var("DNS");
        }
        let r = Resolver::from_env(IpPolicy::PreferIpv4).unwrap();
        assert_eq!(
            r.resolve("[::1]", 80).await.unwrap(),
            Some("[::1]:80".parse().unwrap())
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_system_localhost_yields_ipv4() {
        // SAFETY: serialized.
        unsafe {
            std::env::remove_var("DNS");
        }
        let r = Resolver::from_env(IpPolicy::Ipv4Only).unwrap();
        let a = r.resolve("localhost", 80).await.unwrap();
        assert!(a.is_some_and(|s| s.ip().is_ipv4()));
    }

    #[test]
    #[serial_test::serial]
    fn from_env_builds_custom_backend_when_dns_set() {
        // SAFETY: serialized.
        unsafe {
            std::env::set_var("DNS", "1.1.1.1,8.8.8.8");
        }
        let r = Resolver::from_env(IpPolicy::Ipv4Only);
        unsafe {
            std::env::remove_var("DNS");
        }
        assert!(r.is_ok());
        assert_eq!(r.unwrap().policy(), IpPolicy::Ipv4Only);
    }
}
