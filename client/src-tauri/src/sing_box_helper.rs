use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/* =========================================================
   ROOT CONFIG
========================================================= */

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub log: Log,
    pub dns: Dns,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub route: Route,
    pub experimental: Option<Experimental>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Experimental {
    pub cache_file: Option<CacheFile>,
    pub clash_api: Option<ClashApi>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheFile {
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClashApi {
    pub external_controller: String,
    pub external_ui: Option<String>,
}

/* =========================================================
   MODES (YOUR REQUESTED HELPERS)
========================================================= */

impl Config {

    /// 1️⃣ tun inbound + socks outbound
    /// 1️⃣ tun inbound + socks outbound
    pub fn mode_tun_socks(
        proxy_host: &str, 
        proxy_port: u16,
        primary_dns: &str,
        secondary_dns: &str,
        inet4_address: &str,
        inet6_address: &str,
        mtu: u32,
        direct_domains: Vec<String>,
        block_domains: Vec<String>,
    ) -> Self {
        let mut cfg = Self::base();

        // DNS
        cfg.dns.servers = vec![
            DnsServer {
                tag: "dns-remote".into(),
                address: primary_dns.into(),
                address_resolver: Some("dns-local".into()),
                strategy: Some("prefer_ipv4".into()), 
                detour: Some("socks-out".into()),
            },
            DnsServer {
                tag: "dns-local".into(),
                address: secondary_dns.into(),
                address_resolver: None,
                strategy: None,
                detour: Some("direct-out".into()),
            },
            DnsServer {
                tag: "dns-block".into(),
                address: "rcode://success".into(),
                address_resolver: None,
                strategy: None,
                detour: None,
            },
        ];

        cfg.inbounds = vec![Inbound::tun(
            inet4_address, 
            inet6_address, 
            mtu, 
            "gvisor" // stack
        )];
        
        cfg.outbounds = vec![
            Outbound::socks("socks-out", proxy_host, proxy_port),
            Outbound::direct("direct-out"),
            Outbound::dns("dns-out"),
            Outbound::block("block-out"),
        ];

        cfg.route.final_ = "socks-out".into();

        // Custom Rules
        for domain in direct_domains {
            cfg.route.rules.push(RouteRule {
                protocol: None,
                outbound: Some("direct-out".into()),
                ip_cidr: None,
                domain: Some(vec![domain]),
            });
        }
        for domain in block_domains {
            cfg.route.rules.push(RouteRule {
                protocol: None,
                outbound: Some("block-out".into()),
                ip_cidr: None,
                domain: Some(vec![domain]),
            });
        }

        cfg
    }

    /// 2️⃣ socks inbound + wireguard outbound (simple, no keys)
    /// 2️⃣ socks inbound + wireguard outbound (simple, no keys)
    #[allow(dead_code)]
    pub fn mode_wireguard_socks(wg_endpoint: &str, wg_port: u16) -> Self {
        let mut cfg = Self::base();

        cfg.inbounds = vec![Inbound::socks_inbound("127.0.0.1", 1080)];
        cfg.outbounds = vec![
            Outbound::wireguard("wg-out", wg_endpoint, wg_port),
            Outbound::direct("direct-out"),
            Outbound::dns("dns-out"),
            Outbound::block("block-out"),
        ];

        cfg.route.final_ = "wg-out".into();
        cfg
    }

    /// 2b️⃣ SOCKS inbound (proxy mode) + full WireGuard outbound with key material
    /// Used when the user selects "Proxy" mode for WireGuard.
    /// Sing-box listens as a SOCKS proxy on socks_host:socks_port and routes
    /// all traffic through the WireGuard tunnel.
    #[allow(dead_code)]
    pub fn mode_wireguard_proxy(
        wg_endpoint: &str,
        wg_port: u16,
        private_key: &str,
        peer_public_key: &str,
        pre_shared_key: Option<&str>,
        local_addresses: Vec<String>,
        socks_host: &str,
        socks_port: u16,
    ) -> Self {
        let mut cfg = Self::base();

        // DNS: route through WireGuard outbound (not socks-out which doesn't exist here)
        cfg.dns.servers[0].detour = Some("wg-out".into());
        cfg.dns.servers[1].detour = Some("direct-out".into());

        cfg.inbounds = vec![Inbound::socks_inbound(socks_host, socks_port)];
        cfg.outbounds = vec![
            Outbound::wireguard_full(
                "wg-out", wg_endpoint, wg_port,
                private_key, peer_public_key, pre_shared_key,
                local_addresses, None, None,
                "1.1.1.1", "8.8.8.8",
            ),
            Outbound::direct("direct-out"),
            Outbound::dns("dns-out"),
            Outbound::block("block-out"),
        ];

        // Bypass the WireGuard server endpoint itself (route direct so we don't loop)
        cfg.route.rules.push(RouteRule {
            protocol: None,
            outbound: Some("direct-out".into()),
            ip_cidr: Some(vec![format!("{}/32", wg_endpoint)]),
            domain: None,
        });

        cfg.route.final_ = "wg-out".into();
        cfg
    }

    /// 3️⃣ tun inbound + wireguard outbound
    /// 3️⃣ tun inbound + wireguard outbound
    #[allow(dead_code)]
    pub fn mode_wireguard_tun(wg_endpoint: &str, wg_port: u16) -> Self {
        let mut cfg = Self::base();

        cfg.inbounds = vec![Inbound::tun("172.19.0.1/30", "fdfe::1/126", 1500, "gvisor")];
        cfg.outbounds = vec![
            Outbound::wireguard("wg-out", wg_endpoint, wg_port),
            Outbound::direct("direct-out"),
            Outbound::dns("dns-out"),
            Outbound::block("block-out"),
        ];

        cfg.route.final_ = "wg-out".into();
        cfg
    }

    /// 4️⃣ tun inbound + full wireguard outbound (with keys, peers, addresses)
    #[allow(dead_code)]
    pub fn mode_wireguard_tun_full(
        wg_endpoint: &str,
        wg_port: u16,
        private_key: &str,
        peer_public_key: &str,
        pre_shared_key: Option<&str>,
        local_addresses: Vec<String>,
        reserved: Option<Vec<u8>>,
        mtu: Option<u16>,
        primary_dns: &str,
        secondary_dns: &str,
    ) -> Self {
        let mut cfg = Self::base();

        // Update DNS servers to use WireGuard outbound
        cfg.dns.servers[0].address = primary_dns.to_string();
        cfg.dns.servers[0].detour = Some("wg-out".into());
        cfg.dns.servers[1].address = secondary_dns.to_string();

        cfg.inbounds = vec![Inbound::tun(
             "172.19.0.1/30", "fdfe::1/126", mtu.unwrap_or(1420) as u32, "gvisor"
        )];
        cfg.outbounds = vec![
            Outbound::wireguard_full(
                "wg-out", wg_endpoint, wg_port,
                private_key, peer_public_key, pre_shared_key,
                local_addresses, reserved, mtu,
                primary_dns, secondary_dns,
            ),
            Outbound::direct("direct-out"),
            Outbound::dns("dns-out"),
            Outbound::block("block-out"),
        ];

        // Add route rule to direct the WireGuard endpoint itself
        cfg.route.rules.push(RouteRule {
            protocol: None,
            outbound: Some("direct-out".into()),
            ip_cidr: Some(vec![format!("{}/32", wg_endpoint)]),
            domain: None,
        });

        cfg.route.final_ = "wg-out".into();
        cfg
    }

    /// base shared config (dns, log, route etc)
    fn base() -> Self {
        Self {
            log: Log {
                level: "info".into(),
                timestamp: true,
            },

            dns: Dns::default(),

            inbounds: vec![],
            outbounds: vec![],

            route: Route::default(),
            experimental: None,
        }
    }
}

/* =========================================================
   LOG
========================================================= */

#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    pub level: String,
    pub timestamp: bool,
}

/* =========================================================
   DNS
========================================================= */

#[derive(Debug, Serialize, Deserialize)]
pub struct Dns {
    pub servers: Vec<DnsServer>,

    #[serde(rename = "final")]
    pub final_: String,

    pub strategy: String,
    pub disable_cache: bool,
    pub disable_expire: bool,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            servers: vec![
                DnsServer {
                    tag: "dns-remote".into(),
                    address: "1.1.1.1".into(),
                    address_resolver: Some("dns-local".into()),
                    strategy: Some("prefer_ipv4".into()),
                    detour: Some("socks-out".into()),
                },
                DnsServer {
                    tag: "dns-local".into(),
                    address: "8.8.8.8".into(),
                    address_resolver: None,
                    strategy: None,
                    detour: Some("direct-out".into()),
                },
                DnsServer {
                    tag: "dns-block".into(),
                    address: "rcode://success".into(),
                    address_resolver: None,
                    strategy: None,
                    detour: None,
                },
            ],
            final_: "dns-remote".into(),
            strategy: "prefer_ipv4".into(),
            disable_cache: false,
            disable_expire: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsServer {
    pub tag: String,
    pub address: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_resolver: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
}

/* =========================================================
   INBOUND (GENERIC WITH EXTRA FIELDS)
========================================================= */

#[derive(Debug, Serialize, Deserialize)]
pub struct Inbound {
    #[serde(rename = "type")]
    pub kind: String,

    pub tag: String,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl Inbound {

    /// tun inbound preset
    pub fn tun(inet4: &str, inet6: &str, mtu: u32, stack: &str) -> Self {
        let mut extra = HashMap::new();

        extra.insert("interface_name".into(), "CandyConnect".into());
        extra.insert("inet4_address".into(), inet4.into());
        extra.insert("inet6_address".into(), inet6.into());
        extra.insert("mtu".into(), mtu.into());
        extra.insert("auto_route".into(), true.into());
        extra.insert("strict_route".into(), false.into());
        extra.insert("sniff".into(), true.into());
        extra.insert("stack".into(), stack.into());
        extra.insert("sniff_override_destination".into(), false.into());
        extra.insert("endpoint_independent_nat".into(), true.into());
        
        let mut platform = serde_json::Map::new();
        let mut http_proxy = serde_json::Map::new();
        http_proxy.insert("enabled".into(), Value::Bool(true));
        http_proxy.insert("server".into(), Value::String("127.0.0.1".into()));
        http_proxy.insert("server_port".into(), Value::Number(2080.into()));
        platform.insert("http_proxy".into(), Value::Object(http_proxy));
        extra.insert("platform".into(), Value::Object(platform));

        Self {
            kind: "tun".into(),
            tag: "tun-in".into(),
            extra,
        }
    }

    /// socks inbound preset
    #[allow(dead_code)]
    pub fn socks_inbound(bind: &str, port: u16) -> Self {
        let mut extra = HashMap::new();
        extra.insert("listen".into(), bind.into());
        extra.insert("listen_port".into(), port.into());

        Self {
            kind: "socks".into(),
            tag: "socks-in".into(),
            extra,
        }
    }
}

/* =========================================================
   OUTBOUND
========================================================= */

#[derive(Debug, Serialize, Deserialize)]
pub struct Outbound {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl Outbound {

    pub fn socks(tag: &str, host: &str, port: u16) -> Self {
        let mut extra = HashMap::new();
        extra.insert("server".into(), host.into());
        extra.insert("server_port".into(), port.into());

        Self {
            kind: "socks".into(),
            tag: tag.into(),
            extra,
        }
    }

    #[allow(dead_code)]
    pub fn wireguard(tag: &str, endpoint: &str, port: u16) -> Self {
        let mut extra = HashMap::new();
        extra.insert("server".into(), endpoint.into());
        extra.insert("server_port".into(), port.into());

        Self {
            kind: "wireguard".into(),
            tag: tag.into(),
            extra,
        }
    }

    /// Full WireGuard outbound with all key material and peer config
    #[allow(dead_code)]
    pub fn wireguard_full(
        tag: &str,
        endpoint: &str,
        port: u16,
        private_key: &str,
        peer_public_key: &str,
        pre_shared_key: Option<&str>,
        local_addresses: Vec<String>,
        reserved: Option<Vec<u8>>,
        mtu: Option<u16>,
        primary_dns: &str, // Just to match caller if needed
        secondary_dns: &str, // Unused here, but kept if you want to use it
    ) -> Self {
        let mut extra = HashMap::new();
        extra.insert("server".into(), Value::String(endpoint.into()));
        extra.insert("server_port".into(), Value::Number(port.into()));
        extra.insert("private_key".into(), Value::String(private_key.into()));
        
        let _ = primary_dns;
        let _ = secondary_dns;

        // Build peer object
        let mut peer = serde_json::Map::new();
        peer.insert("public_key".into(), Value::String(peer_public_key.into()));
        if let Some(psk) = pre_shared_key {
            if !psk.is_empty() {
                peer.insert("pre_shared_key".into(), Value::String(psk.into()));
            }
        }
        // allowed_ips: route everything through the tunnel
        peer.insert("allowed_ips".into(), Value::Array(vec![
            Value::String("0.0.0.0/0".into()),
            Value::String("::/0".into()),
        ]));
        extra.insert("peers".into(), Value::Array(vec![Value::Object(peer)]));

        // Local addresses for the WireGuard interface
        let addr_values: Vec<Value> = local_addresses.iter().map(|a| Value::String(a.clone())).collect();
        extra.insert("local_address".into(), Value::Array(addr_values));

        if let Some(r) = reserved {
            let r_values: Vec<Value> = r.iter().map(|b| Value::Number((*b).into())).collect();
            extra.insert("reserved".into(), Value::Array(r_values));
        }

        extra.insert("mtu".into(), Value::Number(mtu.unwrap_or(1280).into()));

        Self {
            kind: "wireguard".into(),
            tag: tag.into(),
            extra,
        }
    }

    pub fn direct(tag: &str) -> Self {
        Self {
            kind: "direct".into(),
            tag: tag.into(),
            extra: HashMap::new(),
        }
    }

    pub fn dns(tag: &str) -> Self {
        Self {
            kind: "dns".into(),
            tag: tag.into(),
            extra: HashMap::new(),
        }
    }

    pub fn block(tag: &str) -> Self {
        Self {
            kind: "block".into(),
            tag: tag.into(),
            extra: HashMap::new(),
        }
    }
}

/* =========================================================
   ROUTE
========================================================= */

#[derive(Debug, Serialize, Deserialize)]
pub struct Route {
    pub rules: Vec<RouteRule>,

    #[serde(rename = "final")]
    pub final_: String,

    pub auto_detect_interface: bool,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            rules: vec![
                RouteRule {
                    protocol: Some("dns".into()),
                    outbound: Some("dns-out".into()),
                    ip_cidr: None,
                    domain: None,
                }
            ],
            final_: "socks-out".into(),
            auto_detect_interface: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteRule {
    pub protocol: Option<String>,
    pub outbound: Option<String>,
    pub ip_cidr: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
}

/* =========================================================
 DEMO
========================================================= */

/* fn main() -> Result<(), Box<dyn Error>> {

    // choose mode here 👇

    let config = Config::mode_wireguard_tun("1.2.3.4", 51820);
    // let config = Config::mode_tun_socks("127.0.0.1", 1080);
    // let config = Config::mode_wireguard_socks("1.2.3.4", 51820);

    let json = serde_json::to_string_pretty(&config)?;
    std::fs::write("config.json", json)?;

    println!("config.json written");

    Ok(())
}
*/