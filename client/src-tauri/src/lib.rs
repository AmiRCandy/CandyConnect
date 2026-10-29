mod sing_box_helper;
mod local_proxy;
mod system_proxy;

use std::fs;
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent},
    Manager,
};

/* ───────────────────────── connection session / cleanup ───────────────────────── */

/// Monotonic id of the current connection attempt. Every start_* command begins a new
/// session and stop_vpn ends it, so watcher threads of an older (stopped or replaced)
/// connection can tell they are stale and must not tear down / report the new one.
static CONN_SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn current_session() -> u64 {
    CONN_SESSION.load(std::sync::atomic::Ordering::SeqCst)
}

fn is_current_session(id: u64) -> bool {
    current_session() == id
}

/// Start a new connection session: invalidates old watchers and undoes any system proxy
/// left over from a previous connection.
fn begin_session(app_data_dir: &std::path::Path) -> u64 {
    let id = CONN_SESSION.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    system_proxy::restore(app_data_dir, &app_data_dir.join("candy.logs"));
    id
}

/// The in-process local proxy (DNS tunnels), tagged with its session id.
fn local_proxy_slot() -> &'static Mutex<Option<(u64, local_proxy::ProxyHandle)>> {
    static SLOT: OnceLock<Mutex<Option<(u64, local_proxy::ProxyHandle)>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Stop the in-process local proxy (only the one of `session`, or any when `None`).
fn stop_local_proxy(session: Option<u64>) {
    let mut slot = local_proxy_slot().lock().unwrap_or_else(|e| e.into_inner());
    let matches = match (&*slot, session) {
        (Some((id, _)), Some(s)) => *id == s,
        (Some(_), None) => true,
        _ => false,
    };
    if matches {
        if let Some((_, h)) = slot.take() {
            h.stop();
        }
    }
}

/// Called by watcher threads when an engine process / tunnel of `session` ended on its own:
/// restores the system proxy and tells the UI — unless the session was already replaced
/// or stopped (then the exit was expected and the new connection must not be touched).
fn notify_engine_exit(app: &tauri::AppHandle, session: u64) {
    if !is_current_session(session) {
        return;
    }
    if let Ok(dir) = app.path().app_data_dir() {
        system_proxy::restore(&dir, &dir.join("candy.logs"));
    }
    stop_local_proxy(Some(session));
    use tauri::Emitter;
    let _ = app.emit("vpn-disconnected", ());
}

/// In Proxy mode, point the OS proxy at the local inbound unless the user turned the
/// "Set system proxy" setting off. Failures are logged, never fatal.
fn apply_system_proxy(
    app_data_dir: &std::path::Path,
    mode: &str,
    session: u64,
    host: &str,
    http_port: Option<u16>,
    socks_port: Option<u16>,
) {
    let logs_path = app_data_dir.join("candy.logs");
    if mode != "proxy" || !is_current_session(session) {
        return;
    }
    if read_settings(app_data_dir)["systemProxy"].as_bool() == Some(false) {
        let _ = append_log(&logs_path, "info", "System proxy is disabled in settings — configure apps to use the local proxy manually");
        return;
    }
    let target = system_proxy::ProxyTarget { host: host.to_string(), http_port, socks_port };
    if let Err(e) = system_proxy::set(app_data_dir, &logs_path, &target) {
        let _ = append_log(&logs_path, "warn", &format!("Could not set the system proxy: {}", e));
    }
}

#[tauri::command]
async fn generate_sing_box_config(app: tauri::AppHandle, server_address: String) -> Result<String, String> {
    let app_data_dir = app.path().app_data_dir().map_err(|e| format!("Failed to get app data directory: {}", e))?;
    build_tun_socks_config(&app_data_dir, &server_address, None, false)
}

/// Read settings.json from the app data dir (returns `Null` when missing/invalid so callers fall back to defaults).
fn read_settings(app_data_dir: &std::path::Path) -> serde_json::Value {
    fs::read_to_string(app_data_dir.join("settings.json"))
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .unwrap_or(serde_json::Value::Null)
}

/// Local proxy listen address configured by the user (ProxyPage), defaulting to 127.0.0.1:10808.
fn local_proxy_from_settings(settings: &serde_json::Value) -> (String, u16) {
    let host = settings["proxyHost"].as_str()
        .or_else(|| settings["proxyAddress"].as_str())
        .filter(|h| !h.trim().is_empty())
        .unwrap_or("127.0.0.1")
        .to_string();
    let port = settings["proxyPort"].as_u64()
        .filter(|p| *p > 0 && *p <= 65535)
        .unwrap_or(10808) as u16;
    (host, port)
}

/// Build a sing-box TUN config whose default outbound is a local SOCKS proxy.
/// `proxy_override` forces the SOCKS target (e.g. xray's or SSH's local SOCKS port);
/// otherwise proxyHost/proxyPort from settings.json are used.
fn build_tun_socks_config(
    app_data_dir: &std::path::Path,
    server_address: &str,
    proxy_override: Option<(&str, u16)>,
    tcp_dns: bool,
) -> Result<String, String> {
    use crate::sing_box_helper::{Config, RouteRule};

    let settings = read_settings(app_data_dir);

    // Extract settings with defaults
    let primary_dns = settings["primaryDns"].as_str().filter(|s| !s.is_empty()).unwrap_or("8.8.8.8");
    let secondary_dns = settings["secondaryDns"].as_str().filter(|s| !s.is_empty()).unwrap_or("1.1.1.1");
    let inet4 = settings["tunInet4CIDR"].as_str().filter(|s| !s.is_empty()).unwrap_or("172.19.0.1/30");
    let inet6 = settings["tunInet6CIDR"].as_str().filter(|s| !s.is_empty()).unwrap_or("fdfe:dcba:9876::1/126");
    let mtu = settings["mtu"].as_u64().filter(|m| *m >= 576).unwrap_or(9000) as u32;
    let (settings_host, settings_port) = local_proxy_from_settings(&settings);
    let (mut proxy_host, proxy_port) = match proxy_override {
        Some((h, p)) => (h.to_string(), p),
        None => (settings_host, settings_port),
    };
    // A wildcard listen address is not a valid dial target
    if proxy_host == "0.0.0.0" || proxy_host == "::" || proxy_host.is_empty() {
        proxy_host = "127.0.0.1".to_string();
    }

    // Collect custom domains
    let mut direct_domains = Vec::new();
    if let Some(arr) = settings["customDirectDomains"].as_array() {
        for v in arr {
            if let Some(s) = v.as_str() {
                direct_domains.push(s.to_string());
            }
        }
    }

    let mut block_domains = Vec::new();
    if let Some(arr) = settings["customBlockDomains"].as_array() {
        for v in arr {
            if let Some(s) = v.as_str() {
                block_domains.push(s.to_string());
            }
        }
    }

    // Initialize config using helper
    let mut config = Config::mode_tun_socks(
        &proxy_host,
        proxy_port,
        primary_dns,
        secondary_dns,
        inet4,
        inet6,
        mtu,
        direct_domains,
        block_domains,
    );

    // Upstreams without UDP (SSH direct-tcpip, plain SOCKS CONNECT) need DNS over TCP
    if tcp_dns {
        if let Some(remote) = config.dns.servers.first_mut() {
            if !remote.address.contains("://") {
                remote.address = format!("tcp://{}", remote.address);
            }
        }
    }

    // Add server bypass rule (IP or Domain) so the tunnel's own traffic doesn't loop through TUN
    if let Ok(ip) = server_address.parse::<std::net::IpAddr>() {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        config.route.rules.push(RouteRule {
            protocol: None,
            outbound: Some("direct-out".into()),
            ip_cidr: Some(vec![format!("{}/{}", server_address, prefix)]),
            domain: None,
        });
    } else if !server_address.is_empty() {
        config.route.rules.push(RouteRule {
            protocol: None,
            outbound: Some("direct-out".into()),
            ip_cidr: None,
            domain: Some(vec![server_address.to_string()]),
        });
    }

    // Serialize
    serde_json::to_string_pretty(&config).map_err(|e| e.to_string())
}

/// Locate a helper binary (xray, sing-box, dnstt-client, ...).
/// Search order: bundled resource dir, `<resource_dir>/resources`, next to the app executable
/// (same sub-path as bundled, e.g. `xray/xray.exe`, then the bare file name),
/// then the system PATH. Returns a clear error when nothing is found (e.g. on Linux/macOS,
/// where only the Windows .exe builds are bundled).
fn resolve_binary(resource_dir: &std::path::Path, rel_path: &str) -> Result<std::path::PathBuf, String> {
    use std::path::{Path, PathBuf};

    let bundled = [resource_dir.join(rel_path), resource_dir.join("resources").join(rel_path)];
    let file_name: PathBuf = Path::new(rel_path)
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(rel_path));

    let mut candidates: Vec<PathBuf> = bundled.to_vec();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // Release zip layout: <exe dir>/xray/xray(.exe), <exe dir>/sing-box/sing-box(.exe),
            // <exe dir>/openvpn/openvpn.exe, <exe dir>/dnstt-client(.exe)
            candidates.push(dir.join(rel_path));
            candidates.push(dir.join("resources").join(rel_path));
            candidates.push(dir.join(&file_name));
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            candidates.push(dir.join(&file_name));
        }
    }

    for c in candidates {
        if c.is_file() {
            // Bundled resources may lose their executable bit on Unix — try to restore it
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(&c) {
                    let mode = meta.permissions().mode();
                    if mode & 0o111 == 0 {
                        let _ = fs::set_permissions(&c, fs::Permissions::from_mode(mode | 0o755));
                    }
                }
            }
            return Ok(c);
        }
    }

    Err(format!(
        "'{}' was not found (looked in {} and on the system PATH). Install it or place the binary there.",
        file_name.display(),
        bundled[0].display()
    ))
}

/// Environment flags needed by the bundled sing-box (1.12.x) to accept the legacy
/// config fields generated by sing_box_helper (special outbounds, tun inet4_address,
/// inbound sniff fields, wireguard outbound). Without them sing-box 1.12 exits with a fatal error.
fn apply_sing_box_env(cmd: &mut std::process::Command) {
    cmd.env("ENABLE_DEPRECATED_SPECIAL_OUTBOUNDS", "true")
        .env("ENABLE_DEPRECATED_TUN_ADDRESS_X", "true")
        .env("ENABLE_DEPRECATED_WIREGUARD_OUTBOUND", "true")
        .env("ENABLE_DEPRECATED_INBOUND_OPTIONS", "true")
        .env("ENABLE_DEPRECATED_DESTINATION_OVERRIDE_FIELDS", "true");
}

/// Adapt the server-provided Xray client config to this machine:
/// - bind the SOCKS inbound to the user's local proxy address/port (and HTTP on port+1)
/// - drop geosite:/geoip: routing entries when geosite.dat/geoip.dat are not available
///   (xray refuses to start if a referenced .dat file is missing)
/// Returns the (host, SOCKS port, HTTP port) of the local inbounds.
fn prepare_xray_config(
    cfg: &mut serde_json::Value,
    socks_host: &str,
    socks_port: u16,
    have_geo_files: bool,
) -> (String, u16, u16) {
    use serde_json::{json, Value};

    let http_port = if socks_port < 65535 { socks_port + 1 } else { socks_port - 1 };

    if !cfg["inbounds"].is_array() {
        cfg["inbounds"] = json!([]);
    }
    let mut has_socks = false;
    let mut has_http = false;
    if let Some(inbounds) = cfg["inbounds"].as_array_mut() {
        for inbound in inbounds.iter_mut() {
            match inbound["protocol"].as_str() {
                Some("socks") if !has_socks => {
                    inbound["listen"] = Value::String(socks_host.to_string());
                    inbound["port"] = json!(socks_port);
                    has_socks = true;
                }
                Some("http") if !has_http => {
                    inbound["listen"] = Value::String(socks_host.to_string());
                    inbound["port"] = json!(http_port);
                    has_http = true;
                }
                _ => {}
            }
        }
        if !has_socks {
            inbounds.push(json!({
                "port": socks_port,
                "listen": socks_host,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": true}
            }));
        }
        // The HTTP inbound is what the OS system proxy points at in Proxy mode
        if !has_http {
            inbounds.push(json!({
                "port": http_port,
                "listen": socks_host,
                "protocol": "http",
                "settings": {}
            }));
        }
    }

    if !have_geo_files {
        const PRIVATE_CIDRS: [&str; 9] = [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
            "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128",
        ];
        if let Some(rules) = cfg["routing"]["rules"].as_array_mut() {
            rules.retain_mut(|rule| {
                let had_matcher = rule.get("domain").is_some() || rule.get("ip").is_some();
                if let Some(domains) = rule.get_mut("domain").and_then(|d| d.as_array_mut()) {
                    domains.retain(|d| {
                        let s = d.as_str().unwrap_or("");
                        !s.starts_with("geosite:") && !s.starts_with("ext:")
                    });
                }
                if let Some(ips) = rule.get_mut("ip").and_then(|d| d.as_array_mut()) {
                    let mut out: Vec<Value> = Vec::new();
                    for ip in ips.iter() {
                        let s = ip.as_str().unwrap_or("");
                        if s == "geoip:private" {
                            out.extend(PRIVATE_CIDRS.iter().map(|c| Value::String(c.to_string())));
                        } else if !s.starts_with("geoip:") && !s.starts_with("ext:") {
                            out.push(ip.clone());
                        }
                    }
                    *ips = out;
                }
                if let Some(obj) = rule.as_object_mut() {
                    for key in ["domain", "ip"] {
                        if obj.get(key).and_then(|v| v.as_array()).map_or(false, |a| a.is_empty()) {
                            obj.remove(key);
                        }
                    }
                    // A rule that lost all of its conditions would match *everything* — drop it.
                    const MATCHERS: [&str; 10] = [
                        "domain", "ip", "port", "sourcePort", "network", "source", "user",
                        "inboundTag", "protocol", "attrs",
                    ];
                    if had_matcher && !MATCHERS.iter().any(|k| obj.contains_key(*k)) {
                        return false;
                    }
                }
                true
            });
        }
    }

    (socks_host.to_string(), socks_port, http_port)
}

/// Extract the remote server address from the first proxy outbound of an Xray config
/// (vnext for vless/vmess, servers for trojan/shadowsocks).
fn xray_server_address(cfg: &serde_json::Value) -> Option<String> {
    let outbounds = cfg["outbounds"].as_array()?;
    let proxy = outbounds
        .iter()
        .find(|o| o["tag"].as_str() == Some("proxy"))
        .or_else(|| outbounds.iter().find(|o| !matches!(o["protocol"].as_str(), Some("freedom") | Some("blackhole") | Some("dns"))))?;
    let settings = &proxy["settings"];
    settings["vnext"][0]["address"].as_str()
        .or_else(|| settings["servers"][0]["address"].as_str())
        .map(|s| s.to_string())
}

/// Kill a process by PID. Used to tear down the companion process in TUN mode
/// (e.g. kill sing-box when xray exits, or vice versa).
fn kill_process(pid: u32) {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill")
            .args(&["/F", "/PID", &pid.to_string(), "/T"])
            .creation_flags(0x08000000)
            .spawn();
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::process::Command;
        let _ = Command::new("kill").args(&["-9", &pid.to_string()]).spawn();
    }
}

#[tauri::command]
async fn start_vpn(
    app: tauri::AppHandle,
    config_json: String,
    mode: String,
) -> Result<(), String> {
    use std::process::{Command, Stdio};
    use std::io::{BufRead, BufReader};
    use std::thread;

    let app_data_dir = app.path().app_data_dir().map_err(|e| format!("Failed to get app dir: {}", e))?;
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    let logs_path = app_data_dir.join("candy.logs");
    let session = begin_session(&app_data_dir);

    // 1. Resolve engine binaries (bundled .exe on Windows, bundled or system PATH elsewhere)
    let xray_bin = resolve_binary(&resource_dir, if cfg!(target_os = "windows") { "xray/xray.exe" } else { "xray/xray" })
        .map_err(|e| {
            let msg = format!("Xray engine not available: {}", e);
            let _ = append_log(&logs_path, "error", &msg);
            msg
        })?;
    let sing_box_bin = if mode == "tun" {
        Some(resolve_binary(&resource_dir, if cfg!(target_os = "windows") { "sing-box/sing-box.exe" } else { "sing-box/sing-box" })
            .map_err(|e| {
                let msg = format!("Sing-box (required for TUN mode) not available: {}", e);
                let _ = append_log(&logs_path, "error", &msg);
                msg
            })?)
    } else {
        None
    };

    // 2. Validate, adapt and save Xray config
    let xray_config_path = app_data_dir.join("xray_config.json");

    // Validate that config_json is valid JSON before writing
    let mut parsed: serde_json::Value = serde_json::from_str(&config_json).map_err(|e| {
        let err_msg = format!("Invalid Xray config JSON: {}. First 200 chars: {}", e, config_json.chars().take(200).collect::<String>());
        let _ = append_log(&logs_path, "error", &err_msg);
        err_msg
    })?;

    // Bind the local SOCKS/HTTP inbounds to the user's proxy settings so proxy mode and
    // the TUN (sing-box -> socks) chain agree on the port.
    let settings = read_settings(&app_data_dir);
    let (proxy_host, proxy_port) = local_proxy_from_settings(&settings);
    let xray_dir = xray_bin.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| resource_dir.clone());
    let have_geo_files = xray_dir.join("geosite.dat").is_file() && xray_dir.join("geoip.dat").is_file();
    if !have_geo_files {
        let _ = append_log(&logs_path, "warn", "geosite.dat/geoip.dat not found next to xray — geo routing rules will be skipped");
    }
    let (socks_host, socks_port, http_port) = prepare_xray_config(&mut parsed, &proxy_host, proxy_port, have_geo_files);
    let server_address = xray_server_address(&parsed).unwrap_or_default();
    let _ = append_log(&logs_path, "info", &format!(
        "Xray local proxy: socks={}:{}, http={}:{}", socks_host, socks_port, socks_host, http_port
    ));

    // Re-serialize to ensure clean formatting
    let clean_config = serde_json::to_string_pretty(&parsed).unwrap_or(config_json.clone());
    fs::write(&xray_config_path, &clean_config).map_err(|e| e.to_string())?;

    // Log config snippet for debugging (first 200 chars)
    let config_preview: String = clean_config.chars().take(200).collect();
    let _ = append_log(&logs_path, "info", &format!("Xray config saved ({} bytes): {}...", clean_config.len(), config_preview));

    // 3. Start Xray
    let _ = append_log(&logs_path, "info", &format!("Starting Xray engine: {}", xray_bin.display()));

    let mut xray_cmd = Command::new(&xray_bin);
    xray_cmd
        .arg("run")
        .arg("-c")
        .arg(&xray_config_path)
        .env("XRAY_LOCATION_ASSET", &xray_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Prevent console window flash on Windows
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        xray_cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let mut xray_child = xray_cmd
        .spawn()
        .map_err(|e| {
            let err_msg = format!("CRITICAL: Failed to spawn Xray ({}): {}", xray_bin.display(), e);
            let _ = append_log(&logs_path, "error", &err_msg);
            err_msg
        })?;

    let _ = append_log(&logs_path, "info", &format!("Xray process spawned successfully (PID: {})", xray_child.id()));

    // Log Xray output to candy.logs
    let stdout = xray_child.stdout.take().unwrap();
    let stderr = xray_child.stderr.take().unwrap();

    let logs_path_clone = logs_path.clone();
    let xray_stdout_thread = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs_path_clone, "info", &format!("[Xray] {}", l));
                }
                Err(e) => {
                    let _ = append_log(&logs_path_clone, "warn", &format!("[Xray] stdout read error: {}", e));
                    break;
                }
                _ => {}
            }
        }
    });

    let logs_path_err = logs_path.clone();
    let xray_stderr_thread = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs_path_err, "error", &format!("[Xray] {}", l));
                }
                Err(e) => {
                    let _ = append_log(&logs_path_err, "warn", &format!("[Xray] stderr read error: {}", e));
                    break;
                }
                _ => {}
            }
        }
    });

    // Brief health check: wait a moment to see if xray survives startup
    thread::sleep(std::time::Duration::from_millis(500));
    match xray_child.try_wait() {
        Ok(Some(status)) => {
            // Process already exited — wait for output threads to capture everything
            let _ = xray_stdout_thread.join();
            let _ = xray_stderr_thread.join();
            let err_msg = format!("Xray exited immediately with {}", status);
            let _ = append_log(&logs_path, "error", &err_msg);
            use tauri::Emitter;
            let _ = app.emit("vpn-disconnected", ());
            return Err(err_msg);
        }
        Ok(None) => {
            let _ = append_log(&logs_path, "info", "Xray process is running after health check");
        }
        Err(e) => {
            let _ = append_log(&logs_path, "warn", &format!("Could not check Xray status: {}", e));
        }
    }

    // Shared PID holders for cross-process cleanup in TUN mode
    let xray_pid = xray_child.id();
    let sing_box_pid: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let is_tun_mode = mode == "tun";

    // Watch Xray exit in background — wait for output threads to flush before emitting event
    let app_h_xray = app.clone();
    let logs_p_xray_exit = logs_path.clone();
    let sing_box_pid_for_xray = Arc::clone(&sing_box_pid);
    thread::spawn(move || {
        let exit_status = xray_child.wait();
        // Wait for stdout/stderr reader threads to finish processing all output
        let _ = xray_stdout_thread.join();
        let _ = xray_stderr_thread.join();
        match exit_status {
            Ok(status) => {
                let _ = append_log(&logs_p_xray_exit, "warn", &format!("Xray process exited with {}", status));
            }
            Err(e) => {
                let _ = append_log(&logs_p_xray_exit, "error", &format!("Failed to wait on Xray process: {}", e));
            }
        }
        // In TUN mode, kill sing-box if it's still running
        if is_tun_mode {
            if let Some(sb_pid) = *sing_box_pid_for_xray.lock().unwrap() {
                let _ = append_log(&logs_p_xray_exit, "info", &format!("Xray exited — killing companion Sing-box (PID {})", sb_pid));
                kill_process(sb_pid);
            }
        }
        notify_engine_exit(&app_h_xray, session);
    });

    // 4. If TUN mode, also start Sing-box
    if mode == "tun" {
        let _ = append_log(&logs_path, "info", "Initializing TUN mode orchestration...");
        let sing_box_bin = sing_box_bin.clone().unwrap_or_default();

        let sb_config = match build_tun_socks_config(&app_data_dir, &server_address, Some((&socks_host, socks_port)), false) {
            Ok(c) => c,
            Err(e) => {
                kill_process(xray_pid);
                return Err(format!("Failed to build sing-box TUN config: {}", e));
            }
        };
        let sb_config_path = app_data_dir.join("sing_box_config.json");
        if let Err(e) = fs::write(&sb_config_path, &sb_config) {
            kill_process(xray_pid);
            return Err(e.to_string());
        }

        let _ = append_log(&logs_path, "info", &format!("Starting Sing-box routing engine: {}", sing_box_bin.display()));

        let mut sb_cmd = Command::new(&sing_box_bin);
        sb_cmd
            .arg("run")
            .arg("-c")
            .arg(&sb_config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        apply_sing_box_env(&mut sb_cmd);

        // Prevent console window flash on Windows
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            sb_cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        let mut sb_child = match sb_cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                let err_msg = format!("CRITICAL: Failed to spawn Sing-box: {}", e);
                let _ = append_log(&logs_path, "error", &err_msg);
                // Kill xray since TUN mode can't work without sing-box
                let _ = append_log(&logs_path, "info", &format!("Killing Xray (PID {}) because Sing-box failed to start", xray_pid));
                kill_process(xray_pid);
                use tauri::Emitter;
                let _ = app.emit("vpn-disconnected", ());
                return Err(err_msg);
            }
        };

        let _ = append_log(&logs_path, "info", &format!("Sing-box TUN engine spawned successfully (PID: {})", sb_child.id()));

        if sing_box_bin.exists() {
            let _ = append_log(&logs_path, "info", &format!("Sing-box binary confirmed at: {}", sing_box_bin.display()));
        } else {
            let _ = append_log(&logs_path, "error", &format!("Sing-box binary NOT FOUND at: {}", sing_box_bin.display()));
        }

        let sb_stdout = sb_child.stdout.take().unwrap();
        let sb_stderr = sb_child.stderr.take().unwrap();

        let logs_path_sb = logs_path.clone();
        let sb_stdout_thread = thread::spawn(move || {
            let reader = BufReader::new(sb_stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) if !l.trim().is_empty() => {
                        let _ = append_log(&logs_path_sb, "info", &format!("[Sing-box] {}", l));
                    }
                    Err(e) => {
                        let _ = append_log(&logs_path_sb, "warn", &format!("[Sing-box] stdout read error: {}", e));
                        break;
                    }
                    _ => {}
                }
            }
        });

        let logs_path_sb_err = logs_path.clone();
        let sb_stderr_thread = thread::spawn(move || {
            let reader = BufReader::new(sb_stderr);
            for line in reader.lines() {
                match line {
                    Ok(l) if !l.trim().is_empty() => {
                        let _ = append_log(&logs_path_sb_err, "error", &format!("[Sing-box] {}", l));
                    }
                    Err(e) => {
                        let _ = append_log(&logs_path_sb_err, "warn", &format!("[Sing-box] stderr read error: {}", e));
                        break;
                    }
                    _ => {}
                }
            }
        });

        // Brief health check for sing-box
        thread::sleep(std::time::Duration::from_millis(500));
        match sb_child.try_wait() {
            Ok(Some(status)) => {
                let _ = sb_stdout_thread.join();
                let _ = sb_stderr_thread.join();
                let err_msg = format!("Sing-box exited immediately with {}", status);
                let _ = append_log(&logs_path, "error", &err_msg);
                // Kill xray since TUN mode can't work without sing-box
                let _ = append_log(&logs_path, "info", &format!("Killing Xray (PID {}) because Sing-box failed to start", xray_pid));
                kill_process(xray_pid);
                use tauri::Emitter;
                let _ = app.emit("vpn-disconnected", ());
                return Err(err_msg);
            }
            Ok(None) => {
                let _ = append_log(&logs_path, "info", "Sing-box process is running after health check");
            }
            Err(e) => {
                let _ = append_log(&logs_path, "warn", &format!("Could not check Sing-box status: {}", e));
            }
        }

        // Store sing-box PID so the xray watcher can kill it if xray exits first
        *sing_box_pid.lock().unwrap() = Some(sb_child.id());

        // Watch Sing-box exit in background — kill xray if sing-box exits first
        let app_h_sb = app.clone();
        let logs_p_sb_exit = logs_path.clone();
        let xray_pid_for_sb = xray_pid;
        thread::spawn(move || {
            let exit_status = sb_child.wait();
            let _ = sb_stdout_thread.join();
            let _ = sb_stderr_thread.join();
            match exit_status {
                Ok(status) => {
                    let _ = append_log(&logs_p_sb_exit, "warn", &format!("Sing-box process exited with {}", status));
                }
                Err(e) => {
                    let _ = append_log(&logs_p_sb_exit, "error", &format!("Failed to wait on Sing-box process: {}", e));
                }
            }
            // Kill xray since sing-box (TUN routing) is dead
            let _ = append_log(&logs_p_sb_exit, "info", &format!("Sing-box exited — killing companion Xray (PID {})", xray_pid_for_sb));
            kill_process(xray_pid_for_sb);
            notify_engine_exit(&app_h_sb, session);
        });
    } else {
        apply_system_proxy(&app_data_dir, &mode, session, &socks_host, Some(http_port), Some(socks_port));
    }

    Ok(())
}

/// Start WireGuard via sing-box.
/// - proxy mode: SOCKS inbound on proxyHost:proxyPort + WireGuard outbound
/// - tun mode:   TUN inbound + WireGuard outbound (full key material)
#[tauri::command]
async fn start_wireguard(
    app: tauri::AppHandle,
    server: String,
    port: u64,
    private_key: String,
    peer_public_key: String,
    pre_shared_key: String,
    local_addresses: Vec<String>,
    mode: String,
    mtu: Option<u64>,
) -> Result<(), String> {
    use std::process::{Command, Stdio};
    use std::io::{BufRead, BufReader};
    use std::thread;
    use crate::sing_box_helper::Config;

    let app_data_dir = app.path().app_data_dir().expect("Failed to get app dir");
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    let logs_path = app_data_dir.join("candy.logs");

    let session = begin_session(&app_data_dir);
    let _ = append_log(&logs_path, "info", &format!(
        "Starting WireGuard via sing-box: server={}:{}, mode={}", server, port, mode
    ));

    let sing_box_bin = resolve_binary(
        &resource_dir,
        if cfg!(target_os = "windows") { "sing-box/sing-box.exe" } else { "sing-box/sing-box" }
    ).map_err(|e| {
        let msg = format!("Sing-box (required for WireGuard) not available: {}", e);
        let _ = append_log(&logs_path, "error", &msg);
        msg
    })?;

    // WireGuard tunnel MTU comes from the server (default 1420). The TUN "mtu" setting
    // (default 9000) must NOT be used for the WireGuard interface itself.
    let wg_mtu: u16 = mtu.filter(|m| *m >= 576 && *m <= 9000).unwrap_or(1420) as u16;

    // Build the correct sing-box config depending on mode
    let mut wg_proxy_listen: Option<(String, u16)> = None;
    let sb_config = if mode == "tun" {
        // TUN mode: TUN inbound + WireGuard outbound with full key material
        // Read TUN settings from settings file
        let settings_path = app_data_dir.join("settings.json");
        let (_inet4, _inet6, _tun_mtu, primary_dns, secondary_dns) = if settings_path.exists() {
            if let Ok(content) = fs::read_to_string(&settings_path) {
                if let Ok(s) = serde_json::from_str::<serde_json::Value>(&content) {
                    (
                        s["tunInet4CIDR"].as_str().unwrap_or("172.19.0.1/30").to_string(),
                        s["tunInet6CIDR"].as_str().unwrap_or("fdfe:dcba:9876::1/126").to_string(),
                        s["mtu"].as_u64().unwrap_or(1420) as u16,
                        s["primaryDns"].as_str().unwrap_or("1.1.1.1").to_string(),
                        s["secondaryDns"].as_str().unwrap_or("8.8.8.8").to_string(),
                    )
                } else {
                    ("172.19.0.1/30".into(), "fdfe:dcba:9876::1/126".into(), 1420, "1.1.1.1".into(), "8.8.8.8".into())
                }
            } else {
                ("172.19.0.1/30".into(), "fdfe:dcba:9876::1/126".into(), 1420, "1.1.1.1".into(), "8.8.8.8".into())
            }
        } else {
            ("172.19.0.1/30".into(), "fdfe:dcba:9876::1/126".into(), 1420, "1.1.1.1".into(), "8.8.8.8".into())
        };

        let psk_opt = if pre_shared_key.is_empty() { None } else { Some(pre_shared_key.as_str()) };

        let cfg = Config::mode_wireguard_tun_full(
            &server,
            port as u16,
            &private_key,
            &peer_public_key,
            psk_opt,
            local_addresses.clone(),
            None,
            Some(wg_mtu),
            &primary_dns,
            &secondary_dns,
        );
        serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?
    } else {
        // Proxy mode: mixed (SOCKS5 + HTTP) inbound + WireGuard outbound
        let (proxy_host, proxy_port) = local_proxy_from_settings(&read_settings(&app_data_dir));
        wg_proxy_listen = Some((proxy_host.clone(), proxy_port));

        let psk_opt = if pre_shared_key.is_empty() { None } else { Some(pre_shared_key.as_str()) };

        let cfg = Config::mode_wireguard_proxy(
            &server,
            port as u16,
            &private_key,
            &peer_public_key,
            psk_opt,
            local_addresses.clone(),
            &proxy_host,
            proxy_port,
            Some(wg_mtu),
        );
        serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?
    };

    // Write sing-box config
    let sb_config_path = app_data_dir.join("sing_box_config.json");
    fs::write(&sb_config_path, &sb_config).map_err(|e| e.to_string())?;
    let _ = append_log(&logs_path, "info", &format!(
        "WireGuard sing-box config written ({} bytes, mode={})", sb_config.len(), mode
    ));

    // Spawn sing-box
    let mut sb_cmd = Command::new(&sing_box_bin);
    sb_cmd
        .arg("run")
        .arg("-c")
        .arg(&sb_config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_sing_box_env(&mut sb_cmd);

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        sb_cmd.creation_flags(0x08000000);
    }

    let mut sb_child = sb_cmd.spawn().map_err(|e| {
        let msg = format!("CRITICAL: Failed to spawn sing-box for WireGuard: {}", e);
        let _ = append_log(&logs_path, "error", &msg);
        msg
    })?;

    let _ = append_log(&logs_path, "info", &format!(
        "WireGuard sing-box spawned (PID: {})", sb_child.id()
    ));

    let sb_stdout = sb_child.stdout.take().unwrap();
    let sb_stderr = sb_child.stderr.take().unwrap();

    let logs1 = logs_path.clone();
    thread::spawn(move || {
        let reader = BufReader::new(sb_stdout);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs1, "info", &format!("[WG/sing-box] {}", l));
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    let logs2 = logs_path.clone();
    thread::spawn(move || {
        let reader = BufReader::new(sb_stderr);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs2, "error", &format!("[WG/sing-box] {}", l));
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    // Health check
    thread::sleep(std::time::Duration::from_millis(700));
    match sb_child.try_wait() {
        Ok(Some(status)) => {
            let err_msg = format!("WireGuard sing-box exited immediately with {}", status);
            let _ = append_log(&logs_path, "error", &err_msg);
            use tauri::Emitter;
            let _ = app.emit("vpn-disconnected", ());
            return Err(err_msg);
        }
        Ok(None) => {
            let _ = append_log(&logs_path, "info", "WireGuard sing-box is running");
        }
        Err(e) => {
            let _ = append_log(&logs_path, "warn", &format!("Could not check WireGuard sing-box status: {}", e));
        }
    }

    // Watch process in background
    let app_h = app.clone();
    let logs_exit = logs_path.clone();
    thread::spawn(move || {
        let _ = sb_child.wait();
        let _ = append_log(&logs_exit, "warn", "WireGuard sing-box process exited");
        notify_engine_exit(&app_h, session);
    });

    if let Some((host, port)) = wg_proxy_listen {
        // The mixed inbound serves both HTTP and SOCKS5 on the same port
        apply_system_proxy(&app_data_dir, &mode, session, &host, Some(port), Some(port));
    }

    Ok(())
}

/// Start OpenVPN as a client using a .ovpn config string.
/// Writes the config to a temp file and spawns openvpn process.
#[tauri::command]
async fn start_openvpn(
    app: tauri::AppHandle,
    ovpn_config: String,
    username: String,
    password: String,
    mode: String,
) -> Result<(), String> {
    use std::process::{Command, Stdio};
    use std::io::{BufRead, BufReader, Write};
    use std::thread;

    let app_data_dir = app.path().app_data_dir().expect("Failed to get app dir");
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    let logs_path = app_data_dir.join("candy.logs");

    let session = begin_session(&app_data_dir);
    let _ = append_log(&logs_path, "info", &format!(
        "Starting OpenVPN client: user={}, mode={}", username, mode
    ));

    if ovpn_config.is_empty() {
        return Err("OpenVPN config is empty".to_string());
    }

    // Write .ovpn config file
    let ovpn_config_path = app_data_dir.join("client.ovpn");
    fs::write(&ovpn_config_path, &ovpn_config).map_err(|e| e.to_string())?;

    // Write auth file (username\npassword) for --auth-user-pass
    let auth_path = app_data_dir.join("openvpn_auth.txt");
    {
        let mut f = std::fs::File::create(&auth_path).map_err(|e| e.to_string())?;
        writeln!(f, "{}", username).map_err(|e| e.to_string())?;
        writeln!(f, "{}", password).map_err(|e| e.to_string())?;
    }

    let _ = append_log(&logs_path, "info", &format!(
        "OpenVPN config written to: {}", ovpn_config_path.display()
    ));

    // Resolve openvpn binary: bundled, PATH, then the default install location on Windows
    let openvpn_bin = resolve_binary(&resource_dir, if cfg!(target_os = "windows") { "openvpn/openvpn.exe" } else { "openvpn" })
        .or_else(|e| {
            #[cfg(target_os = "windows")]
            {
                for base in ["ProgramFiles", "ProgramFiles(x86)"] {
                    if let Ok(pf) = std::env::var(base) {
                        let p = std::path::Path::new(&pf).join("OpenVPN").join("bin").join("openvpn.exe");
                        if p.is_file() {
                            return Ok(p);
                        }
                    }
                }
            }
            #[cfg(target_os = "macos")]
            {
                for p in ["/opt/homebrew/sbin/openvpn", "/usr/local/sbin/openvpn"] {
                    if std::path::Path::new(p).is_file() {
                        return Ok(std::path::PathBuf::from(p));
                    }
                }
            }
            Err(e)
        })
        .map_err(|e| {
            let msg = format!("OpenVPN is not installed: {}", e);
            let _ = append_log(&logs_path, "error", &msg);
            msg
        })?;

    let _ = append_log(&logs_path, "info", &format!(
        "Using OpenVPN binary: {}", openvpn_bin.display()
    ));

    // OpenVPN needs root to create the TUN device on Linux/macOS. When not root, elevate
    // with pkexec (graphical prompt) on Linux, or non-interactive sudo elsewhere
    // (plain `sudo` would wait for a password on a terminal the GUI app doesn't have).
    #[cfg(not(target_os = "windows"))]
    let mut ovpn_cmd = {
        let is_root = unsafe { libc::geteuid() } == 0;
        let mut c = if is_root {
            Command::new(&openvpn_bin)
        } else if cfg!(target_os = "linux") && resolve_binary(&resource_dir, "pkexec").is_ok() {
            let mut c = Command::new("pkexec");
            c.arg(&openvpn_bin);
            c
        } else {
            let mut c = Command::new("sudo");
            c.arg("-n").arg(&openvpn_bin);
            c
        };
        c.arg("--config")
            .arg(&ovpn_config_path)
            .arg("--auth-user-pass")
            .arg(&auth_path)
            .arg("--auth-nocache")
            .arg("--verb")
            .arg("3")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    };

    #[cfg(target_os = "windows")]
    let mut ovpn_cmd = {
        let mut c = Command::new(&openvpn_bin);
        c.arg("--config")
            .arg(&ovpn_config_path)
            .arg("--auth-user-pass")
            .arg(&auth_path)
            .arg("--auth-nocache")
            .arg("--verb")
            .arg("3")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    };

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        ovpn_cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let mut ovpn_child = ovpn_cmd.spawn().map_err(|e| {
        let msg = format!("CRITICAL: Failed to spawn OpenVPN: {}. Is openvpn installed?", e);
        let _ = append_log(&logs_path, "error", &msg);
        msg
    })?;

    let _ = append_log(&logs_path, "info", &format!(
        "OpenVPN process spawned (PID: {})", ovpn_child.id()
    ));

    let ovpn_stdout = ovpn_child.stdout.take().unwrap();
    let ovpn_stderr = ovpn_child.stderr.take().unwrap();

    let logs1 = logs_path.clone();
    thread::spawn(move || {
        let reader = BufReader::new(ovpn_stdout);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs1, "info", &format!("[OpenVPN] {}", l));
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    let logs2 = logs_path.clone();
    thread::spawn(move || {
        let reader = BufReader::new(ovpn_stderr);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs2, "error", &format!("[OpenVPN] {}", l));
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    // Health check — openvpn takes a moment to establish connection
    thread::sleep(std::time::Duration::from_millis(1500));
    match ovpn_child.try_wait() {
        Ok(Some(status)) => {
            let err_msg = format!("OpenVPN exited immediately with {} — check logs for details", status);
            let _ = append_log(&logs_path, "error", &err_msg);
            use tauri::Emitter;
            let _ = app.emit("vpn-disconnected", ());
            return Err(err_msg);
        }
        Ok(None) => {
            let _ = append_log(&logs_path, "info", "OpenVPN process is running after health check");
        }
        Err(e) => {
            let _ = append_log(&logs_path, "warn", &format!("Could not check OpenVPN status: {}", e));
        }
    }

    // Watch OpenVPN exit in background
    let app_h = app.clone();
    let logs_exit = logs_path.clone();
    let auth_path_cleanup = auth_path.clone();
    thread::spawn(move || {
        let _ = ovpn_child.wait();
        let _ = append_log(&logs_exit, "warn", "OpenVPN process exited");
        // Clean up auth file for security
        let _ = fs::remove_file(&auth_path_cleanup);
        notify_engine_exit(&app_h, session);
    });

    Ok(())
}

/// Resolve the DNSTT resolver setting string into command-line arguments for dnstt-client.
/// Returns (flag, address) e.g. ("-udp", "8.8.8.8:53") or ("-doh", "https://dns.google/dns-query").
fn resolve_dnstt_resolver(resolver: &str) -> (&'static str, &'static str) {
    match resolver {
        // UDP resolvers
        "udp-google"     => ("-udp", "8.8.8.8:53"),
        "udp-cloudflare" => ("-udp", "1.1.1.1:53"),
        "udp-quad9"      => ("-udp", "9.9.9.9:53"),
        "udp-opendns"    => ("-udp", "208.67.222.222:53"),
        // DoT resolvers
        "dot-google"     => ("-dot", "dns.google:853"),
        "dot-cloudflare" => ("-dot", "cloudflare-dns.com:853"),
        "dot-quad9"      => ("-dot", "dns.quad9.net:853"),
        // DoH resolvers
        "doh-google"     => ("-doh", "https://dns.google/dns-query"),
        "doh-cloudflare" => ("-doh", "https://cloudflare-dns.com/dns-query"),
        "doh-quad9"      => ("-doh", "https://dns.quad9.net/dns-query"),
        // Auto / fallback: use UDP with system-friendly Google DNS
        _ => ("-udp", "8.8.8.8:53"),
    }
}

/// Plain-UDP resolver address for tunnels that only speak UDP DNS (SlipStream).
fn udp_resolver_for(resolver: &str) -> &'static str {
    match resolve_dnstt_resolver(resolver) {
        ("-udp", addr) => addr,
        _ => match resolver {
            r if r.ends_with("cloudflare") => "1.1.1.1:53",
            r if r.ends_with("quad9") => "9.9.9.9:53",
            _ => "8.8.8.8:53",
        },
    }
}

/// Log every line of a child's stdout/stderr to candy.logs with a tag.
fn spawn_log_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    logs_path: std::path::PathBuf,
    level: &'static str,
    tag: String,
) -> std::thread::JoinHandle<()> {
    use std::io::{BufRead, BufReader};
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs_path, level, &format!("{} {}", tag, l));
                }
                Err(_) => break,
                _ => {}
            }
        }
    })
}

/// DNSTT: `dnstt-client` forwards a local TCP port through DNS to the server, which connects
/// it to its SSH server (tunnel_mode "ssh") or to a dante SOCKS5 server (tunnel_mode "socks").
/// On top of it the built-in local proxy (SOCKS5 + HTTP on proxy_host:proxy_port) forwards
/// connections over SSH direct-tcpip channels or the remote SOCKS5 server.
#[tauri::command]
async fn start_dnstt(
    app: tauri::AppHandle,
    domain: String,
    public_key: String,
    resolver: String,
    mode: String,
    proxy_host: String,
    proxy_port: u64,
    server_ip: String,
    ssh_user: String,
    ssh_pass: String,
    tunnel_mode: Option<String>,
) -> Result<(), String> {
    let app_data_dir = app.path().app_data_dir().map_err(|e| format!("Failed to get app dir: {}", e))?;
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    let logs_path = app_data_dir.join("candy.logs");
    let session = begin_session(&app_data_dir);

    let dnstt_bin = resolve_binary(&resource_dir, if cfg!(target_os = "windows") { "dnstt-client.exe" } else { "dnstt-client" })
        .map_err(|e| {
            let msg = format!("dnstt-client not available: {}", e);
            let _ = append_log(&logs_path, "error", &msg);
            msg
        })?;

    let proxy_port = u16::try_from(proxy_port).ok().filter(|p| *p > 0).ok_or("Invalid local proxy port")?;
    let tunnel_port = if proxy_port < 65535 { proxy_port + 1 } else { proxy_port - 1 };
    let (resolver_flag, resolver_addr) = resolve_dnstt_resolver(&resolver);
    let socks_mode = tunnel_mode.as_deref().map_or(false, |m| m.eq_ignore_ascii_case("socks"));
    let _ = append_log(&logs_path, "info", &format!(
        "Starting DNSTT client: {} (resolver {} {}, tunnel mode {})",
        dnstt_bin.display(), resolver_flag, resolver_addr, if socks_mode { "socks" } else { "ssh" }
    ));

    // dnstt-client -udp <resolver> -pubkey <hex> <domain> 127.0.0.1:<port>
    let args = vec![
        resolver_flag.to_string(),
        resolver_addr.to_string(),
        "-pubkey".to_string(),
        public_key,
        domain,
        format!("127.0.0.1:{}", tunnel_port),
    ];
    run_dns_tunnel(
        app, session, "DNSTT", dnstt_bin, args, tunnel_port, socks_mode,
        mode, proxy_host, proxy_port, server_ip, ssh_user, ssh_pass,
    )
    .await
}

/// SlipStream (DNS tunnel over QUIC): `slipstream-client` forwards a local TCP port to the
/// server's SSH; the built-in SSH local proxy runs on top, exactly like DNSTT's SSH mode.
#[tauri::command]
async fn start_slipstream(
    app: tauri::AppHandle,
    domain: String,
    resolver: String,
    congestion_control: Option<String>,
    mode: String,
    proxy_host: String,
    proxy_port: u64,
    server_ip: String,
    ssh_user: String,
    ssh_pass: String,
) -> Result<(), String> {
    let app_data_dir = app.path().app_data_dir().map_err(|e| format!("Failed to get app dir: {}", e))?;
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    let logs_path = app_data_dir.join("candy.logs");
    let session = begin_session(&app_data_dir);

    let bin_name = if cfg!(target_os = "windows") { "slipstream-client.exe" } else { "slipstream-client" };
    let slip_bin = resolve_binary(&resource_dir, bin_name)
        .or_else(|_| resolve_binary(&resource_dir, &format!("slipstream/{}", bin_name)))
        .map_err(|e| {
            let msg = if cfg!(target_os = "linux") {
                format!("slipstream-client not available: {}", e)
            } else {
                format!(
                    "SlipStream client is only available on Linux (no official build for this OS). \
                     Build slipstream-client from https://github.com/EndPositive/slipstream and place it next to the app or on PATH. ({})",
                    e
                )
            };
            let _ = append_log(&logs_path, "error", &msg);
            msg
        })?;

    let proxy_port = u16::try_from(proxy_port).ok().filter(|p| *p > 0).ok_or("Invalid local proxy port")?;
    let tunnel_port = if proxy_port < 65535 { proxy_port + 1 } else { proxy_port - 1 };
    let resolver_addr = udp_resolver_for(&resolver);
    if !resolver.starts_with("udp-") && resolver != "auto" {
        let _ = append_log(&logs_path, "warn", &format!("SlipStream only supports plain UDP resolvers — using {} instead of '{}'", resolver_addr, resolver));
    }
    let cc = congestion_control.filter(|c| !c.trim().is_empty()).unwrap_or_else(|| "bbr".to_string());
    let _ = append_log(&logs_path, "info", &format!(
        "Starting SlipStream client: {} (resolver {}, congestion control {})", slip_bin.display(), resolver_addr, cc
    ));

    let args = vec![
        format!("--congestion-control={}", cc),
        format!("--tcp-listen-port={}", tunnel_port),
        format!("--resolver={}", resolver_addr),
        format!("--domain={}", domain),
    ];
    run_dns_tunnel(
        app, session, "SlipStream", slip_bin, args, tunnel_port, false,
        mode, proxy_host, proxy_port, server_ip, ssh_user, ssh_pass,
    )
    .await
}

/// Shared DNS tunnel pipeline:
/// tunnel client (local TCP port) -> built-in local proxy (SSH or SOCKS5 upstream)
/// -> [sing-box TUN in tun mode | OS system proxy in proxy mode].
#[allow(clippy::too_many_arguments)]
async fn run_dns_tunnel(
    app: tauri::AppHandle,
    session: u64,
    label: &'static str,
    tunnel_bin: std::path::PathBuf,
    tunnel_args: Vec<String>,
    tunnel_port: u16,
    upstream_is_socks: bool,
    mode: String,
    proxy_host: String,
    proxy_port: u16,
    server_ip: String,
    ssh_user: String,
    ssh_pass: String,
) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let app_data_dir = app.path().app_data_dir().map_err(|e| format!("Failed to get app dir: {}", e))?;
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    let logs_path = app_data_dir.join("candy.logs");
    let tag = format!("[{}]", label);

    if !upstream_is_socks && (ssh_user.is_empty() || ssh_pass.is_empty()) {
        let msg = format!("{} config is missing the SSH credentials (ssh_username / ssh_password)", label);
        let _ = append_log(&logs_path, "error", &msg);
        return Err(msg);
    }
    let sing_box_bin = if mode == "tun" {
        Some(resolve_binary(&resource_dir, if cfg!(target_os = "windows") { "sing-box/sing-box.exe" } else { "sing-box/sing-box" })
            .map_err(|e| {
                let msg = format!("Sing-box (required for TUN mode) not available: {}", e);
                let _ = append_log(&logs_path, "error", &msg);
                msg
            })?)
    } else {
        None
    };
    // A wildcard listen address is fine for the proxy but not as a dial target
    let local_dial_host = if proxy_host.is_empty() || proxy_host == "0.0.0.0" || proxy_host == "::" {
        "127.0.0.1".to_string()
    } else {
        proxy_host.clone()
    };

    // 1. Tunnel client
    let mut cmd = Command::new(&tunnel_bin);
    cmd.args(&tunnel_args).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().map_err(|e| {
        let msg = format!("CRITICAL: Failed to spawn {} client: {}", label, e);
        let _ = append_log(&logs_path, "error", &msg);
        msg
    })?;
    let tunnel_pid = child.id();
    let _ = append_log(&logs_path, "info", &format!("{} client spawned (PID: {}), local tunnel port 127.0.0.1:{}", label, tunnel_pid, tunnel_port));
    let out_t = spawn_log_reader(child.stdout.take().unwrap(), logs_path.clone(), "info", tag.clone());
    let err_t = spawn_log_reader(child.stderr.take().unwrap(), logs_path.clone(), "info", tag.clone());

    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    if let Ok(Some(status)) = child.try_wait() {
        let _ = out_t.join();
        let _ = err_t.join();
        let msg = format!("{} client exited immediately with {}", label, status);
        let _ = append_log(&logs_path, "error", &msg);
        return Err(msg);
    }

    let sing_box_pid: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));

    // Tunnel client watcher: tear everything down when it exits
    {
        let app_h = app.clone();
        let logs = logs_path.clone();
        let sb_pid = Arc::clone(&sing_box_pid);
        std::thread::spawn(move || {
            let status = child.wait();
            let _ = out_t.join();
            let _ = err_t.join();
            let _ = append_log(&logs, "warn", &format!("{} client exited ({})",
                label, status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string())));
            if is_current_session(session) {
                stop_local_proxy(Some(session));
                if let Some(pid) = *sb_pid.lock().unwrap() {
                    kill_process(pid);
                }
            }
            notify_engine_exit(&app_h, session);
        });
    }

    // 2. Built-in local proxy (SOCKS5 + HTTP) on top of the tunnel
    let tunnel_addr = std::net::SocketAddr::from(([127, 0, 0, 1], tunnel_port));
    let upstream = if upstream_is_socks {
        local_proxy::Upstream::Socks5 { server: tunnel_addr }
    } else {
        local_proxy::Upstream::Ssh { server: tunnel_addr, user: ssh_user, password: ssh_pass }
    };
    let on_exit: Box<dyn FnOnce(String) + Send> = {
        let app_h = app.clone();
        let logs = logs_path.clone();
        let sb_pid = Arc::clone(&sing_box_pid);
        Box::new(move |reason: String| {
            if is_current_session(session) {
                let _ = append_log(&logs, "warn", &format!("{} local proxy ended ({}) — stopping the tunnel", label, reason));
                kill_process(tunnel_pid);
                if let Some(pid) = *sb_pid.lock().unwrap() {
                    kill_process(pid);
                }
            }
            notify_engine_exit(&app_h, session);
        })
    };
    let _ = append_log(&logs_path, "info", &format!("Starting local proxy on {}:{} (SOCKS5 + HTTP)", proxy_host, proxy_port));
    let handle = match local_proxy::start(&proxy_host, proxy_port, upstream, Some(logs_path.clone()), on_exit).await {
        Ok(h) => h,
        Err(e) => {
            let msg = format!("{} tunnel failed: {}", label, e);
            let _ = append_log(&logs_path, "error", &msg);
            kill_process(tunnel_pid);
            return Err(msg);
        }
    };
    if !is_current_session(session) {
        // Disconnected (or another connection started) while we were logging in
        handle.stop();
        kill_process(tunnel_pid);
        return Err(format!("{} connection was cancelled", label));
    }
    *local_proxy_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some((session, handle));
    let _ = append_log(&logs_path, "info", &format!("{} tunnel is up — local proxy {}:{}", label, proxy_host, proxy_port));

    // 3. TUN mode: sing-box routes everything into the local SOCKS proxy
    if let Some(sing_box_bin) = sing_box_bin {
        let fail = |msg: String| -> Result<(), String> {
            let _ = append_log(&logs_path, "error", &msg);
            stop_local_proxy(Some(session));
            kill_process(tunnel_pid);
            Err(msg)
        };
        // SSH/SOCKS upstreams carry TCP only, so sing-box must resolve DNS over TCP
        let sb_config = match build_tun_socks_config(&app_data_dir, &server_ip, Some((&local_dial_host, proxy_port)), true) {
            Ok(c) => c,
            Err(e) => return fail(format!("Failed to build sing-box TUN config: {}", e)),
        };
        let sb_config_path = app_data_dir.join("sing_box_config.json");
        if let Err(e) = fs::write(&sb_config_path, &sb_config) {
            return fail(e.to_string());
        }
        let mut sb_cmd = Command::new(&sing_box_bin);
        sb_cmd.arg("run").arg("-c").arg(&sb_config_path).stdout(Stdio::piped()).stderr(Stdio::piped());
        apply_sing_box_env(&mut sb_cmd);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            sb_cmd.creation_flags(0x08000000);
        }
        let mut sb_child = match sb_cmd.spawn() {
            Ok(c) => c,
            Err(e) => return fail(format!("CRITICAL: Failed to spawn Sing-box for {} TUN: {}", label, e)),
        };
        let sb_tag = format!("[Sing-box/{}]", label);
        let sb_out = spawn_log_reader(sb_child.stdout.take().unwrap(), logs_path.clone(), "info", sb_tag.clone());
        let sb_err = spawn_log_reader(sb_child.stderr.take().unwrap(), logs_path.clone(), "error", sb_tag);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if let Ok(Some(status)) = sb_child.try_wait() {
            let _ = sb_out.join();
            let _ = sb_err.join();
            return fail(format!("Sing-box ({} TUN) exited immediately with {}", label, status));
        }
        *sing_box_pid.lock().unwrap() = Some(sb_child.id());
        let _ = append_log(&logs_path, "info", &format!("Sing-box TUN running (PID: {}) for {}", sb_child.id(), label));

        let app_h = app.clone();
        let logs = logs_path.clone();
        std::thread::spawn(move || {
            let status = sb_child.wait();
            let _ = sb_out.join();
            let _ = sb_err.join();
            let _ = append_log(&logs, "warn", &format!("Sing-box ({} TUN) exited ({})",
                label, status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string())));
            if is_current_session(session) {
                stop_local_proxy(Some(session));
                kill_process(tunnel_pid);
            }
            notify_engine_exit(&app_h, session);
        });
    } else {
        apply_system_proxy(&app_data_dir, &mode, session, &local_dial_host, Some(proxy_port), Some(proxy_port));
    }

    let _ = append_log(&logs_path, "info", &format!("{} connection established in {} mode", label, mode));
    Ok(())
}

/* ───────────────────────────── TrustTunnel ───────────────────────────── */

/// Prefix of the error returned when the TrustTunnel CLI client is not available; the UI
/// then falls back to handing the tt:// link to the TrustTunnel app.
const TRUSTTUNNEL_MISSING: &str = "TRUSTTUNNEL_CLIENT_MISSING";

fn find_file_recursive(dir: &std::path::Path, name: &str, depth: usize) -> Option<std::path::PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            subdirs.push(p);
        } else if p.file_name().map_or(false, |f| f.eq_ignore_ascii_case(name)) {
            return Some(p);
        }
    }
    if depth == 0 {
        return None;
    }
    subdirs.into_iter().find_map(|d| find_file_recursive(&d, name, depth - 1))
}

/// Locate a TrustTunnel binary: anywhere inside a bundled `trusttunnel/` dir (the archive
/// layout is not fixed), then the usual resolve_binary locations / PATH.
fn resolve_trusttunnel_binary(resource_dir: &std::path::Path, base: &str) -> Option<std::path::PathBuf> {
    let name = if cfg!(target_os = "windows") { format!("{}.exe", base) } else { base.to_string() };
    let mut roots = vec![resource_dir.join("trusttunnel"), resource_dir.join("resources").join("trusttunnel")];
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())) {
        roots.push(dir.join("trusttunnel"));
        roots.push(dir.join("resources").join("trusttunnel"));
    }
    for root in roots {
        if let Some(found) = find_file_recursive(&root, &name, 4) {
            // resolve_binary restores a lost executable bit on Unix
            return resolve_binary(resource_dir, &found.to_string_lossy()).ok().or(Some(found));
        }
    }
    resolve_binary(resource_dir, &format!("trusttunnel/{}", name)).ok()
}

/// TrustTunnel: write the endpoint config, generate the client settings with
/// `setup_wizard --mode non-interactive` and run `trusttunnel_client -c <settings>`
/// (it creates its own TUN device, so it needs administrator/root rights).
#[tauri::command]
async fn start_trusttunnel(app: tauri::AppHandle, endpoint_config: String, mode: String) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let app_data_dir = app.path().app_data_dir().map_err(|e| format!("Failed to get app dir: {}", e))?;
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    let logs_path = app_data_dir.join("candy.logs");
    let session = begin_session(&app_data_dir);

    let client_bin = match resolve_trusttunnel_binary(&resource_dir, "trusttunnel_client") {
        Some(b) => b,
        None => {
            let _ = append_log(&logs_path, "warn", "TrustTunnel: trusttunnel_client was not found next to the app or on PATH");
            return Err(format!("{}: the TrustTunnel client is not installed", TRUSTTUNNEL_MISSING));
        }
    };
    if endpoint_config.trim().is_empty() {
        return Err("TrustTunnel endpoint configuration is empty — ask the admin to check the TrustTunnel endpoint on the server".into());
    }
    if mode == "proxy" {
        let _ = append_log(&logs_path, "info", "TrustTunnel always runs as a system-wide TUN tunnel (proxy mode does not apply)");
    }

    let endpoint_path = app_data_dir.join("trusttunnel_endpoint.toml");
    let settings_path = app_data_dir.join("trusttunnel_client.toml");
    fs::write(&endpoint_path, &endpoint_config).map_err(|e| format!("Failed to write the TrustTunnel endpoint config: {}", e))?;

    // 1. Generate the client settings
    match resolve_trusttunnel_binary(&resource_dir, "setup_wizard") {
        Some(wizard) => {
            let _ = append_log(&logs_path, "info", &format!("TrustTunnel: generating client settings with {}", wizard.display()));
            let mut cmd = Command::new(&wizard);
            cmd.arg("--mode").arg("non-interactive")
                .arg("--endpoint_config").arg(&endpoint_path)
                .arg("--settings").arg(&settings_path);
            if let Some(dir) = wizard.parent() {
                cmd.current_dir(dir);
            }
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x08000000);
            }
            let out = cmd.output().map_err(|e| format!("Failed to run the TrustTunnel setup_wizard: {}", e))?;
            for line in String::from_utf8_lossy(&out.stdout).lines().chain(String::from_utf8_lossy(&out.stderr).lines()) {
                if !line.trim().is_empty() {
                    let _ = append_log(&logs_path, "info", &format!("[TrustTunnel setup] {}", line));
                }
            }
            if !out.status.success() || !settings_path.is_file() {
                let msg = format!("TrustTunnel setup_wizard failed ({}) — see the logs", out.status);
                let _ = append_log(&logs_path, "error", &msg);
                return Err(msg);
            }
        }
        None if settings_path.is_file() => {
            let _ = append_log(&logs_path, "warn", "TrustTunnel: setup_wizard not found — reusing the previously generated client settings");
        }
        None => {
            let msg = "TrustTunnel setup_wizard was not found next to trusttunnel_client — cannot generate the client settings".to_string();
            let _ = append_log(&logs_path, "error", &msg);
            return Err(msg);
        }
    }

    // 2. Run the client (elevated like OpenVPN when not root on Linux/macOS)
    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let is_root = unsafe { libc::geteuid() } == 0;
        if is_root {
            Command::new(&client_bin)
        } else if cfg!(target_os = "linux") && resolve_binary(&resource_dir, "pkexec").is_ok() {
            let mut c = Command::new("pkexec");
            c.arg(&client_bin);
            c
        } else {
            let mut c = Command::new("sudo");
            c.arg("-n").arg(&client_bin);
            c
        }
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new(&client_bin);
        c.creation_flags(0x08000000);
        c
    };
    cmd.arg("-c").arg(&settings_path).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(dir) = client_bin.parent() {
        cmd.current_dir(dir);
    }
    let _ = append_log(&logs_path, "info", &format!("Starting TrustTunnel client: {}", client_bin.display()));
    let mut child = cmd.spawn().map_err(|e| {
        let msg = format!("CRITICAL: Failed to spawn the TrustTunnel client: {}", e);
        let _ = append_log(&logs_path, "error", &msg);
        msg
    })?;
    let _ = append_log(&logs_path, "info", &format!("TrustTunnel client spawned (PID: {})", child.id()));
    let out_t = spawn_log_reader(child.stdout.take().unwrap(), logs_path.clone(), "info", "[TrustTunnel]".into());
    let err_t = spawn_log_reader(child.stderr.take().unwrap(), logs_path.clone(), "info", "[TrustTunnel]".into());

    tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
    if let Ok(Some(status)) = child.try_wait() {
        let _ = out_t.join();
        let _ = err_t.join();
        let hint = if cfg!(target_os = "windows") { " (it needs administrator rights — restart CandyConnect as administrator)" } else { "" };
        let msg = format!("TrustTunnel client exited immediately with {}{} — see the logs", status, hint);
        let _ = append_log(&logs_path, "error", &msg);
        return Err(msg);
    }

    let app_h = app.clone();
    let logs = logs_path.clone();
    std::thread::spawn(move || {
        let status = child.wait();
        let _ = out_t.join();
        let _ = err_t.join();
        let _ = append_log(&logs, "warn", &format!("TrustTunnel client exited ({})",
            status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string())));
        notify_engine_exit(&app_h, session);
    });
    Ok(())
}

/* ───────────────────────────── IKEv2 helpers ───────────────────────────── */

/// Write the server's CA (PEM) to the app data dir; returns its path.
fn write_ikev2_ca(app_data_dir: &std::path::Path, ca_cert: &str) -> Option<std::path::PathBuf> {
    let pem = ca_cert.trim();
    if !pem.contains("-----BEGIN CERTIFICATE-----") {
        return None;
    }
    let path = app_data_dir.join("ikev2_ca.pem");
    fs::write(&path, format!("{}\n", pem)).ok()?;
    Some(path)
}

/// Single-quote a string for PowerShell.
#[cfg(target_os = "windows")]
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Run a PowerShell script; returns (success, combined output).
#[cfg(target_os = "windows")]
fn run_powershell(script: &str) -> (bool, String) {
    use std::os::windows::process::CommandExt;
    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .creation_flags(0x08000000)
        .output()
    {
        Ok(o) => {
            let mut out = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if !err.is_empty() {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(&err);
            }
            (o.status.success(), out)
        }
        Err(e) => (false, e.to_string()),
    }
}

/// Trust the server CA and create the IKEv2 (EAP-MSCHAPv2) phonebook entry.
#[cfg(target_os = "windows")]
fn windows_prepare_ikev2(
    conn_name: &str,
    server: &str,
    ca_path: Option<&std::path::Path>,
    logs_path: &std::path::Path,
) -> Result<(), String> {
    // 1. Trust the server CA. The IKEEXT service validates the server certificate against the
    //    machine store, so LocalMachine\Root (needs admin) is what actually makes IKEv2 work.
    match ca_path {
        Some(ca) => {
            let ca_q = ps_quote(&ca.display().to_string());
            let (ok, out) = run_powershell(&format!(
                "$ErrorActionPreference='Stop'; Import-Certificate -FilePath {} -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null",
                ca_q
            ));
            if ok {
                let _ = append_log(logs_path, "info", "IKEv2: server CA imported into Cert:\\LocalMachine\\Root");
            } else {
                let _ = append_log(logs_path, "warn", &format!(
                    "IKEv2: could not import the CA into Cert:\\LocalMachine\\Root (not running as administrator?): {} — falling back to Cert:\\CurrentUser\\Root",
                    out
                ));
                let (ok, out) = run_powershell(&format!(
                    "$ErrorActionPreference='Stop'; Import-Certificate -FilePath {} -CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null",
                    ca_q
                ));
                if ok {
                    let _ = append_log(logs_path, "warn",
                        "IKEv2: CA imported into Cert:\\CurrentUser\\Root only. Windows' IKEv2 service may still reject the server certificate (error 13801) — restart CandyConnect as administrator if the connection fails.");
                } else {
                    let _ = append_log(logs_path, "error", &format!("IKEv2: could not import the server CA: {}", out));
                }
            }
        }
        None => {
            let _ = append_log(logs_path, "warn", "IKEv2: the server did not provide its CA certificate — Windows will only connect if the CA is already trusted");
        }
    }

    // 2. Phonebook entry. EAP-MSCHAPv2 is the default EAP method Add-VpnConnection uses for IKEv2.
    //    The IPsec proposal must be one the server accepts (aes256-sha256-modp2048 / aes256-sha256).
    let n = ps_quote(conn_name);
    let (ok, out) = run_powershell(&format!(
        "$ErrorActionPreference='Stop'; \
         Add-VpnConnection -Name {n} -ServerAddress {s} -TunnelType Ikev2 -AuthenticationMethod Eap -EncryptionLevel Required -RememberCredential -Force; \
         Set-VpnConnectionIPsecConfiguration -ConnectionName {n} -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -PfsGroup None -Force",
        n = n,
        s = ps_quote(server)
    ));
    if !ok {
        return Err(format!("Failed to create the IKEv2 VPN profile: {}", out));
    }
    let _ = append_log(logs_path, "info", &format!("IKEv2: VPN profile '{}' created (EAP-MSCHAPv2, AES256/SHA256/DH14)", conn_name));
    Ok(())
}

/// Explain the common rasdial / RAS error codes.
#[cfg(target_os = "windows")]
fn rasdial_hint(output: &str) -> &'static str {
    if output.contains("13801") {
        " — the server certificate is not trusted by Windows (restart CandyConnect as administrator so the server CA can be installed in the machine store)"
    } else if output.contains("13806") || output.contains("13809") {
        " — Windows could not validate the server certificate chain (restart CandyConnect as administrator so the CA can be installed)"
    } else if output.contains("13868") || output.contains("13843") {
        " — IPsec policy mismatch between client and server"
    } else if output.contains("691") {
        " — wrong username or password"
    } else if output.contains("809") {
        " — IKE/IPsec traffic (UDP 500/4500) was blocked; check the firewall or NAT"
    } else if output.contains("868") {
        " — the server address could not be resolved"
    } else {
        ""
    }
}

/// Linux IKEv2: NetworkManager strongSwan plugin, falling back to strongSwan's charon-cmd.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn linux_connect_ikev2(
    app: &tauri::AppHandle,
    session: u64,
    resource_dir: &std::path::Path,
    app_data_dir: &std::path::Path,
    conn_name: &str,
    server: &str,
    username: &str,
    password: &str,
    ca_path: Option<&std::path::Path>,
    remote_id: &str,
) -> Result<(), String> {
    use std::process::{Command, Stdio};
    let logs_path = app_data_dir.join("candy.logs");
    let mut nm_error: Option<String> = None;

    // ── 1. NetworkManager + strongSwan plugin ──
    if Command::new("nmcli").arg("--version").output().is_ok() {
        let _ = Command::new("nmcli").args(["connection", "delete", conn_name]).output();
        let esc = |v: &str| v.replace('\\', "\\\\").replace(',', "\\,");
        let mut data = vec![
            format!("address={}", esc(server)),
            "method=eap".to_string(),
            format!("user={}", esc(username)),
            "virtual=yes".to_string(),
            "encap=yes".to_string(),
            "ipcomp=no".to_string(),
            "proposal=yes".to_string(),
            "ike=aes256-sha256-modp2048".to_string(),
            "esp=aes256-sha256".to_string(),
            // secret is not stored; it is handed over at activation via passwd-file
            "password-flags=2".to_string(),
        ];
        if let Some(ca) = ca_path {
            data.push(format!("certificate={}", esc(&ca.display().to_string())));
        }
        if !remote_id.is_empty() {
            data.push(format!("remote-identity={}", esc(remote_id)));
        }
        let add = Command::new("nmcli")
            .args(["connection", "add", "con-name", conn_name, "type", "vpn", "vpn-type", "strongswan", "vpn.data"])
            .arg(data.join(", "))
            .output();
        match add {
            Ok(o) if o.status.success() => {
                let pw_file = app_data_dir.join("ikev2_nm_secrets");
                let _ = fs::write(&pw_file, format!("vpn.secrets.password:{}\n", password));
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&pw_file, fs::Permissions::from_mode(0o600));
                }
                let up = Command::new("nmcli")
                    .args(["--wait", "60", "connection", "up", "id", conn_name, "passwd-file"])
                    .arg(&pw_file)
                    .output();
                let _ = fs::remove_file(&pw_file);
                match up {
                    Ok(o) if o.status.success() => {
                        let _ = append_log(&logs_path, "info", "IKEv2 connected via NetworkManager (strongSwan)");
                        let app_h = app.clone();
                        let logs_p = logs_path.clone();
                        let name = conn_name.to_string();
                        std::thread::spawn(move || loop {
                            std::thread::sleep(std::time::Duration::from_secs(3));
                            if !is_current_session(session) {
                                break;
                            }
                            if let Ok(o) = Command::new("nmcli").args(["-t", "-f", "NAME", "connection", "show", "--active"]).output() {
                                if !String::from_utf8_lossy(&o.stdout).lines().any(|l| l == name) {
                                    let _ = append_log(&logs_p, "warn", &format!("{} connection dropped", name));
                                    notify_engine_exit(&app_h, session);
                                    break;
                                }
                            }
                        });
                        return Ok(());
                    }
                    Ok(o) => {
                        nm_error = Some(format!("{} {}", String::from_utf8_lossy(&o.stdout).trim(), String::from_utf8_lossy(&o.stderr).trim()));
                    }
                    Err(e) => nm_error = Some(e.to_string()),
                }
                let _ = Command::new("nmcli").args(["connection", "delete", conn_name]).output();
            }
            Ok(o) => {
                nm_error = Some(format!(
                    "{} (is the NetworkManager strongSwan plugin installed? package network-manager-strongswan / NetworkManager-strongswan)",
                    String::from_utf8_lossy(&o.stderr).trim()
                ));
            }
            Err(e) => nm_error = Some(e.to_string()),
        }
        let _ = append_log(&logs_path, "warn", &format!("IKEv2 via NetworkManager failed: {}", nm_error.clone().unwrap_or_default()));
    }

    // ── 2. strongSwan charon-cmd ──
    let charon = resolve_binary(resource_dir, "charon-cmd").or_else(|e| {
        ["/usr/sbin/charon-cmd", "/usr/bin/charon-cmd", "/usr/local/sbin/charon-cmd"]
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.is_file())
            .ok_or(e)
    });
    let charon = match charon {
        Ok(c) => c,
        Err(_) => {
            return Err(match nm_error {
                Some(e) => format!("IKEv2 connection failed via NetworkManager: {}. strongSwan's charon-cmd is not installed either (package charon-cmd).", e),
                None => "IKEv2 on Linux needs NetworkManager with the strongSwan plugin (network-manager-strongswan / NetworkManager-strongswan) or strongSwan's charon-cmd (package charon-cmd).".to_string(),
            });
        }
    };
    let _ = append_log(&logs_path, "info", &format!("IKEv2: using charon-cmd ({})", charon.display()));

    let is_root = unsafe { libc::geteuid() } == 0;
    let mut cmd = if is_root {
        Command::new(&charon)
    } else if resolve_binary(resource_dir, "pkexec").is_ok() {
        let mut c = Command::new("pkexec");
        c.arg(&charon);
        c
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg(&charon);
        c
    };
    cmd.args(["--host", server, "--identity", username, "--profile", "ikev2-eap"]);
    if !remote_id.is_empty() {
        cmd.args(["--remote-identity", remote_id]);
    }
    if let Some(ca) = ca_path {
        cmd.arg("--cert").arg(ca);
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("Failed to start charon-cmd: {}", e))?;
    // charon-cmd asks for the EAP password with getpass(), which reads stdin without a TTY
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = writeln!(stdin, "{}", password);
    }
    let established = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for (stream, level) in [
        (child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>), "info"),
        (child.stderr.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>), "info"),
    ] {
        if let Some(stream) = stream {
            let logs_p = logs_path.clone();
            let est = Arc::clone(&established);
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader};
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    if line.contains("CHILD_SA") && line.contains("established") {
                        est.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    if !line.trim().is_empty() {
                        let _ = append_log(&logs_p, level, &format!("[charon-cmd] {}", line));
                    }
                }
            });
        }
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        if established.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("charon-cmd exited with {} before the IKEv2 tunnel was up — see the logs", status));
        }
        if std::time::Instant::now() > deadline {
            kill_process(child.id());
            return Err("IKEv2 (charon-cmd) did not establish a tunnel within 45s — see the logs".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    let _ = append_log(&logs_path, "info", "IKEv2 connected via charon-cmd");
    let app_h = app.clone();
    let logs_p = logs_path.clone();
    std::thread::spawn(move || {
        let status = child.wait();
        let _ = append_log(&logs_p, "warn", &format!("charon-cmd exited ({})", status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string())));
        notify_engine_exit(&app_h, session);
    });
    Ok(())
}

#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// Random-looking UUID (v4 layout) without an extra crate.
#[cfg(target_os = "macos")]
fn pseudo_uuid() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let mut parts = [0u64; 2];
    for (i, p) in parts.iter_mut().enumerate() {
        let mut h = RandomState::new().build_hasher();
        h.write_u128(nanos);
        h.write_usize(i);
        *p = h.finish();
    }
    let b: Vec<u8> = parts.iter().flat_map(|p| p.to_be_bytes()).collect();
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-4{:01X}{:02X}-{:01X}{:01X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6] & 0x0F, b[7], 8 | (b[8] & 0x3), b[8] >> 4, b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Build a .mobileconfig with the server CA (com.apple.security.root) and an IKEv2
/// EAP-MSCHAPv2 VPN payload.
#[cfg(target_os = "macos")]
fn macos_ikev2_profile(conn_name: &str, server: &str, remote_id: &str, username: &str, password: &str, ca_pem: Option<&str>) -> String {
    let ca_payload = ca_pem
        .map(|pem| {
            let b64: String = pem
                .lines()
                .skip_while(|l| !l.contains("BEGIN CERTIFICATE"))
                .skip(1)
                .take_while(|l| !l.contains("END CERTIFICATE"))
                .map(|l| l.trim())
                .collect();
            format!(
                r#"        <dict>
            <key>PayloadType</key><string>com.apple.security.root</string>
            <key>PayloadIdentifier</key><string>com.candyconnect.ikev2.ca</string>
            <key>PayloadUUID</key><string>{uuid}</string>
            <key>PayloadVersion</key><integer>1</integer>
            <key>PayloadDisplayName</key><string>CandyConnect VPN CA</string>
            <key>PayloadCertificateFileName</key><string>candyconnect-ca.cer</string>
            <key>PayloadContent</key><data>{b64}</data>
        </dict>
"#,
                uuid = pseudo_uuid(),
                b64 = b64
            )
        })
        .unwrap_or_default();
    let sa = r#"<dict>
                    <key>EncryptionAlgorithm</key><string>AES-256</string>
                    <key>IntegrityAlgorithm</key><string>SHA2-256</string>
                    <key>DiffieHellmanGroup</key><integer>14</integer>
                    <key>LifeTimeInMinutes</key><integer>1440</integer>
                </dict>"#;
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
{ca}        <dict>
            <key>PayloadType</key><string>com.apple.vpn.managed</string>
            <key>PayloadIdentifier</key><string>com.candyconnect.ikev2.vpn</string>
            <key>PayloadUUID</key><string>{vpn_uuid}</string>
            <key>PayloadVersion</key><integer>1</integer>
            <key>PayloadDisplayName</key><string>{name}</string>
            <key>UserDefinedName</key><string>{name}</string>
            <key>VPNType</key><string>IKEv2</string>
            <key>IKEv2</key>
            <dict>
                <key>RemoteAddress</key><string>{server}</string>
                <key>RemoteIdentifier</key><string>{remote_id}</string>
                <key>LocalIdentifier</key><string>{user}</string>
                <key>AuthenticationMethod</key><string>None</string>
                <key>ExtendedAuthEnabled</key><integer>1</integer>
                <key>AuthName</key><string>{user}</string>
                <key>AuthPassword</key><string>{pass}</string>
                <key>DeadPeerDetectionRate</key><string>Medium</string>
                <key>EnablePFS</key><integer>0</integer>
                <key>IKESecurityAssociationParameters</key>
                {sa}
                <key>ChildSecurityAssociationParameters</key>
                {sa}
            </dict>
        </dict>
    </array>
    <key>PayloadDisplayName</key><string>CandyConnect IKEv2</string>
    <key>PayloadIdentifier</key><string>com.candyconnect.ikev2</string>
    <key>PayloadUUID</key><string>{root_uuid}</string>
    <key>PayloadType</key><string>Configuration</string>
    <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#,
        ca = ca_payload,
        vpn_uuid = pseudo_uuid(),
        root_uuid = pseudo_uuid(),
        name = xml_escape(conn_name),
        server = xml_escape(server),
        remote_id = xml_escape(if remote_id.is_empty() { server } else { remote_id }),
        user = xml_escape(username),
        pass = xml_escape(password),
        sa = sa,
    )
}

/// `scutil --nc status <name>` first line ("Connected", "Disconnected", ...), None if unknown service.
#[cfg(target_os = "macos")]
fn macos_nc_status(name: &str) -> Option<String> {
    let o = std::process::Command::new("scutil").args(["--nc", "status", name]).output().ok()?;
    if !o.status.success() {
        return None;
    }
    let first = String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").trim().to_string();
    if first.is_empty() || first.to_ascii_lowercase().contains("no service") { None } else { Some(first) }
}

/// macOS IKEv2: install a configuration profile (user approval required), then start it via scutil.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
async fn macos_connect_ikev2(
    app: &tauri::AppHandle,
    session: u64,
    app_data_dir: &std::path::Path,
    conn_name: &str,
    server: &str,
    username: &str,
    password: &str,
    ca_pem: Option<&str>,
    remote_id: &str,
) -> Result<(), String> {
    use std::hash::{Hash, Hasher};
    use std::process::Command;
    let logs_path = app_data_dir.join("candy.logs");

    // Re-install the profile only when its contents (server/credentials/CA) changed
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (server, remote_id, username, password, ca_pem.unwrap_or("")).hash(&mut h);
    let profile_id = format!("{:x}", h.finish());
    let id_path = app_data_dir.join("ikev2_profile.id");
    let installed_id = fs::read_to_string(&id_path).unwrap_or_default();

    if macos_nc_status(conn_name).is_none() || installed_id.trim() != profile_id {
        let profile_path = app_data_dir.join("CandyConnect-IKEv2.mobileconfig");
        fs::write(&profile_path, macos_ikev2_profile(conn_name, server, remote_id, username, password, ca_pem))
            .map_err(|e| format!("Failed to write the IKEv2 profile: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o600));
        }
        let _ = Command::new("open").arg(&profile_path).output();
        let _ = Command::new("open").arg("x-apple.systempreferences:com.apple.Profiles-Settings.extension").output();
        let _ = append_log(&logs_path, "warn", &format!(
            "IKEv2: macOS requires you to approve the VPN profile. Open System Settings → Privacy & Security → Profiles (or General → Device Management), \
             select \"CandyConnect IKEv2\" and click Install. The profile also installs the server's CA. Waiting up to 3 minutes... (profile: {})",
            profile_path.display()
        ));
        // A new service appears once the profile is installed. When an existing profile is
        // being replaced, watch its configuration (`scutil --nc show`) change instead.
        let nc_show = || {
            Command::new("scutil").args(["--nc", "show", conn_name]).output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
        };
        let existed = macos_nc_status(conn_name).is_some();
        let before = nc_show();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(if existed { 90 } else { 180 });
        loop {
            if !is_current_session(session) {
                return Err("IKEv2 connection was cancelled".into());
            }
            if (!existed && macos_nc_status(conn_name).is_some()) || (existed && nc_show() != before) {
                break;
            }
            if std::time::Instant::now() > deadline {
                if existed {
                    let _ = append_log(&logs_path, "warn", "IKEv2: the updated profile was not detected — trying the installed one");
                    break;
                }
                return Err("The IKEv2 profile was not installed. Install \"CandyConnect IKEv2\" from System Settings → Profiles and connect again.".into());
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        let _ = fs::write(&id_path, &profile_id);
        let _ = fs::remove_file(&profile_path); // contains the password in clear text
    }

    let _ = append_log(&logs_path, "info", &format!("IKEv2: starting '{}' via scutil", conn_name));
    let out = Command::new("scutil").args(["--nc", "start", conn_name]).output().map_err(|e| format!("scutil failed: {}", e))?;
    if !out.status.success() {
        return Err(format!("scutil --nc start failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let st = macos_nc_status(conn_name).unwrap_or_default();
        if st == "Connected" {
            break;
        }
        // "Disconnected" right after start (after a short grace period) means it failed
        if std::time::Instant::now() > deadline || (st == "Disconnected" && std::time::Instant::now() + std::time::Duration::from_secs(25) > deadline) {
            let _ = Command::new("scutil").args(["--nc", "stop", conn_name]).output();
            return Err(format!("IKEv2 did not connect (status: {}). Check the server CA/credentials in the profile and the system log.", if st.is_empty() { "unknown" } else { &st }));
        }
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    }
    let _ = append_log(&logs_path, "info", "IKEv2 connected (macOS native VPN)");

    let app_h = app.clone();
    let name = conn_name.to_string();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(3));
        if !is_current_session(session) {
            break;
        }
        if macos_nc_status(&name).as_deref() != Some("Connected") {
            let _ = append_log(&logs_path, "warn", &format!("{} connection dropped", name));
            notify_engine_exit(&app_h, session);
            break;
        }
    });
    Ok(())
}

#[tauri::command]
async fn start_native_vpn(
    app: tauri::AppHandle,
    protocol: String,
    server: String,
    port: u64,
    username: String,
    password: String,
    psk: String,
    auth_method: String,
    ca_cert: Option<String>,
    remote_id: Option<String>,
) -> Result<(), String> {
    use std::process::Command;
    use std::thread;

    let app_data_dir = app.path().app_data_dir().map_err(|e| format!("Failed to get app dir: {}", e))?;
    let logs_path = app_data_dir.join("candy.logs");
    let session = begin_session(&app_data_dir);

    let conn_name = format!("CandyConnect-{}", if protocol == "l2tp" { "L2TP" } else { "IKEv2" });
    let _ = append_log(&logs_path, "info", &format!("Starting native {} VPN: server={}, port={}, user={}", protocol.to_uppercase(), server, port, username));

    // IKEv2: the server authenticates with a certificate issued by its own CA (EAP-MSCHAPv2 for
    // the user), so the CA must be trusted and the remote identity is the server's IP.
    let ca_pem = ca_cert.as_deref().map(str::trim).filter(|c| c.contains("BEGIN CERTIFICATE"));
    let ca_path = if protocol == "ikev2" { ca_pem.and_then(|c| write_ikev2_ca(&app_data_dir, c)) } else { None };
    let remote_id = remote_id.filter(|r| !r.trim().is_empty()).unwrap_or_else(|| server.clone());
    if protocol == "ikev2" {
        if auth_method == "cert" {
            let _ = append_log(&logs_path, "warn", "IKEv2: the server only supports EAP-MSCHAPv2 — ignoring the 'certificate' auth setting");
        }
        let _ = append_log(&logs_path, "info", &format!(
            "IKEv2: remote id={}, auth=EAP-MSCHAPv2, CA={}", remote_id,
            ca_path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "(not provided)".into())
        ));
    }
    #[allow(unused_variables)]
    let _ = (&ca_pem, &auth_method, port);

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        // 1. Remove old connection if it exists (ignore errors)
        let _ = Command::new("rasdial")
            .args(&[&conn_name, "/DISCONNECT"])
            .creation_flags(0x08000000)
            .output();
        let _ = Command::new("powershell")
            .args(&["-NoProfile", "-Command", &format!("Remove-VpnConnection -Name '{}' -Force -ErrorAction SilentlyContinue", conn_name)])
            .creation_flags(0x08000000)
            .output();

        // 2. Create VPN connection profile
        let _ = append_log(&logs_path, "info", &format!("Creating VPN profile: {}", conn_name));
        if protocol == "ikev2" {
            if let Err(e) = windows_prepare_ikev2(&conn_name, &server, ca_path.as_deref(), &logs_path) {
                let _ = append_log(&logs_path, "error", &e);
                return Err(e);
            }
        } else {
            let create_cmd = format!(
                "Add-VpnConnection -Name {} -ServerAddress {} -TunnelType L2tp -L2tpPsk {} -AuthenticationMethod MSChapv2 -EncryptionLevel Optional -Force -RememberCredential",
                ps_quote(&conn_name), ps_quote(&server), ps_quote(&psk)
            );
            let (ok, out) = run_powershell(&create_cmd);
            if !ok {
                // Non-fatal: profile might already exist
                let _ = append_log(&logs_path, "warn", &format!("VPN profile creation output: {}", out));
            }
        }

        // For L2TP, also set the PSK in the phonebook if needed
        if protocol == "l2tp" && !psk.is_empty() {
            let set_psk_cmd = format!(
                "Set-VpnConnectionIPsecConfiguration -ConnectionName '{}' -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES128 -DHGroup Group14 -EncryptionMethod AES128 -IntegrityCheckMethod SHA256 -PfsGroup None -Force -ErrorAction SilentlyContinue",
                conn_name
            );
            let _ = Command::new("powershell")
                .args(&["-NoProfile", "-Command", &set_psk_cmd])
                .creation_flags(0x08000000)
                .output();
        }

        // 3. Connect using rasdial
        let _ = append_log(&logs_path, "info", &format!("Connecting via rasdial: {} ...", conn_name));
        let connect_output = Command::new("rasdial")
            .args(&[&conn_name, &username, &password])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| {
                let msg = format!("rasdial failed to execute: {}", e);
                let _ = append_log(&logs_path, "error", &msg);
                msg
            })?;

        if !connect_output.status.success() {
            let stderr = String::from_utf8_lossy(&connect_output.stderr);
            let stdout = String::from_utf8_lossy(&connect_output.stdout);
            let combined = format!("{} {}", stdout.trim(), stderr.trim());
            let err_msg = format!("{} connection failed: {}{}", protocol.to_uppercase(), combined.trim(), rasdial_hint(&combined));
            let _ = append_log(&logs_path, "error", &err_msg);
            // Clean up the profile on failure
            let _ = Command::new("powershell")
                .args(&["-NoProfile", "-Command", &format!("Remove-VpnConnection -Name '{}' -Force -ErrorAction SilentlyContinue", conn_name)])
                .creation_flags(0x08000000)
                .output();
            return Err(err_msg);
        }

        let _ = append_log(&logs_path, "info", &format!("{} connected successfully via rasdial", protocol.to_uppercase()));

        // 4. Monitor the connection in background — emit vpn-disconnected when it drops
        let app_h = app.clone();
        let logs_p = logs_path.clone();
        let conn_name_monitor = conn_name.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(std::time::Duration::from_secs(3));
                if !is_current_session(session) {
                    break;
                }
                let output = Command::new("rasdial")
                    .creation_flags(0x08000000)
                    .output();
                match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        if !stdout.contains(&conn_name_monitor) {
                            let _ = append_log(&logs_p, "warn", &format!("{} connection dropped", conn_name_monitor));
                            notify_engine_exit(&app_h, session);
                            break;
                        }
                    }
                    Err(_) => {
                        // Can't check — assume still connected
                    }
                }
            }
        });
    }

    #[cfg(target_os = "linux")]
    if protocol == "ikev2" {
        let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
        return linux_connect_ikev2(&app, session, &resource_dir, &app_data_dir, &conn_name, &server, &username, &password, ca_path.as_deref(), &remote_id)
            .map_err(|e| {
                let _ = append_log(&logs_path, "error", &e);
                e
            });
    }

    #[cfg(target_os = "linux")]
    {
        // Use nmcli (NetworkManager) for native VPN connections
        // 1. Delete old connection if exists
        let _ = Command::new("nmcli")
            .args(&["connection", "delete", &conn_name])
            .output();

        // 2. Create connection
        if protocol == "l2tp" {
            let add_output = Command::new("nmcli")
                .args(&[
                    "connection", "add",
                    "con-name", &conn_name,
                    "type", "vpn",
                    "vpn-type", "l2tp",
                    "ifname", "--",
                    &format!("vpn.data"), &format!("gateway={}, ipsec-enabled=yes, ipsec-psk={}, user={}", server, psk, username),
                    &format!("vpn.secrets"), &format!("password={}", password),
                ])
                .output()
                .map_err(|e| {
                    let msg = format!("nmcli failed: {}. Is NetworkManager-l2tp installed?", e);
                    let _ = append_log(&logs_path, "error", &msg);
                    msg
                })?;

            if !add_output.status.success() {
                // Fallback: try xl2tpd + ipsec directly
                let _ = append_log(&logs_path, "warn", "nmcli l2tp failed, trying xl2tpd fallback...");

                // Write xl2tpd client config
                let l2tp_conf = format!(
                    "[lac candyconnect]\nlns = {}\nppp debug = yes\npppoptfile = /tmp/cc-l2tp-options.txt\nlength bit = yes\n",
                    server
                );
                let ppp_opts = format!(
                    "ipcp-accept-local\nipcp-accept-remote\nrefuse-eap\nrequire-mschap-v2\nnoccp\nnoauth\nmtu 1400\nmru 1400\nnodefaultroute\nusepeerdns\nname {}\npassword {}\n",
                    username, password
                );
                std::fs::write("/tmp/cc-l2tp-lac.conf", &l2tp_conf).map_err(|e| e.to_string())?;
                std::fs::write("/tmp/cc-l2tp-options.txt", &ppp_opts).map_err(|e| e.to_string())?;

                // Start IPSec
                if !psk.is_empty() {
                    let ipsec_secrets = format!("{} %any : PSK \"{}\"\n", server, psk);
                    std::fs::write("/tmp/cc-ipsec.secrets", &ipsec_secrets).map_err(|e| e.to_string())?;
                    let _ = Command::new("sudo").args(&["ipsec", "restart"]).output();
                }

                let _ = Command::new("sudo")
                    .args(&["xl2tpd", "-c", "/tmp/cc-l2tp-lac.conf", "-D"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|e| format!("Failed to start xl2tpd: {}", e))?;

                thread::sleep(std::time::Duration::from_secs(1));
                let _ = Command::new("sudo")
                    .args(&["bash", "-c", "echo 'c candyconnect' > /var/run/xl2tpd/l2tp-control"])
                    .output();
            }
        }

        // 3. Activate the connection
        let up_output = Command::new("nmcli")
            .args(&["connection", "up", &conn_name])
            .output()
            .map_err(|e| format!("nmcli connection up failed: {}", e))?;

        if !up_output.status.success() {
            let stderr = String::from_utf8_lossy(&up_output.stderr);
            let err_msg = format!("{} connection failed: {}", protocol.to_uppercase(), stderr.trim());
            let _ = append_log(&logs_path, "error", &err_msg);
            let _ = Command::new("nmcli").args(&["connection", "delete", &conn_name]).output();
            return Err(err_msg);
        }

        let _ = append_log(&logs_path, "info", &format!("{} connected successfully via nmcli", protocol.to_uppercase()));

        // Monitor connection in background
        let app_h = app.clone();
        let logs_p = logs_path.clone();
        let conn_name_monitor = conn_name.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(std::time::Duration::from_secs(3));
                if !is_current_session(session) {
                    break;
                }
                let output = Command::new("nmcli")
                    .args(&["-t", "-f", "NAME,TYPE", "connection", "show", "--active"])
                    .output();
                match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        if !stdout.contains(&conn_name_monitor) {
                            let _ = append_log(&logs_p, "warn", &format!("{} connection dropped", conn_name_monitor));
                            notify_engine_exit(&app_h, session);
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
        });
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: use scutil / networksetup for native VPN
        if protocol == "l2tp" {
            // Create L2TP VPN service
            let create_output = Command::new("networksetup")
                .args(&["-createnetworkservice", &conn_name, "L2TP"])
                .output()
                .map_err(|e| format!("networksetup failed: {}", e))?;

            // Configure the VPN
            let _ = Command::new("networksetup")
                .args(&["-setpppoeserveraddress", &conn_name, &server])
                .output();
            let _ = Command::new("networksetup")
                .args(&["-setpppoeaccountname", &conn_name, &username])
                .output();

            // Set shared secret via security command
            if !psk.is_empty() {
                let _ = Command::new("security")
                    .args(&["add-generic-password", "-a", &conn_name, "-s", "com.apple.net.racoon", "-w", &psk, "-T", "/usr/sbin/racoon"])
                    .output();
            }

            // Connect
            let connect_output = Command::new("networksetup")
                .args(&["-connectpppoeservice", &conn_name])
                .output()
                .map_err(|e| format!("L2TP connect failed: {}", e))?;

            if !connect_output.status.success() {
                let stderr = String::from_utf8_lossy(&connect_output.stderr);
                let err_msg = format!("L2TP connection failed: {}", stderr.trim());
                let _ = append_log(&logs_path, "error", &err_msg);
                return Err(err_msg);
            }
        } else {
            return macos_connect_ikev2(&app, session, &app_data_dir, &conn_name, &server, &username, &password, ca_pem, &remote_id)
                .await
                .map_err(|e| {
                    let _ = append_log(&logs_path, "error", &e);
                    e
                });
        }

        // Monitor for macOS
        let app_h = app.clone();
        let logs_p = logs_path.clone();
        let conn_name_monitor = conn_name.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(std::time::Duration::from_secs(3));
                if !is_current_session(session) {
                    break;
                }
                let output = Command::new("scutil")
                    .args(&["--nc", "list"])
                    .output();
                match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        // Check if our connection is listed and connected
                        let is_connected = stdout.lines().any(|line| {
                            line.contains(&conn_name_monitor) && line.contains("Connected")
                        });
                        if !is_connected {
                            // Check if it was ever there (might still be connecting)
                            let exists = stdout.contains(&conn_name_monitor);
                            if exists {
                                let _ = append_log(&logs_p, "warn", &format!("{} connection dropped", conn_name_monitor));
                                notify_engine_exit(&app_h, session);
                                break;
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        });
    }

    Ok(())
}

#[tauri::command]
async fn stop_vpn(app: tauri::AppHandle) -> Result<(), String> {
    let app_data_dir = app.path().app_data_dir().ok();
    stop_everything(app_data_dir.as_deref());
    Ok(())
}

/// Stop every engine / tunnel / native VPN and restore the system proxy.
/// Used by stop_vpn and on app exit.
fn stop_everything(app_data_dir: Option<&std::path::Path>) {
    // End the session first so watcher threads treat the exits below as expected
    CONN_SESSION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    stop_local_proxy(None);
    if let Some(dir) = app_data_dir {
        system_proxy::restore(dir, &dir.join("candy.logs"));
    }
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill").args(&["/F", "/IM", "xray.exe", "/T"]).creation_flags(0x08000000).output();
        let _ = Command::new("taskkill").args(&["/F", "/IM", "sing-box.exe", "/T"]).creation_flags(0x08000000).output();
        let _ = Command::new("taskkill").args(&["/F", "/IM", "dnstt-client.exe", "/T"]).creation_flags(0x08000000).output();
        let _ = Command::new("taskkill").args(&["/F", "/IM", "slipstream-client.exe", "/T"]).creation_flags(0x08000000).output();
        let _ = Command::new("taskkill").args(&["/F", "/IM", "trusttunnel_client.exe", "/T"]).creation_flags(0x08000000).output();
        let _ = Command::new("taskkill").args(&["/F", "/IM", "openvpn.exe", "/T"]).creation_flags(0x08000000).output();
        // Disconnect native L2TP/IKEv2 VPN connections
        let _ = Command::new("rasdial").args(&["CandyConnect-L2TP", "/DISCONNECT"]).creation_flags(0x08000000).output();
        let _ = Command::new("rasdial").args(&["CandyConnect-IKEv2", "/DISCONNECT"]).creation_flags(0x08000000).output();
        let _ = Command::new("powershell").args(&["-NoProfile", "-Command", "Remove-VpnConnection -Name 'CandyConnect-L2TP' -Force -ErrorAction SilentlyContinue"]).creation_flags(0x08000000).output();
        let _ = Command::new("powershell").args(&["-NoProfile", "-Command", "Remove-VpnConnection -Name 'CandyConnect-IKEv2' -Force -ErrorAction SilentlyContinue"]).creation_flags(0x08000000).output();
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("xray").output();
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("sing-box").output();
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("dnstt-client").output();
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("slipstream-client").output();
        // OpenVPN / charon-cmd / TrustTunnel run as root (pkexec/sudo); fall back to an elevated kill
        for name in ["openvpn", "charon-cmd", "trusttunnel_client"] {
            kill_root_process(name);
        }
        // Disconnect native L2TP/IKEv2 VPN connections
        let _ = Command::new("nmcli").args(&["connection", "down", "CandyConnect-L2TP"]).output();
        let _ = Command::new("nmcli").args(&["connection", "down", "CandyConnect-IKEv2"]).output();
        let _ = Command::new("nmcli").args(&["connection", "delete", "CandyConnect-L2TP"]).output();
        let _ = Command::new("nmcli").args(&["connection", "delete", "CandyConnect-IKEv2"]).output();
        // Also kill xl2tpd if running as fallback
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("xl2tpd").output();
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("xray").output();
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("sing-box").output();
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("dnstt-client").output();
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("slipstream-client").output();
        // OpenVPN / charon-cmd / TrustTunnel run as root (pkexec/sudo); fall back to an elevated kill
        for name in ["openvpn", "charon-cmd", "trusttunnel_client"] {
            kill_root_process(name);
        }
        // Disconnect native VPN
        let _ = Command::new("networksetup").args(&["-disconnectpppoeservice", "CandyConnect-L2TP"]).output();
        let _ = Command::new("scutil").args(&["--nc", "stop", "CandyConnect-IKEv2"]).output();
    }
}

/// Kill a process started as root (pkexec/sudo) by name: plain pkill first, elevated if that fails.
#[cfg(unix)]
fn kill_root_process(name: &str) {
    use std::process::Command;
    let running = Command::new("pgrep").arg("-x").arg(name).output().map(|o| o.status.success()).unwrap_or(false);
    if running {
        let killed = Command::new("pkill").arg("-x").arg(name).output().map(|o| o.status.success()).unwrap_or(false);
        if !killed && unsafe { libc::geteuid() } != 0 {
            let mut c = if cfg!(target_os = "linux") { Command::new("pkexec") } else { let mut c = Command::new("sudo"); c.arg("-n"); c };
            let _ = c.args(["pkill", "-x", name]).output();
        }
    }
}

#[tauri::command]
async fn write_log(app: tauri::AppHandle, level: String, message: String) -> Result<(), String> {
    let app_data_dir = app.path().app_data_dir().expect("Failed to get app dir");
    let logs_path = app_data_dir.join("candy.logs");
    append_log(&logs_path, &level, &message).map_err(|e| e.to_string())
}

fn append_log(path: &std::path::Path, level: &str, message: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let log_entry = serde_json::json!({
        "timestamp": chrono::Local::now().to_rfc3339(),
        "level": level,
        "message": message
    });

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    let line = format!("{}\n", log_entry.to_string());
    file.write_all(line.as_bytes())?;
    Ok(())
}

fn init_app_files(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .expect("Failed to get app data directory");

    // Create the app data directory if it doesn't exist
    if !app_data_dir.exists() {
        fs::create_dir_all(&app_data_dir)?;
    }

    // Initialize settings.json with default values if it doesn't exist
    let settings_path = app_data_dir.join("settings.json");
    if !settings_path.exists() {
        let default_settings = serde_json::json!({
            "autoConnect": false,
            "launchAtStartup": false,
            "selectedProfile": "",
            "selectedProtocol": "v2ray",
            "theme": "light",
            "language": "en",
            "proxyHost": "127.0.0.1",
            "proxyPort": 10808,
            "adBlocking": true,
            "malwareProtection": true,
            "phishingPrevention": false,
            "cryptominerBlocking": false,
            "directCountryAccess": true,
            "v2rayCore": "sing-box",
            "wireguardCore": "amnezia",
            "proxyMode": "proxy",
            "proxyType": "socks",
            "autoReconnect": true,
            "killSwitch": false,
            "dnsLeakProtection": true,
            "splitTunneling": false,
            "tunInet4CIDR": "172.19.0.1/30",
            "tunInet6CIDR": "fdfe:dcba:9876::1/126",
            "mtu": 9000,
            "primaryDns": "8.8.8.8",
            "secondaryDns": "1.1.1.1",
            "customDirectDomains": [],
            "customBlockDomains": [],
            "dnsttResolver": "auto",
            "dnsttProxyPort": 7070,
            "systemProxy": true,
            "l2tpPsk": "",
            "ikev2AuthMethod": "eap"
        });
        fs::write(&settings_path, serde_json::to_string_pretty(&default_settings)?)?;
        log::info!("Created default settings.json");
    }

    // Initialize account.json with empty object if it doesn't exist
    let account_path = app_data_dir.join("account.json");
    if !account_path.exists() {
        let default_account = serde_json::json!({});
        fs::write(&account_path, serde_json::to_string_pretty(&default_account)?)?;
        log::info!("Created default account.json");
    }

    // Initialize candy.logs with empty array if it doesn't exist
    let logs_path = app_data_dir.join("candy.logs");
    if !logs_path.exists() {
        fs::write(&logs_path, "")?;
        log::info!("Created default candy.logs");
    }

    log::info!("App data directory: {:?}", app_data_dir);
    Ok(())
}

#[tauri::command]
async fn measure_latency(host: String) -> Result<u64, String> {
    use std::process::Command;
    
    // Determine the ping command based on the OS
    #[cfg(target_os = "windows")]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new("ping");
        c.args(&["-n", "1", "-w", "2000", &host]);
        c.creation_flags(0x08000000); // CREATE_NO_WINDOW
        c
    };

    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let mut c = Command::new("ping");
        c.args(&["-c", "1", "-W", "2", &host]);
        c
    };

    let output = cmd.output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    if output.status.success() {
        // Parse "time=XXms" or "time=XX ms" from the output
        for line in stdout.lines() {
            if let Some(time_pos) = line.find("time=") {
                let part = &line[time_pos + 5..];
                // Handle cases like "time=14ms" or "time=14.2 ms"
                let end_pos = part.find("ms").unwrap_or_else(|| {
                    part.find(' ').unwrap_or(part.len())
                });
                let time_str = part[..end_pos].trim();
                if let Ok(ms) = time_str.parse::<f64>() {
                    return Ok(ms.round() as u64);
                }
            }
        }
        Err("Could not parse ping time".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Ping failed: {} {}", stdout, stderr))
    }
}

#[tauri::command]
async fn check_system_executables(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    let mut missing = Vec::new();
    let app_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    
    // Check bundled tools (or system-installed ones on PATH)
    let tools = vec![
        ("xray", if cfg!(target_os = "windows") { "xray/xray.exe" } else { "xray/xray" }),
        ("sing-box", if cfg!(target_os = "windows") { "sing-box/sing-box.exe" } else { "sing-box/sing-box" }),
        ("dnstt", if cfg!(target_os = "windows") { "dnstt-client.exe" } else { "dnstt-client" }),
    ];

    for (name, path) in tools {
        if resolve_binary(&app_dir, path).is_err() {
            missing.push(name.to_string());
        }
    }

    Ok(missing)
}

#[tauri::command]
async fn is_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW = 0x08000000
        let output = Command::new("net")
            .arg("session")
            .creation_flags(0x08000000)
            .output();
        
        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On Unix-like systems, check if UID is 0
        unsafe { libc::getuid() == 0 }
    }
}

#[tauri::command]
async fn restart_as_admin(app: tauri::AppHandle) -> Result<(), String> {
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        // Use PowerShell to start the process with 'runas' verb (triggers UAC)
        let _ = Command::new("powershell")
            .arg("-Command")
            .arg(format!("Start-Process '{}' -Verb RunAs", current_exe.display()))
            .spawn();
            
        app.exit(0);
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        use std::process::Command;
        // Try pkexec for Linux or just sudo for macOS if we have a terminal (usually GUI apps use other ways)
        // For simplicity, we'll try pkexec
        let _status = Command::new("pkexec")
            .arg(current_exe)
            .spawn()
            .map_err(|e| e.to_string())?;
        
        app.exit(0);
        Ok(())
    }
}

/// Snapshot of network interface byte counters at a point in time.
struct NetSnapshot {
    bytes_recv: u64,
    bytes_sent: u64,
    timestamp: std::time::Instant,
}


/// Global state for tracking network deltas between calls.
fn net_state() -> &'static Mutex<Option<NetSnapshot>> {
    static STATE: OnceLock<Mutex<Option<NetSnapshot>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

/// Session-level cumulative counters (reset when the client reconnects).
fn net_session() -> &'static Mutex<(u64, u64)> {
    static SESSION: OnceLock<Mutex<(u64, u64)>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new((0, 0)))
}

/// VPN interface prefixes we want to track. Only these carry VPN traffic.
/// - tun*     : OpenVPN, WireGuard (wg-quick), sing-box TUN, IKEv2
/// - wg*      : WireGuard kernel interface
/// - utun*    : macOS VPN tunnel interfaces
/// - ppp*     : L2TP/IPSec PPP links
/// - sing-box : sing-box TUN interface name on some platforms
fn is_vpn_interface(name: &str) -> bool {
    let lower = name.trim_end_matches(':').to_ascii_lowercase();
    let n = lower.as_str();
    n.starts_with("tun")
        || n.starts_with("wg")
        || n.starts_with("utun")
        || n.starts_with("ppp")
        || n == "sing-box"
        || n.starts_with("candy")
}

/// Read bytes_recv and bytes_sent across VPN interfaces only.
/// Falls back to all-interface totals if no VPN interface is found (not connected).
/// Platform-specific implementation.
fn read_net_counters() -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        // Read from /proc/net/dev — only sum VPN interfaces
        if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
            let mut vpn_recv: u64 = 0;
            let mut vpn_sent: u64 = 0;
            let mut found_vpn = false;
            for line in content.lines().skip(2) {
                let line = line.trim();
                if let Some((iface, rest)) = line.split_once(':') {
                    if !is_vpn_interface(iface.trim()) {
                        continue;
                    }
                    let fields: Vec<&str> = rest.split_whitespace().collect();
                    if fields.len() >= 9 {
                        if let (Ok(r), Ok(s)) = (fields[0].parse::<u64>(), fields[8].parse::<u64>()) {
                            vpn_recv += r;
                            vpn_sent += s;
                            found_vpn = true;
                        }
                    }
                }
            }
            if found_vpn {
                return Some((vpn_recv, vpn_sent));
            }
            // No VPN interface found — return zeros (not connected to VPN)
            return Some((0, 0));
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        use std::os::windows::process::CommandExt;

        // Use `netsh interface ipv4 show interfaces` to enumerate interfaces and
        // find VPN/TAP adapters (TUN/TAP from sing-box / WireGuard / OpenVPN).
        // These typically appear as adapters with "VPN", "tun", "wg", "TAP" in their name.
        // We use `Get-NetAdapterStatistics` via PowerShell for precision.
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile", "-NonInteractive", "-Command",
                "Get-NetAdapterStatistics | Where-Object { $_.Name -match 'tun|wg|vpn|tap|candyconnect|sing' -or (Get-NetAdapter -Name $_.Name -ErrorAction SilentlyContinue).InterfaceDescription -match 'tun|tap|wintun|wireguard|sing' } | Measure-Object -Property ReceivedBytes,SentBytes -Sum | Select-Object -Property Property,Sum | ConvertTo-Csv -NoTypeInformation",
            ])
            .creation_flags(0x08000000)
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut recv: u64 = 0;
        let mut sent: u64 = 0;
        for line in stdout.lines() {
            let parts: Vec<&str> = line.trim_matches('"').split("\",\"").collect();
            if parts.len() >= 2 {
                let prop = parts[0].trim_matches('"');
                let val: u64 = parts[1].trim_matches('"').parse().unwrap_or(0);
                if prop == "ReceivedBytes" { recv = val; }
                if prop == "SentBytes" { sent = val; }
            }
        }
        if recv > 0 || sent > 0 {
            return Some((recv, sent));
        }
        // Fallback: try reading just the WinTUN/TAP adapter via netstat -e
        // (netstat -e gives totals for ALL adapters; not ideal but better than nothing)
        let output2 = Command::new("netstat")
            .args(&["-e"])
            .creation_flags(0x08000000)
            .output()
            .ok()?;
        let stdout2 = String::from_utf8_lossy(&output2.stdout);
        for line in stdout2.lines() {
            let line = line.trim();
            if line.starts_with("Bytes") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let (Ok(r), Ok(s)) = (parts[1].parse::<u64>(), parts[2].parse::<u64>()) {
                        return Some((r, s));
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        // Use netstat -ib on macOS — filter to VPN interfaces only (utun*, ppp*, tun*)
        let output = Command::new("netstat")
            .args(&["-ib"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut vpn_recv: u64 = 0;
        let mut vpn_sent: u64 = 0;
        let mut found_vpn = false;
        for line in stdout.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // netstat -ib columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes
            if fields.len() >= 10 && is_vpn_interface(fields[0]) {
                if let (Ok(r), Ok(s)) = (fields[6].parse::<u64>(), fields[9].parse::<u64>()) {
                    vpn_recv += r;
                    vpn_sent += s;
                    found_vpn = true;
                }
            }
        }
        if found_vpn {
            return Some((vpn_recv, vpn_sent));
        }
        Some((0, 0))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        None
    }
}

#[tauri::command]
async fn get_network_stats() -> Result<serde_json::Value, String> {
    let counters = read_net_counters().ok_or("Failed to read network counters")?;
    let now = std::time::Instant::now();
    let (bytes_recv, bytes_sent) = counters;

    let mut state = net_state().lock().map_err(|e| e.to_string())?;
    let mut session = net_session().lock().map_err(|e| e.to_string())?;

    let (dl_kbps, ul_kbps) = if let Some(prev) = state.as_ref() {
        let elapsed = now.duration_since(prev.timestamp).as_secs_f64();
        if elapsed > 0.01 {
            let dl_bytes = bytes_recv.saturating_sub(prev.bytes_recv);
            let ul_bytes = bytes_sent.saturating_sub(prev.bytes_sent);

            // Accumulate session totals
            session.0 += dl_bytes;
            session.1 += ul_bytes;

            let dl = (dl_bytes as f64 / elapsed) / 1024.0;
            let ul = (ul_bytes as f64 / elapsed) / 1024.0;
            (dl, ul)
        } else {
            (0.0, 0.0)
        }
    } else {
        // First call — no delta yet, just record baseline
        (0.0, 0.0)
    };

    // Store current snapshot
    *state = Some(NetSnapshot {
        bytes_recv,
        bytes_sent,
        timestamp: now,
    });

    Ok(serde_json::json!({
        "downloadSpeed": (dl_kbps * 10.0).round() / 10.0,
        "uploadSpeed": (ul_kbps * 10.0).round() / 10.0,
        "totalDownload": session.0,
        "totalUpload": session.1,
        "countryCode": "??",
    }))
}

#[tauri::command]
async fn reset_network_session() -> Result<(), String> {
    let mut session = net_session().lock().map_err(|e| e.to_string())?;
    *session = (0, 0);
    // Also reset the baseline snapshot so the first read after reset shows 0 speed
    let mut state = net_state().lock().map_err(|e| e.to_string())?;
    *state = None;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .plugin(tauri_plugin_fs::init())
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }

      // Initialize app data files
      if let Err(e) = init_app_files(app) {
        log::error!("Failed to initialize app files: {}", e);
      }

      // Undo a system proxy left behind by a crash / forced kill of a previous run
      if let Ok(dir) = app.path().app_data_dir() {
        system_proxy::restore(&dir, &dir.join("candy.logs"));
      }

      // System Tray Setup
      let show_i = MenuItem::with_id(app, "show", "Show CandyConnect", true, None::<&str>)?;
      let quit_i = MenuItem::with_id(app, "quit", "Exit App", true, None::<&str>)?;
      let menu = Menu::with_items(app, &[&show_i, &quit_i])?;

      let _tray = TrayIconBuilder::new()
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
           "quit" => {
               app.exit(0);
           }
           "show" => {
               if let Some(window) = app.get_webview_window("main") {
                   let _ = window.show();
                   let _ = window.set_focus();
               }
           }
           _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: tauri::tray::MouseButton::Left, .. } = event {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

      Ok(())
    })
    .invoke_handler(tauri::generate_handler![measure_latency, check_system_executables, is_admin, restart_as_admin, generate_sing_box_config, start_vpn, start_dnstt, start_slipstream, start_trusttunnel, start_native_vpn, start_wireguard, start_openvpn, stop_vpn, write_log, get_network_stats, reset_network_session])
    .build(tauri::generate_context!())
    .expect("error while building tauri application")
    .run(|app_handle, event| match event {
        tauri::RunEvent::WindowEvent { label, event: tauri::WindowEvent::CloseRequested { api, .. }, .. } => {
            if label == "main" {
                api.prevent_close();
                if let Some(window) = app_handle.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
        }
        tauri::RunEvent::Exit => {
            // Quitting must not leave the OS proxy pointing at a dead local port
            // (or engines running in the background)
            let dir = app_handle.path().app_data_dir().ok();
            stop_everything(dir.as_deref());
        }
        _ => {}
    });
}
