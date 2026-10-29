//! OS system proxy management for Proxy mode.
//!
//! `set()` saves the user's current proxy settings to `system_proxy_backup.json` in the
//! app data dir (only when no backup exists yet, so the backup always holds the values from
//! before CandyConnect touched them) and points the OS proxy at the local inbound.
//! `restore()` puts the saved values back and deletes the backup. Because the backup is on
//! disk, a crash or a killed process is recovered from at the next app start.
//!
//! - Windows: HKCU\...\Internet Settings (ProxyEnable/ProxyServer/ProxyOverride) + WinINet refresh
//! - macOS:   `networksetup` web/secure-web/SOCKS proxy for every enabled network service
//! - Linux:   GNOME `gsettings org.gnome.system.proxy` and/or KDE `kioslaverc` (kwriteconfig5/6)

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Where the local proxy listens. `http_port` is an HTTP(-CONNECT) capable inbound,
/// `socks_port` a SOCKS5 inbound (both may be the same port for "mixed" inbounds).
pub struct ProxyTarget {
    pub host: String,
    pub http_port: Option<u16>,
    pub socks_port: Option<u16>,
}

/// Hosts that must bypass the proxy (WinINet syntax).
#[cfg(target_os = "windows")]
const WIN_BYPASS: &str = "<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*";

fn lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

fn backup_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("system_proxy_backup.json")
}

fn log(logs: &Path, level: &str, msg: &str) {
    let _ = crate::append_log(logs, level, &format!("[SystemProxy] {}", msg));
}

/// Point the OS proxy settings at the local proxy.
pub fn set(app_data_dir: &Path, logs: &Path, target: &ProxyTarget) -> Result<(), String> {
    let _guard = lock();
    if target.http_port.is_none() && target.socks_port.is_none() {
        return Err("no local proxy port to use".into());
    }
    let host = if target.host.is_empty() || target.host == "0.0.0.0" || target.host == "::" {
        "127.0.0.1".to_string()
    } else {
        target.host.clone()
    };

    // Keep an existing backup: it holds the settings from before we changed anything.
    let path = backup_path(app_data_dir);
    if !path.is_file() {
        let backup = platform::capture();
        if backup.is_null() {
            return Err("system proxy is not supported on this desktop (nothing to configure)".into());
        }
        std::fs::write(&path, serde_json::to_string_pretty(&backup).unwrap_or_default())
            .map_err(|e| format!("failed to save the current proxy settings: {}", e))?;
    }

    match platform::apply(logs, &host, target.http_port, target.socks_port) {
        Ok(()) => {
            log(logs, "info", &format!(
                "System proxy set to {} (http={}, socks={})",
                host,
                target.http_port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                target.socks_port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            ));
            Ok(())
        }
        Err(e) => {
            // Undo whatever was partially applied
            drop(_guard);
            restore(app_data_dir, logs);
            Err(e)
        }
    }
}

/// Restore the proxy settings saved by `set()`. No-op when nothing was changed.
pub fn restore(app_data_dir: &Path, logs: &Path) {
    let _guard = lock();
    let path = backup_path(app_data_dir);
    let backup = match std::fs::read_to_string(&path).ok().and_then(|c| serde_json::from_str::<Value>(&c).ok()) {
        Some(b) => b,
        None => {
            let _ = std::fs::remove_file(&path);
            return;
        }
    };
    match platform::restore(logs, &backup) {
        Ok(()) => log(logs, "info", "System proxy settings restored"),
        Err(e) => log(logs, "warn", &format!("Failed to fully restore system proxy settings: {}", e)),
    }
    let _ = std::fs::remove_file(&path);
}

/// Run a command without flashing a console window; returns (success, stdout).
#[allow(dead_code)]
fn run(program: &str, args: &[&str]) -> (bool, String) {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    match cmd.output() {
        Ok(o) => (o.status.success(), String::from_utf8_lossy(&o.stdout).trim().to_string()),
        Err(_) => (false, String::new()),
    }
}

/* ───────────────────────────── Windows ───────────────────────────── */

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
    };

    const KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open() -> Result<Key, String> {
        let mut h: HKEY = 0 as HKEY;
        let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide(KEY).as_ptr(), 0, KEY_READ | KEY_WRITE, &mut h) };
        if rc != ERROR_SUCCESS {
            return Err(format!("cannot open HKCU\\{} (error {})", KEY, rc));
        }
        Ok(Key(h))
    }

    fn get_dword(k: &Key, name: &str) -> Option<u32> {
        let mut ty = 0u32;
        let mut val = 0u32;
        let mut len = 4u32;
        let rc = unsafe {
            RegQueryValueExW(k.0, wide(name).as_ptr(), std::ptr::null(), &mut ty, &mut val as *mut u32 as *mut u8, &mut len)
        };
        (rc == ERROR_SUCCESS && ty == REG_DWORD).then_some(val)
    }

    fn get_string(k: &Key, name: &str) -> Option<String> {
        let name_w = wide(name);
        let mut ty = 0u32;
        let mut len = 0u32;
        let rc = unsafe { RegQueryValueExW(k.0, name_w.as_ptr(), std::ptr::null(), &mut ty, std::ptr::null_mut(), &mut len) };
        if rc != ERROR_SUCCESS || (ty != REG_SZ && ty != REG_EXPAND_SZ) {
            return None;
        }
        let mut buf = vec![0u16; (len as usize / 2) + 1];
        let mut len2 = (buf.len() * 2) as u32;
        let rc = unsafe {
            RegQueryValueExW(k.0, name_w.as_ptr(), std::ptr::null(), &mut ty, buf.as_mut_ptr() as *mut u8, &mut len2)
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }

    fn set_dword(k: &Key, name: &str, v: u32) -> Result<(), String> {
        let rc = unsafe { RegSetValueExW(k.0, wide(name).as_ptr(), 0, REG_DWORD, &v as *const u32 as *const u8, 4) };
        if rc == ERROR_SUCCESS { Ok(()) } else { Err(format!("cannot set {} (error {})", name, rc)) }
    }

    fn set_string(k: &Key, name: &str, v: &str) -> Result<(), String> {
        let data = wide(v);
        let rc = unsafe {
            RegSetValueExW(k.0, wide(name).as_ptr(), 0, REG_SZ, data.as_ptr() as *const u8, (data.len() * 2) as u32)
        };
        if rc == ERROR_SUCCESS { Ok(()) } else { Err(format!("cannot set {} (error {})", name, rc)) }
    }

    fn delete(k: &Key, name: &str) {
        unsafe { RegDeleteValueW(k.0, wide(name).as_ptr()) };
    }

    /// Tell WinINet (and everything that follows it: Edge/Chrome, .NET, ...) to reload the settings.
    fn notify() {
        unsafe {
            InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
            InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
        }
    }

    pub fn capture() -> Value {
        match open() {
            Ok(k) => json!({
                "platform": "windows",
                "ProxyEnable": get_dword(&k, "ProxyEnable"),
                "ProxyServer": get_string(&k, "ProxyServer"),
                "ProxyOverride": get_string(&k, "ProxyOverride"),
            }),
            Err(_) => Value::Null,
        }
    }

    pub fn apply(logs: &Path, host: &str, http: Option<u16>, socks: Option<u16>) -> Result<(), String> {
        let k = open()?;
        // A single "host:port" makes every WinINet protocol use the HTTP proxy; without an
        // HTTP inbound fall back to the SOCKS-only syntax.
        let server = match (http, socks) {
            (Some(h), _) => format!("{}:{}", host, h),
            (None, Some(s)) => format!("socks={}:{}", host, s),
            (None, None) => return Err("no local proxy port".into()),
        };
        set_string(&k, "ProxyServer", &server)?;
        set_string(&k, "ProxyOverride", WIN_BYPASS)?;
        set_dword(&k, "ProxyEnable", 1)?;
        if get_string(&k, "AutoConfigURL").map_or(false, |s| !s.is_empty()) {
            log(logs, "warn", "A proxy auto-config (PAC) script is configured in Windows; some apps may prefer it over the system proxy");
        }
        notify();
        Ok(())
    }

    pub fn restore(_logs: &Path, b: &Value) -> Result<(), String> {
        let k = open()?;
        match b["ProxyEnable"].as_u64() {
            Some(v) => set_dword(&k, "ProxyEnable", v as u32)?,
            None => set_dword(&k, "ProxyEnable", 0)?,
        }
        for name in ["ProxyServer", "ProxyOverride"] {
            match b[name].as_str() {
                Some(v) => set_string(&k, name, v)?,
                None => delete(&k, name),
            }
        }
        notify();
        Ok(())
    }
}

/* ───────────────────────────── macOS ───────────────────────────── */

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    const KINDS: [&str; 3] = ["webproxy", "securewebproxy", "socksfirewallproxy"];

    /// Enabled network services (lines starting with '*' are disabled).
    fn services() -> Vec<String> {
        let (ok, out) = run("networksetup", &["-listallnetworkservices"]);
        if !ok {
            return Vec::new();
        }
        out.lines()
            .skip(1) // "An asterisk (*) denotes that a network service is disabled."
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('*'))
            .map(|l| l.to_string())
            .collect()
    }

    fn get(kind: &str, svc: &str) -> Value {
        let (_, out) = run("networksetup", &[&format!("-get{}", kind), svc]);
        let mut enabled = false;
        let mut server = String::new();
        let mut port = 0u64;
        for line in out.lines() {
            if let Some((k, v)) = line.split_once(':') {
                let v = v.trim();
                match k.trim() {
                    "Enabled" => enabled = v.eq_ignore_ascii_case("yes"),
                    "Server" => server = v.to_string(),
                    "Port" => port = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        json!({ "enabled": enabled, "server": server, "port": port })
    }

    pub fn capture() -> Value {
        let svcs = services();
        if svcs.is_empty() {
            return Value::Null;
        }
        let mut map = serde_json::Map::new();
        for s in &svcs {
            let mut entry = serde_json::Map::new();
            for kind in KINDS {
                entry.insert(kind.to_string(), get(kind, s));
            }
            map.insert(s.clone(), Value::Object(entry));
        }
        json!({ "platform": "macos", "services": map })
    }

    pub fn apply(logs: &Path, host: &str, http: Option<u16>, socks: Option<u16>) -> Result<(), String> {
        let svcs = services();
        if svcs.is_empty() {
            return Err("networksetup found no enabled network services".into());
        }
        let mut applied = 0;
        for s in &svcs {
            let mut ok_all = true;
            for kind in KINDS {
                let port = if kind == "socksfirewallproxy" { socks } else { http };
                let state = format!("-set{}state", kind);
                match port {
                    Some(p) => {
                        let (ok, _) = run("networksetup", &[&format!("-set{}", kind), s, host, &p.to_string()]);
                        let (ok2, _) = run("networksetup", &[&state, s, "on"]);
                        ok_all &= ok && ok2;
                    }
                    None => {
                        let _ = run("networksetup", &[&state, s, "off"]);
                    }
                }
            }
            let _ = run("networksetup", &["-setproxybypassdomains", s, "localhost", "127.0.0.1", "*.local", "169.254/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
            if ok_all {
                applied += 1;
            } else {
                log(logs, "warn", &format!("networksetup could not set the proxy for '{}' (administrator rights may be required)", s));
            }
        }
        if applied == 0 {
            return Err("networksetup could not change the proxy settings (administrator rights may be required)".into());
        }
        Ok(())
    }

    pub fn restore(_logs: &Path, b: &Value) -> Result<(), String> {
        let mut failed = Vec::new();
        if let Some(svcs) = b["services"].as_object() {
            for (s, entry) in svcs {
                for kind in KINDS {
                    let e = &entry[kind];
                    let server = e["server"].as_str().unwrap_or("");
                    let port = e["port"].as_u64().unwrap_or(0);
                    if !server.is_empty() && port > 0 {
                        let _ = run("networksetup", &[&format!("-set{}", kind), s, server, &port.to_string()]);
                    }
                    let on = e["enabled"].as_bool().unwrap_or(false);
                    let (ok, _) = run("networksetup", &[&format!("-set{}state", kind), s, if on { "on" } else { "off" }]);
                    if !ok {
                        failed.push(format!("{}/{}", s, kind));
                    }
                }
            }
        }
        if failed.is_empty() { Ok(()) } else { Err(format!("networksetup failed for {}", failed.join(", "))) }
    }
}

/* ───────────────────────────── Linux ───────────────────────────── */

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    const GNOME_KEYS: [(&str, &str); 8] = [
        ("org.gnome.system.proxy", "mode"),
        ("org.gnome.system.proxy", "ignore-hosts"),
        ("org.gnome.system.proxy.http", "host"),
        ("org.gnome.system.proxy.http", "port"),
        ("org.gnome.system.proxy.https", "host"),
        ("org.gnome.system.proxy.https", "port"),
        ("org.gnome.system.proxy.socks", "host"),
        ("org.gnome.system.proxy.socks", "port"),
    ];
    const KDE_KEYS: [&str; 5] = ["ProxyType", "httpProxy", "httpsProxy", "socksProxy", "NoProxyFor"];

    fn has_gsettings() -> bool {
        run("gsettings", &["get", "org.gnome.system.proxy", "mode"]).0
    }

    /// (kwriteconfig, kreadconfig) for KDE Plasma sessions.
    fn kde_tools() -> Option<(&'static str, &'static str)> {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().to_ascii_uppercase();
        if !desktop.contains("KDE") && std::env::var_os("KDE_FULL_SESSION").is_none() {
            return None;
        }
        for (w, r) in [("kwriteconfig6", "kreadconfig6"), ("kwriteconfig5", "kreadconfig5")] {
            if run(r, &["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType"]).0
                || std::process::Command::new(w).arg("--help").output().is_ok()
            {
                return Some((w, r));
            }
        }
        None
    }

    fn kde_write(w: &str, key: &str, value: Option<&str>) -> bool {
        match value {
            Some(v) => run(w, &["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, v]).0,
            None => run(w, &["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, "--delete"]).0,
        }
    }

    fn kde_notify() {
        let _ = run("dbus-send", &["--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:"]);
    }

    pub fn capture() -> Value {
        let mut out = serde_json::Map::new();
        out.insert("platform".into(), json!("linux"));
        if has_gsettings() {
            let mut g = serde_json::Map::new();
            for (schema, key) in GNOME_KEYS {
                let (ok, v) = run("gsettings", &["get", schema, key]);
                if ok {
                    g.insert(format!("{}|{}", schema, key), json!(v));
                }
            }
            out.insert("gnome".into(), Value::Object(g));
        }
        if let Some((_, r)) = kde_tools() {
            let mut k = serde_json::Map::new();
            for key in KDE_KEYS {
                let (_, v) = run(r, &["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key]);
                k.insert(key.to_string(), json!(v));
            }
            out.insert("kde".into(), Value::Object(k));
        }
        if out.len() == 1 {
            return Value::Null; // neither GNOME nor KDE settings are available
        }
        Value::Object(out)
    }

    pub fn apply(logs: &Path, host: &str, http: Option<u16>, socks: Option<u16>) -> Result<(), String> {
        let mut any = false;
        if has_gsettings() {
            let q = |s: &str| format!("'{}'", s.replace('\'', ""));
            let mut ok = true;
            let mut set = |schema: &str, key: &str, val: &str| {
                ok &= run("gsettings", &["set", schema, key, val]).0;
            };
            let (hh, hp) = match http { Some(p) => (q(host), p.to_string()), None => ("''".to_string(), "0".to_string()) };
            let (sh, sp) = match socks { Some(p) => (q(host), p.to_string()), None => ("''".to_string(), "0".to_string()) };
            set("org.gnome.system.proxy.http", "host", &hh);
            set("org.gnome.system.proxy.http", "port", &hp);
            set("org.gnome.system.proxy.https", "host", &hh);
            set("org.gnome.system.proxy.https", "port", &hp);
            set("org.gnome.system.proxy.socks", "host", &sh);
            set("org.gnome.system.proxy.socks", "port", &sp);
            set("org.gnome.system.proxy", "ignore-hosts",
                "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']");
            set("org.gnome.system.proxy", "mode", "'manual'");
            if ok {
                any = true;
            } else {
                log(logs, "warn", "gsettings could not set every proxy key");
            }
        }
        if let Some((w, _)) = kde_tools() {
            let http_v = http.map(|p| format!("http://{} {}", host, p));
            let socks_v = socks.map(|p| format!("socks://{} {}", host, p));
            let ok = kde_write(w, "httpProxy", Some(http_v.as_deref().unwrap_or("")))
                & kde_write(w, "httpsProxy", Some(http_v.as_deref().unwrap_or("")))
                & kde_write(w, "socksProxy", Some(socks_v.as_deref().unwrap_or("")))
                & kde_write(w, "NoProxyFor", Some("localhost,127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))
                & kde_write(w, "ProxyType", Some("1"));
            kde_notify();
            if ok {
                any = true;
            } else {
                log(logs, "warn", &format!("{} could not set every proxy key", w));
            }
        }
        if any {
            Ok(())
        } else {
            Err("no supported desktop proxy settings found (GNOME gsettings or KDE kwriteconfig); configure your apps to use the local proxy manually".into())
        }
    }

    pub fn restore(_logs: &Path, b: &Value) -> Result<(), String> {
        let mut failed = Vec::new();
        if let Some(g) = b["gnome"].as_object() {
            // Restore the mode last so apps never see "manual" with half-restored hosts
            let mut entries: Vec<(&String, &Value)> = g.iter().collect();
            entries.sort_by_key(|(k, _)| k.ends_with("|mode"));
            for (k, v) in entries {
                if let (Some((schema, key)), Some(val)) = (k.split_once('|'), v.as_str()) {
                    if !run("gsettings", &["set", schema, key, val]).0 {
                        failed.push(k.clone());
                    }
                }
            }
        }
        if let Some(k) = b["kde"].as_object() {
            if let Some((w, _)) = kde_tools() {
                for key in KDE_KEYS.iter().filter(|k| **k != "ProxyType").chain(std::iter::once(&"ProxyType")) {
                    let v = k.get(*key).and_then(|v| v.as_str()).unwrap_or("");
                    let val = if v.is_empty() { if *key == "ProxyType" { Some("0") } else { None } } else { Some(v) };
                    if !kde_write(w, key, val) {
                        failed.push(format!("kde/{}", key));
                    }
                }
                kde_notify();
            }
        }
        if failed.is_empty() { Ok(()) } else { Err(format!("could not restore {}", failed.join(", "))) }
    }
}

/* ───────────────────────────── other ───────────────────────────── */

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;
    pub fn capture() -> Value { Value::Null }
    pub fn apply(_: &Path, _: &str, _: Option<u16>, _: Option<u16>) -> Result<(), String> {
        Err("system proxy is not supported on this platform".into())
    }
    pub fn restore(_: &Path, _: &Value) -> Result<(), String> { Ok(()) }
}
