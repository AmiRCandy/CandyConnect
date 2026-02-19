mod sing_box_helper;

use std::fs;
use std::sync::{Arc, Mutex};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent},
    Manager,
};

#[tauri::command]
async fn generate_sing_box_config(app: tauri::AppHandle, server_address: String) -> Result<String, String> {
    use crate::sing_box_helper::{Config, RouteRule};
    
    let app_data_dir = app.path().app_data_dir().expect("Failed to get app data directory");
    let settings_path = app_data_dir.join("settings.json");
    
    if !settings_path.exists() {
        return Err("Settings file not found".to_string());
    }

    let settings_content = fs::read_to_string(settings_path).map_err(|e| e.to_string())?;
    let settings: serde_json::Value = serde_json::from_str(&settings_content).map_err(|e| e.to_string())?;

    // Extract settings with defaults
    let primary_dns = settings["primaryDns"].as_str().unwrap_or("8.8.8.8");
    let secondary_dns = settings["secondaryDns"].as_str().unwrap_or("1.1.1.1");
    let inet4 = settings["tunInet4CIDR"].as_str().unwrap_or("172.19.0.1/30");
    let inet6 = settings["tunInet6CIDR"].as_str().unwrap_or("fdfe:dcba:9876::1/126");
    let mtu = settings["mtu"].as_u64().unwrap_or(9000) as u32;
    let proxy_host = settings["proxyHost"].as_str().unwrap_or("127.0.0.1");
    let proxy_port = settings["proxyPort"].as_u64().unwrap_or(10808) as u16;

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
        proxy_host,
        proxy_port,
        primary_dns,
        secondary_dns,
        inet4,
        inet6,
        mtu,
        direct_domains,
        block_domains,
    );

    // Add server bypass rule (IP or Domain)
    if server_address.parse::<std::net::IpAddr>().is_ok() {
        config.route.rules.push(RouteRule {
            protocol: None,
            outbound: Some("direct-out".into()),
            ip_cidr: Some(vec![format!("{}/32", server_address)]),
            domain: None,
        });
    } else {
        config.route.rules.push(RouteRule {
            protocol: None,
            outbound: Some("direct-out".into()),
            ip_cidr: None,
            domain: Some(vec![server_address]),
        });
    }

    // Serialize
    serde_json::to_string_pretty(&config).map_err(|e| e.to_string())
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

    let app_data_dir = app.path().app_data_dir().expect("Failed to get app dir");
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap());
    let logs_path = app_data_dir.join("candy.logs");

    // 1. Validate and save Xray config
    let xray_config_path = app_data_dir.join("xray_config.json");

    // Validate that config_json is valid JSON before writing
    let parsed: serde_json::Value = serde_json::from_str(&config_json).map_err(|e| {
        let err_msg = format!("Invalid Xray config JSON: {}. First 200 chars: {}", e, config_json.chars().take(200).collect::<String>());
        let _ = append_log(&logs_path, "error", &err_msg);
        err_msg
    })?;

    // Re-serialize to ensure clean formatting
    let clean_config = serde_json::to_string_pretty(&parsed).unwrap_or(config_json.clone());
    fs::write(&xray_config_path, &clean_config).map_err(|e| e.to_string())?;

    // Log config snippet for debugging (first 200 chars)
    let config_preview: String = clean_config.chars().take(200).collect();
    let _ = append_log(&logs_path, "info", &format!("Xray config saved ({} bytes): {}...", clean_config.len(), config_preview));

    // 2. Determine paths using a more robust search
    let resolve_tool = |base: &std::path::Path, rel_path: &str| -> std::path::PathBuf {
        let p1 = base.join(rel_path);
        if p1.exists() { return p1; }
        let p2 = base.join("resources").join(rel_path);
        if p2.exists() { return p2; }
        p1 // fallback to p1
    };

    let xray_bin = resolve_tool(&resource_dir, if cfg!(target_os = "windows") { "xray/xray.exe" } else { "xray/xray" });
    let sing_box_bin = resolve_tool(&resource_dir, if cfg!(target_os = "windows") { "sing-box/sing-box.exe" } else { "sing-box/sing-box" });

    // 3. Start Xray
    let _ = append_log(&logs_path, "info", &format!("Starting Xray engine: {}", xray_bin.display()));
    
    let mut xray_cmd = Command::new(&xray_bin);
    xray_cmd
        .arg("-c")
        .arg(&xray_config_path)
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
            let err_msg = format!("CRITICAL: Failed to spawn Xray: {}", e);
            let _ = append_log(&logs_path, "error", &err_msg);
            err_msg
        })?;

    let _ = append_log(&logs_path, "info", &format!("Xray process spawned successfully (PID: {})", xray_child.id()));

    // Log whether the binary actually exists at the resolved path
    if xray_bin.exists() {
        let _ = append_log(&logs_path, "info", &format!("Xray binary confirmed at: {}", xray_bin.display()));
    } else {
        let _ = append_log(&logs_path, "error", &format!("Xray binary NOT FOUND at: {}", xray_bin.display()));
    }

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
        use tauri::Emitter;
        let _ = app_h_xray.emit("vpn-disconnected", ());
    });

    // 4. If TUN mode, also start Sing-box
    if mode == "tun" {
        let _ = append_log(&logs_path, "info", "Initializing TUN mode orchestration...");
        let mut server_address = "127.0.0.1".to_string();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&config_json) {
            if let Some(outbound) = json["outbounds"].as_array().and_then(|a| a.get(0)) {
               if let Some(vnext) = outbound["settings"]["vnext"].as_array().and_then(|a| a.get(0)) {
                   if let Some(addr) = vnext["address"].as_str() {
                       server_address = addr.to_string();
                   }
               }
            }
        }

        let sb_config = generate_sing_box_config(app.clone(), server_address).await?;
        let sb_config_path = app_data_dir.join("sing_box_config.json");
        fs::write(&sb_config_path, &sb_config).map_err(|e| e.to_string())?;

        let _ = append_log(&logs_path, "info", &format!("Starting Sing-box routing engine: {}", sing_box_bin.display()));

        let mut sb_cmd = Command::new(&sing_box_bin);
        sb_cmd
            .arg("run")
            .arg("-c")
            .arg(&sb_config_path)
            .env("ENABLE_DEPRECATED_SPECIAL_OUTBOUNDS", "true")
            .env("ENABLE_DEPRECATED_TUN_ADDRESS_X", "true")
.env("ENABLE_DEPRECATED_WIREGUARD_OUTBOUND", "true")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

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
            use tauri::Emitter;
            let _ = app_h_sb.emit("vpn-disconnected", ());
        });
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
) -> Result<(), String> {
    use std::process::{Command, Stdio};
    use std::io::{BufRead, BufReader};
    use std::thread;
    use crate::sing_box_helper::Config;

    let app_data_dir = app.path().app_data_dir().expect("Failed to get app dir");
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap());
    let logs_path = app_data_dir.join("candy.logs");

    let _ = append_log(&logs_path, "info", &format!(
        "Starting WireGuard via sing-box: server={}:{}, mode={}", server, port, mode
    ));

    let resolve_tool = |base: &std::path::Path, rel_path: &str| -> std::path::PathBuf {
        let p1 = base.join(rel_path);
        if p1.exists() { return p1; }
        let p2 = base.join("resources").join(rel_path);
        if p2.exists() { return p2; }
        p1
    };

    let sing_box_bin = resolve_tool(
        &resource_dir,
        if cfg!(target_os = "windows") { "sing-box/sing-box.exe" } else { "sing-box/sing-box" }
    );

    // Build the correct sing-box config depending on mode
    let sb_config = if mode == "tun" {
        // TUN mode: TUN inbound + WireGuard outbound with full key material
        // Read TUN settings from settings file
        let settings_path = app_data_dir.join("settings.json");
        let (_inet4, _inet6, mtu, primary_dns, secondary_dns) = if settings_path.exists() {
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
            Some(mtu),
            &primary_dns,
            &secondary_dns,
        );
        serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?
    } else {
        // Proxy mode: SOCKS inbound + WireGuard outbound
        // Read proxy settings
        let settings_path = app_data_dir.join("settings.json");
        let (proxy_host, proxy_port) = if settings_path.exists() {
            if let Ok(content) = fs::read_to_string(&settings_path) {
                if let Ok(s) = serde_json::from_str::<serde_json::Value>(&content) {
                    (
                        s["proxyHost"].as_str().unwrap_or("127.0.0.1").to_string(),
                        s["proxyPort"].as_u64().unwrap_or(1080) as u16,
                    )
                } else {
                    ("127.0.0.1".into(), 1080u16)
                }
            } else {
                ("127.0.0.1".into(), 1080u16)
            }
        } else {
            ("127.0.0.1".into(), 1080u16)
        };

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
        .env("ENABLE_DEPRECATED_SPECIAL_OUTBOUNDS", "true")
        .env("ENABLE_DEPRECATED_TUN_ADDRESS_X", "true")
        .env("ENABLE_DEPRECATED_WIREGUARD_OUTBOUND", "true")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

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
        use tauri::Emitter;
        let _ = app_h.emit("vpn-disconnected", ());
    });

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
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap());
    let logs_path = app_data_dir.join("candy.logs");

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

    // Resolve openvpn binary: try bundled first, then system
    let resolve_tool = |base: &std::path::Path, rel_path: &str| -> std::path::PathBuf {
        let p1 = base.join(rel_path);
        if p1.exists() { return p1; }
        let p2 = base.join("resources").join(rel_path);
        if p2.exists() { return p2; }
        p1
    };

    // On Windows try bundled openvpn.exe; on other platforms use system openvpn
    #[cfg(target_os = "windows")]
    let openvpn_bin = {
        let bundled = resolve_tool(&resource_dir, "openvpn/openvpn.exe");
        if bundled.exists() {
            bundled
        } else {
            std::path::PathBuf::from("openvpn.exe")
        }
    };

    #[cfg(not(target_os = "windows"))]
    let openvpn_bin = std::path::PathBuf::from("openvpn");

    let _ = append_log(&logs_path, "info", &format!(
        "Using OpenVPN binary: {}", openvpn_bin.display()
    ));

    let mut ovpn_cmd = Command::new(&openvpn_bin);
    ovpn_cmd
        .arg("--config")
        .arg(&ovpn_config_path)
        .arg("--auth-user-pass")
        .arg(&auth_path)
        .arg("--auth-nocache")
        .arg("--verb")
        .arg("3")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // On Linux/macOS we may need sudo for TUN interface creation
    #[cfg(not(target_os = "windows"))]
    {
        // Only wrap with sudo if not already root
        // We rebuild the command with sudo prefix
        let user = std::env::var("USER").unwrap_or_default();
        if user != "root" {
            ovpn_cmd = Command::new("sudo");
            ovpn_cmd
                .arg(openvpn_bin.to_str().unwrap_or("openvpn"))
                .arg("--config")
                .arg(&ovpn_config_path)
                .arg("--auth-user-pass")
                .arg(&auth_path)
                .arg("--auth-nocache")
                .arg("--verb")
                .arg("3")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
    }

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
        use tauri::Emitter;
        let _ = app_h.emit("vpn-disconnected", ());
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
) -> Result<(), String> {
    use std::process::{Command, Stdio};
    use std::io::{BufRead, BufReader};
    use std::thread;

    let app_data_dir = app.path().app_data_dir().expect("Failed to get app dir");
    let resource_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap());
    let logs_path = app_data_dir.join("candy.logs");

    // 1. Resolve dnstt-client binary
    let resolve_tool = |base: &std::path::Path, rel_path: &str| -> std::path::PathBuf {
        let p1 = base.join(rel_path);
        if p1.exists() { return p1; }
        let p2 = base.join("resources").join(rel_path);
        if p2.exists() { return p2; }
        p1
    };

    let dnstt_bin = resolve_tool(&resource_dir, if cfg!(target_os = "windows") { "dnstt-client.exe" } else { "dnstt-client" });
    let sing_box_bin = resolve_tool(&resource_dir, if cfg!(target_os = "windows") { "sing-box/sing-box.exe" } else { "sing-box/sing-box" });

    let _ = append_log(&logs_path, "info", &format!("Starting DNSTT client: {}", dnstt_bin.display()));

    // 2. Build resolver arguments
    let (resolver_flag, resolver_addr) = resolve_dnstt_resolver(&resolver);
    let _ = append_log(&logs_path, "info", &format!("DNSTT resolver: {} {}", resolver_flag, resolver_addr));

    // 3. Build the dnstt-client listen address (raw TCP tunnel to server SSH, NOT SOCKS)
    // dnstt-client tunnels TCP to the server's SSH port. We then run SSH -D through it.
    let dnstt_tunnel_port = proxy_port + 1; // internal port for dnstt TCP tunnel
    let dnstt_listen_addr = format!("127.0.0.1:{}", dnstt_tunnel_port);
    let _ = append_log(&logs_path, "info", &format!("DNSTT TCP tunnel will listen on {}", dnstt_listen_addr));

    // The final SOCKS proxy will be created by SSH -D on proxy_host:proxy_port
    let ssh_socks_addr = format!("{}:{}", proxy_host, proxy_port);
    let _ = append_log(&logs_path, "info", &format!("SSH SOCKS proxy will listen on {}", ssh_socks_addr));

    // 4. Spawn dnstt-client
    // dnstt-client -udp <resolver> -pubkey-hex <key> <domain> <listen_addr>
    let mut dnstt_cmd = Command::new(&dnstt_bin);
    dnstt_cmd
        .arg(resolver_flag)
        .arg(resolver_addr)
        .arg("-pubkey")
        .arg(&public_key)
        .arg(&domain)
        .arg(&dnstt_listen_addr)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        dnstt_cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let mut dnstt_child = dnstt_cmd.spawn().map_err(|e| {
        let err_msg = format!("CRITICAL: Failed to spawn dnstt-client: {}", e);
        let _ = append_log(&logs_path, "error", &err_msg);
        err_msg
    })?;

    let _ = append_log(&logs_path, "info", &format!("dnstt-client spawned (PID: {})", dnstt_child.id()));

    // Log dnstt-client output
    let dnstt_stdout = dnstt_child.stdout.take().unwrap();
    let dnstt_stderr = dnstt_child.stderr.take().unwrap();

    let logs_p1 = logs_path.clone();
    let dnstt_stdout_thread = thread::spawn(move || {
        let reader = BufReader::new(dnstt_stdout);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs_p1, "info", &format!("[DNSTT] {}", l));
                }
                Err(e) => {
                    let _ = append_log(&logs_p1, "warn", &format!("[DNSTT] stdout read error: {}", e));
                    break;
                }
                _ => {}
            }
        }
    });

    let logs_p2 = logs_path.clone();
    let dnstt_stderr_thread = thread::spawn(move || {
        let reader = BufReader::new(dnstt_stderr);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs_p2, "error", &format!("[DNSTT] {}", l));
                }
                Err(e) => {
                    let _ = append_log(&logs_p2, "warn", &format!("[DNSTT] stderr read error: {}", e));
                    break;
                }
                _ => {}
            }
        }
    });

    // Health check: wait briefly to see if dnstt-client survives
    thread::sleep(std::time::Duration::from_millis(800));
    match dnstt_child.try_wait() {
        Ok(Some(status)) => {
            let _ = dnstt_stdout_thread.join();
            let _ = dnstt_stderr_thread.join();
            let err_msg = format!("dnstt-client exited immediately with {}", status);
            let _ = append_log(&logs_path, "error", &err_msg);
            use tauri::Emitter;
            let _ = app.emit("vpn-disconnected", ());
            return Err(err_msg);
        }
        Ok(None) => {
            let _ = append_log(&logs_path, "info", "dnstt-client is running after health check");
        }
        Err(e) => {
            let _ = append_log(&logs_path, "warn", &format!("Could not check dnstt-client status: {}", e));
        }
    }

    let dnstt_pid = dnstt_child.id();
    let ssh_pid_holder: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let sing_box_pid: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let is_tun_mode = mode == "tun";

    // Watch dnstt-client exit in background — kill SSH and sing-box if dnstt dies
    let app_h_dnstt = app.clone();
    let logs_p_dnstt_exit = logs_path.clone();
    let sb_pid_for_dnstt = Arc::clone(&sing_box_pid);
    let ssh_pid_for_dnstt = Arc::clone(&ssh_pid_holder);
    thread::spawn(move || {
        let exit_status = dnstt_child.wait();
        let _ = dnstt_stdout_thread.join();
        let _ = dnstt_stderr_thread.join();
        match exit_status {
            Ok(status) => {
                let _ = append_log(&logs_p_dnstt_exit, "warn", &format!("dnstt-client exited with {}", status));
            }
            Err(e) => {
                let _ = append_log(&logs_p_dnstt_exit, "error", &format!("Failed to wait on dnstt-client: {}", e));
            }
        }
        // Kill SSH tunnel
        if let Some(sp) = *ssh_pid_for_dnstt.lock().unwrap() {
            let _ = append_log(&logs_p_dnstt_exit, "info", &format!("dnstt-client exited — killing SSH tunnel (PID {})", sp));
            kill_process(sp);
        }
        // In TUN mode, kill sing-box if it's still running
        if is_tun_mode {
            if let Some(sb_pid) = *sb_pid_for_dnstt.lock().unwrap() {
                let _ = append_log(&logs_p_dnstt_exit, "info", &format!("dnstt-client exited — killing companion Sing-box (PID {})", sb_pid));
                kill_process(sb_pid);
            }
        }
        use tauri::Emitter;
        let _ = app_h_dnstt.emit("vpn-disconnected", ());
    });

    // 5. Start SSH dynamic tunnel through the dnstt TCP tunnel
    // ssh -D <socks_addr> -N -p <dnstt_tunnel_port> -o StrictHostKeyChecking=no <ssh_user>@127.0.0.1
    // On Windows we use plink.exe; on Unix we use sshpass + ssh
    let _ = append_log(&logs_path, "info", &format!("Starting SSH tunnel: {} -> 127.0.0.1:{}", ssh_socks_addr, dnstt_tunnel_port));

    #[cfg(target_os = "windows")]
    let mut ssh_child = {
        use std::os::windows::process::CommandExt;
        // Use plink (PuTTY) on Windows for non-interactive password auth
        let plink_bin = resolve_tool(&resource_dir, "plink.exe");
        let _ = append_log(&logs_path, "info", &format!("Using plink: {}", plink_bin.display()));

        let mut cmd = Command::new(&plink_bin);
        cmd.arg("-ssh")
            .arg("-N")  // no shell
            .arg("-D").arg(&ssh_socks_addr)
            .arg("-P").arg(&dnstt_tunnel_port.to_string())
            .arg("-l").arg(&ssh_user)
            .arg("-pw").arg(&ssh_pass)
            .arg("-batch")  // non-interactive
            .arg("-hostkey").arg("*")  // accept any host key (internal tunnel)
            .arg("127.0.0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(0x08000000);
        cmd.spawn().map_err(|e| {
            let err_msg = format!("Failed to spawn plink SSH tunnel: {}", e);
            let _ = append_log(&logs_path, "error", &err_msg);
            kill_process(dnstt_pid);
            err_msg
        })?
    };

    #[cfg(not(target_os = "windows"))]
    let mut ssh_child = {
        // Use sshpass + ssh on Unix for non-interactive password auth
        let mut cmd = Command::new("sshpass");
        cmd.arg("-p").arg(&ssh_pass)
            .arg("ssh")
            .arg("-D").arg(&ssh_socks_addr)
            .arg("-N")  // no shell
            .arg("-p").arg(&dnstt_tunnel_port.to_string())
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg("UserKnownHostsFile=/dev/null")
            .arg("-o").arg("ServerAliveInterval=30")
            .arg("-o").arg("ServerAliveCountMax=3")
            .arg(&format!("{}@127.0.0.1", ssh_user))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.spawn().map_err(|e| {
            let err_msg = format!("Failed to spawn SSH tunnel (sshpass): {}", e);
            let _ = append_log(&logs_path, "error", &err_msg);
            kill_process(dnstt_pid);
            err_msg
        })?
    };

    let _ = append_log(&logs_path, "info", &format!("SSH tunnel spawned (PID: {})", ssh_child.id()));
    *ssh_pid_holder.lock().unwrap() = Some(ssh_child.id());

    // Log SSH output
    let ssh_stdout = ssh_child.stdout.take().unwrap();
    let ssh_stderr = ssh_child.stderr.take().unwrap();

    let logs_ssh1 = logs_path.clone();
    let ssh_stdout_thread = thread::spawn(move || {
        let reader = BufReader::new(ssh_stdout);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs_ssh1, "info", &format!("[SSH] {}", l));
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    let logs_ssh2 = logs_path.clone();
    let ssh_stderr_thread = thread::spawn(move || {
        let reader = BufReader::new(ssh_stderr);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    let _ = append_log(&logs_ssh2, "error", &format!("[SSH] {}", l));
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    // SSH health check
    thread::sleep(std::time::Duration::from_millis(1500));
    match ssh_child.try_wait() {
        Ok(Some(status)) => {
            let _ = ssh_stdout_thread.join();
            let _ = ssh_stderr_thread.join();
            let err_msg = format!("SSH tunnel exited immediately with {}", status);
            let _ = append_log(&logs_path, "error", &err_msg);
            kill_process(dnstt_pid);
            use tauri::Emitter;
            let _ = app.emit("vpn-disconnected", ());
            return Err(err_msg);
        }
        Ok(None) => {
            let _ = append_log(&logs_path, "info", "SSH tunnel is running after health check");
        }
        Err(e) => {
            let _ = append_log(&logs_path, "warn", &format!("Could not check SSH tunnel status: {}", e));
        }
    }

    let _ssh_pid = ssh_child.id();

    // Watch SSH exit in background — kill dnstt-client and sing-box if SSH dies
    let app_h_ssh = app.clone();
    let logs_p_ssh = logs_path.clone();
    let dnstt_pid_for_ssh = dnstt_pid;
    let sb_pid_for_ssh = Arc::clone(&sing_box_pid);
    thread::spawn(move || {
        let exit_status = ssh_child.wait();
        let _ = ssh_stdout_thread.join();
        let _ = ssh_stderr_thread.join();
        match exit_status {
            Ok(status) => {
                let _ = append_log(&logs_p_ssh, "warn", &format!("SSH tunnel exited with {}", status));
            }
            Err(e) => {
                let _ = append_log(&logs_p_ssh, "error", &format!("Failed to wait on SSH tunnel: {}", e));
            }
        }
        let _ = append_log(&logs_p_ssh, "info", &format!("SSH exited — killing dnstt-client (PID {})", dnstt_pid_for_ssh));
        kill_process(dnstt_pid_for_ssh);
        if let Some(sb_pid) = *sb_pid_for_ssh.lock().unwrap() {
            let _ = append_log(&logs_p_ssh, "info", &format!("SSH exited — killing Sing-box (PID {})", sb_pid));
            kill_process(sb_pid);
        }
        use tauri::Emitter;
        let _ = app_h_ssh.emit("vpn-disconnected", ());
    });

    // 6. If TUN mode, also start Sing-box bound to the SSH SOCKS proxy
    if mode == "tun" {
        let _ = append_log(&logs_path, "info", "DNSTT TUN mode: starting Sing-box routing engine...");

        // Generate sing-box config using dnstt's local proxy as outbound
        // We override proxy_host/proxy_port in the settings temporarily for config generation
        let settings_path = app_data_dir.join("settings.json");
        let original_settings = fs::read_to_string(&settings_path).unwrap_or_default();
        
        // Patch settings to point sing-box at SSH's SOCKS proxy
        if let Ok(mut settings_json) = serde_json::from_str::<serde_json::Value>(&original_settings) {
            settings_json["proxyHost"] = serde_json::Value::String(proxy_host.clone());
            settings_json["proxyPort"] = serde_json::Value::Number(serde_json::Number::from(proxy_port));
            let _ = fs::write(&settings_path, serde_json::to_string_pretty(&settings_json).unwrap_or_default());
        }

        let sb_config = generate_sing_box_config(app.clone(), server_ip).await?;

        // Restore original settings
        let _ = fs::write(&settings_path, &original_settings);

        let sb_config_path = app_data_dir.join("sing_box_config.json");
        fs::write(&sb_config_path, &sb_config).map_err(|e| e.to_string())?;

        let _ = append_log(&logs_path, "info", &format!("Starting Sing-box TUN engine: {}", sing_box_bin.display()));

        let mut sb_cmd = Command::new(&sing_box_bin);
        sb_cmd
            .arg("run")
            .arg("-c")
            .arg(&sb_config_path)
            .env("ENABLE_DEPRECATED_SPECIAL_OUTBOUNDS", "true")
            .env("ENABLE_DEPRECATED_TUN_ADDRESS_X", "true")
.env("ENABLE_DEPRECATED_WIREGUARD_OUTBOUND", "true")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            sb_cmd.creation_flags(0x08000000);
        }

        let mut sb_child = match sb_cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                let err_msg = format!("CRITICAL: Failed to spawn Sing-box for DNSTT TUN: {}", e);
                let _ = append_log(&logs_path, "error", &err_msg);
                let _ = append_log(&logs_path, "info", &format!("Killing dnstt-client (PID {}) because Sing-box failed", dnstt_pid));
                kill_process(dnstt_pid);
                use tauri::Emitter;
                let _ = app.emit("vpn-disconnected", ());
                return Err(err_msg);
            }
        };

        let _ = append_log(&logs_path, "info", &format!("Sing-box TUN spawned (PID: {}) for DNSTT", sb_child.id()));

        let sb_stdout = sb_child.stdout.take().unwrap();
        let sb_stderr = sb_child.stderr.take().unwrap();

        let logs_sb1 = logs_path.clone();
        let sb_stdout_thread = thread::spawn(move || {
            let reader = BufReader::new(sb_stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) if !l.trim().is_empty() => {
                        let _ = append_log(&logs_sb1, "info", &format!("[Sing-box/DNSTT] {}", l));
                    }
                    Err(e) => {
                        let _ = append_log(&logs_sb1, "warn", &format!("[Sing-box/DNSTT] stdout error: {}", e));
                        break;
                    }
                    _ => {}
                }
            }
        });

        let logs_sb2 = logs_path.clone();
        let sb_stderr_thread = thread::spawn(move || {
            let reader = BufReader::new(sb_stderr);
            for line in reader.lines() {
                match line {
                    Ok(l) if !l.trim().is_empty() => {
                        let _ = append_log(&logs_sb2, "error", &format!("[Sing-box/DNSTT] {}", l));
                    }
                    Err(e) => {
                        let _ = append_log(&logs_sb2, "warn", &format!("[Sing-box/DNSTT] stderr error: {}", e));
                        break;
                    }
                    _ => {}
                }
            }
        });

        // Health check for sing-box
        thread::sleep(std::time::Duration::from_millis(500));
        match sb_child.try_wait() {
            Ok(Some(status)) => {
                let _ = sb_stdout_thread.join();
                let _ = sb_stderr_thread.join();
                let err_msg = format!("Sing-box (DNSTT TUN) exited immediately with {}", status);
                let _ = append_log(&logs_path, "error", &err_msg);
                let _ = append_log(&logs_path, "info", &format!("Killing dnstt-client (PID {}) because Sing-box failed", dnstt_pid));
                kill_process(dnstt_pid);
                use tauri::Emitter;
                let _ = app.emit("vpn-disconnected", ());
                return Err(err_msg);
            }
            Ok(None) => {
                let _ = append_log(&logs_path, "info", "Sing-box (DNSTT TUN) is running after health check");
            }
            Err(e) => {
                let _ = append_log(&logs_path, "warn", &format!("Could not check Sing-box status: {}", e));
            }
        }

        *sing_box_pid.lock().unwrap() = Some(sb_child.id());

        // Watch sing-box exit — kill dnstt-client if sing-box dies
        let app_h_sb = app.clone();
        let logs_p_sb = logs_path.clone();
        let dnstt_pid_for_sb = dnstt_pid;
        thread::spawn(move || {
            let exit_status = sb_child.wait();
            let _ = sb_stdout_thread.join();
            let _ = sb_stderr_thread.join();
            match exit_status {
                Ok(status) => {
                    let _ = append_log(&logs_p_sb, "warn", &format!("Sing-box (DNSTT TUN) exited with {}", status));
                }
                Err(e) => {
                    let _ = append_log(&logs_p_sb, "error", &format!("Failed to wait on Sing-box: {}", e));
                }
            }
            let _ = append_log(&logs_p_sb, "info", &format!("Sing-box exited — killing dnstt-client (PID {})", dnstt_pid_for_sb));
            kill_process(dnstt_pid_for_sb);
            use tauri::Emitter;
            let _ = app_h_sb.emit("vpn-disconnected", ());
        });
    }

    let _ = append_log(&logs_path, "info", &format!("DNSTT connection established in {} mode", mode));
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
) -> Result<(), String> {
    use std::process::Command;
    use std::thread;

    let app_data_dir = app.path().app_data_dir().expect("Failed to get app dir");
    let logs_path = app_data_dir.join("candy.logs");

    let conn_name = format!("CandyConnect-{}", if protocol == "l2tp" { "L2TP" } else { "IKEv2" });
    let _ = append_log(&logs_path, "info", &format!("Starting native {} VPN: server={}, port={}, user={}", protocol.to_uppercase(), server, port, username));

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
        let create_cmd = if protocol == "l2tp" {
            format!(
                "Add-VpnConnection -Name '{}' -ServerAddress '{}' -TunnelType L2tp -L2tpPsk '{}' -AuthenticationMethod MSChapv2 -EncryptionLevel Optional -Force -RememberCredential",
                conn_name, server, psk
            )
        } else {
            // IKEv2
            format!(
                "Add-VpnConnection -Name '{}' -ServerAddress '{}' -TunnelType Ikev2 -AuthenticationMethod {} -EncryptionLevel Required -Force -RememberCredential",
                conn_name, server, if auth_method == "cert" { "MachineCertificate" } else { "EAP" }
            )
        };

        let _ = append_log(&logs_path, "info", &format!("Creating VPN profile: {}", conn_name));
        let create_output = Command::new("powershell")
            .args(&["-NoProfile", "-Command", &create_cmd])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| {
                let msg = format!("Failed to create VPN profile: {}", e);
                let _ = append_log(&logs_path, "error", &msg);
                msg
            })?;

        if !create_output.status.success() {
            let stderr = String::from_utf8_lossy(&create_output.stderr);
            let _ = append_log(&logs_path, "warn", &format!("VPN profile creation output: {}", stderr));
            // Non-fatal: profile might already exist
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
            let err_msg = format!("{} connection failed: {} {}", protocol.to_uppercase(), stdout.trim(), stderr.trim());
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
                let output = Command::new("rasdial")
                    .creation_flags(0x08000000)
                    .output();
                match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        if !stdout.contains(&conn_name_monitor) {
                            let _ = append_log(&logs_p, "warn", &format!("{} connection dropped", conn_name_monitor));
                            use tauri::Emitter;
                            let _ = app_h.emit("vpn-disconnected", ());
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
        } else {
            // IKEv2 via nmcli + strongswan
            let add_output = Command::new("nmcli")
                .args(&[
                    "connection", "add",
                    "con-name", &conn_name,
                    "type", "vpn",
                    "vpn-type", "strongswan",
                    "ifname", "--",
                    &format!("vpn.data"), &format!("address={}, certificate=ignore, encap=no, esp=aes128-sha256, ike=aes256-sha256-modp2048, ipcomp=no, method={}, proposal=yes, virtual=yes",
                        server, if auth_method == "cert" { "cert" } else { "eap" }),
                    &format!("vpn.secrets"), &format!("password={}", password),
                    &format!("vpn.user-name"), &username,
                ])
                .output()
                .map_err(|e| {
                    let msg = format!("nmcli failed: {}. Is NetworkManager-strongswan installed?", e);
                    let _ = append_log(&logs_path, "error", &msg);
                    msg
                })?;

            if !add_output.status.success() {
                let stderr = String::from_utf8_lossy(&add_output.stderr);
                let err_msg = format!("IKEv2 connection creation failed: {}", stderr.trim());
                let _ = append_log(&logs_path, "error", &err_msg);
                return Err(err_msg);
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
                let output = Command::new("nmcli")
                    .args(&["-t", "-f", "NAME,TYPE", "connection", "show", "--active"])
                    .output();
                match output {
                    Ok(o) => {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        if !stdout.contains(&conn_name_monitor) {
                            let _ = append_log(&logs_p, "warn", &format!("{} connection dropped", conn_name_monitor));
                            use tauri::Emitter;
                            let _ = app_h.emit("vpn-disconnected", ());
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
            // IKEv2 via scutil profiles
            let _ = append_log(&logs_path, "info", "macOS IKEv2: creating VPN profile via scutil...");
            
            let profile_plist = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>IKEv2</key>
            <dict>
                <key>RemoteAddress</key>
                <string>{}</string>
                <key>AuthenticationMethod</key>
                <string>{}</string>
                <key>ExtendedAuthEnabled</key>
                <true/>
                <key>AuthName</key>
                <string>{}</string>
                <key>AuthPassword</key>
                <string>{}</string>
            </dict>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>VPNType</key>
            <string>IKEv2</string>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>{}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
</dict>
</plist>"#, server, if auth_method == "cert" { "Certificate" } else { "None" }, username, password, conn_name);

            let profile_path = app_data_dir.join("ikev2_profile.mobileconfig");
            std::fs::write(&profile_path, &profile_plist).map_err(|e| e.to_string())?;

            let install = Command::new("open")
                .arg(&profile_path)
                .output()
                .map_err(|e| format!("Failed to install IKEv2 profile: {}", e))?;

            let _ = append_log(&logs_path, "info", "IKEv2 profile opened for installation. User needs to approve in System Preferences.");
        }

        // Monitor for macOS
        let app_h = app.clone();
        let logs_p = logs_path.clone();
        let conn_name_monitor = conn_name.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(std::time::Duration::from_secs(3));
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
                                use tauri::Emitter;
                                let _ = app_h.emit("vpn-disconnected", ());
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
async fn stop_vpn() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill").args(&["/F", "/IM", "xray.exe", "/T"]).creation_flags(0x08000000).spawn();
        let _ = Command::new("taskkill").args(&["/F", "/IM", "sing-box.exe", "/T"]).creation_flags(0x08000000).spawn();
        let _ = Command::new("taskkill").args(&["/F", "/IM", "dnstt-client.exe", "/T"]).creation_flags(0x08000000).spawn();
        let _ = Command::new("taskkill").args(&["/F", "/IM", "plink.exe", "/T"]).creation_flags(0x08000000).spawn();
        // Disconnect native L2TP/IKEv2 VPN connections
        let _ = Command::new("rasdial").args(&["CandyConnect-L2TP", "/DISCONNECT"]).creation_flags(0x08000000).output();
        let _ = Command::new("rasdial").args(&["CandyConnect-IKEv2", "/DISCONNECT"]).creation_flags(0x08000000).output();
        let _ = Command::new("powershell").args(&["-NoProfile", "-Command", "Remove-VpnConnection -Name 'CandyConnect-L2TP' -Force -ErrorAction SilentlyContinue"]).creation_flags(0x08000000).output();
        let _ = Command::new("powershell").args(&["-NoProfile", "-Command", "Remove-VpnConnection -Name 'CandyConnect-IKEv2' -Force -ErrorAction SilentlyContinue"]).creation_flags(0x08000000).output();
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("xray").spawn();
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("sing-box").spawn();
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("dnstt-client").spawn();
        let _ = Command::new("pkill").arg("-9").arg("-f").arg("sshpass.*ssh.*-D").spawn();
        // Disconnect native L2TP/IKEv2 VPN connections
        let _ = Command::new("nmcli").args(&["connection", "down", "CandyConnect-L2TP"]).output();
        let _ = Command::new("nmcli").args(&["connection", "down", "CandyConnect-IKEv2"]).output();
        let _ = Command::new("nmcli").args(&["connection", "delete", "CandyConnect-L2TP"]).output();
        let _ = Command::new("nmcli").args(&["connection", "delete", "CandyConnect-IKEv2"]).output();
        // Also kill xl2tpd if running as fallback
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("xl2tpd").spawn();
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("xray").spawn();
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("sing-box").spawn();
        let _ = Command::new("pkill").arg("-9").arg("-x").arg("dnstt-client").spawn();
        let _ = Command::new("pkill").arg("-9").arg("-f").arg("sshpass.*ssh.*-D").spawn();
        // Disconnect native VPN
        let _ = Command::new("networksetup").args(&["-disconnectpppoeservice", "CandyConnect-L2TP"]).output();
        let _ = Command::new("scutil").args(&["--nc", "stop", "CandyConnect-IKEv2"]).output();
    }
    Ok(())
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
    let app_dir = app.path().resource_dir().unwrap_or_else(|_| std::env::current_dir().unwrap());
    
    // Check extra-tools subdirectories/files based on workflow structure
    let tools = vec![
        ("xray", if cfg!(target_os = "windows") { "xray/xray.exe" } else { "xray/xray" }),
        ("sing-box", if cfg!(target_os = "windows") { "sing-box/sing-box.exe" } else { "sing-box/sing-box" }),
        ("dnstt", if cfg!(target_os = "windows") { "dnstt-client.exe" } else { "dnstt-client" }),
    ];

    let resolve_tool_check = |base: &std::path::Path, rel_path: &str| -> bool {
        if base.join(rel_path).exists() { return true; }
        if base.join("resources").join(rel_path).exists() { return true; }
        false
    };

    for (name, path) in tools {
        if !resolve_tool_check(&app_dir, path) {
            missing.push(name.to_string());
        }
    }

    #[cfg(target_os = "windows")]
    {
        let ovpn_path = app_dir.join("openvpn/openvpn.exe");
        if !ovpn_path.exists() {
            missing.push("openvpn".to_string());
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

use std::sync::OnceLock;

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
    let n = name.trim_end_matches(':');
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
    .invoke_handler(tauri::generate_handler![measure_latency, check_system_executables, is_admin, restart_as_admin, generate_sing_box_config, start_vpn, start_dnstt, start_native_vpn, start_wireguard, start_openvpn, stop_vpn, write_log, get_network_stats, reset_network_session])
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
        _ => {}
    });
}
