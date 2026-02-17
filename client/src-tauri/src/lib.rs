use std::fs;
use tauri::Manager;

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
            "proxyPort": 1080,
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
            "splitTunneling": false
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
        fs::write(&logs_path, "[]")?;
        log::info!("Created default candy.logs");
    }

    log::info!("App data directory: {:?}", app_data_dir);
    Ok(())
}

#[tauri::command]
async fn measure_latency(host: String) -> Result<u64, String> {
    use std::process::Command;
    
    // Determine the ping command based on the OS
    let mut cmd = if cfg!(target_os = "windows") {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new("ping");
        c.args(&["-n", "1", "-w", "2000", &host]);
        // 0x08000000 is CREATE_NO_WINDOW
        c.creation_flags(0x08000000);
        c
    } else {
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

      Ok(())
    })
    .invoke_handler(tauri::generate_handler![measure_latency])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
