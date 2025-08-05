use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path};
use std::process;
use std::{thread, time};
use serde::{Deserialize, Serialize};
use glob::Pattern;
use rpassword::prompt_password;
use sha2::{Sha256, Digest};
use hex::encode;
use sysinfo::System;
use rand::{thread_rng, Rng};
// For email sending
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;

#[derive(Serialize, Deserialize)] // <-- Add this
pub struct AdminInfo {
    pub hashed_password: String,
    pub two_factor_enabled: bool,
}

#[derive(Serialize, Deserialize)]  // ✅ Add this
pub struct ProtectedConfig {
    pub admins: HashMap<String, AdminInfo>,
    pub protected: Vec<String>,
}

pub fn load_protected_config() -> ProtectedConfig {
    if let Ok(mut file) = File::open("Protected.json") {
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Could not read Protected.json");
        serde_json::from_str(&contents).expect("Invalid JSON in Protected.json")
    } else {
        ProtectedConfig {
            admins: HashMap::new(),
            protected: vec!["C:\\".into(), "C:\\Windows\\**".into()],
        }
    }
}

pub fn save_protected_config(config: &ProtectedConfig) {
    let json = serde_json::to_string_pretty(config).expect("Failed to serialize config");
    fs::write("Protected.json", json).expect("Failed to write Protected.json");
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    encode(hasher.finalize())
}

#[derive(Deserialize, Serialize)]
pub struct ProtectedConfig2 {
    pub admins: HashMap<String, AdminInfo>,
    pub protected: Vec<String>,
}

fn load_protected_config2() -> anyhow::Result<ProtectedConfig2> {
    let json_str = fs::read_to_string("Protected.json")?;
    let config: ProtectedConfig2 = serde_json::from_str(&json_str)?;
    Ok(config)
}

pub fn is_path_protected(path: &Path) -> bool {
    let canon_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let path_str = canon_path.to_string_lossy().to_lowercase();

    // Try loading config inside the function
    let config = load_protected_config2().unwrap_or_else(|_| ProtectedConfig2 {
        admins: HashMap::new(),
        protected: vec!["C:\\".into(), "C:\\Windows\\**".into()],
    });

    let hardcoded = ["c:\\", "c:\\windows\\**"];

    for pattern in hardcoded.iter().map(|s| *s).chain(config.protected.iter().map(|s| s.as_str())) {
        if let Ok(glob_pattern) = Pattern::new(&pattern.to_lowercase()) {
            if glob_pattern.matches(&path_str) {
                return true;
            }
        }
    }

    false
}

pub fn delete_path(
    path: &Path,
    recursive: bool,
    force: bool,
    silent: bool,
    terminate: bool,
) -> io::Result<()> {
    if terminate {
        try_terminate_locking_processes(path);
        thread::sleep(time::Duration::from_millis(300));
    }
    if !is_path_protected(path) || force {
        if path.is_dir() {
            if recursive {
                fs::remove_dir_all(path).or_else(|e| {
                    if terminate {
                        thread::sleep(time::Duration::from_millis(300));
                        fs::remove_dir_all(path)
                    } else {
                        Err(e)
                    }
                })?;
            } else {
                if !silent {
                    eprintln!("❌ {} is a directory. Use -r to delete recursively.", path.display());
                }
            }
        } else if path.is_file() {
            fs::remove_file(path)?;
        } else {
            if !silent {
                eprintln!("⚠️ {} does not exist.", path.display());
            } 
        }
    }
    Ok(())
}

use sysinfo::{SystemExt, ProcessExt};
use sysinfo::PidExt;

pub fn try_terminate_locking_processes(path: &Path) {
    println!("🔍 Checking for processes locking: {}", path.display());

    let mut sys = System::new_all();
    sys.refresh_all();

    let target = path.to_string_lossy().to_lowercase();
    let current_pid = process::id();

    for proc in sys.processes().values() {
        if proc.pid().as_u32() == current_pid {
            continue;
        }

        if proc.cmd().iter().any(|arg| arg.to_lowercase().contains(&target)) {
            println!("⚠️ Found process: {} (PID {})", proc.name(), proc.pid());

            if !proc.kill() {
                println!("❌ Failed to terminate: {}", proc.name());
            } else {
                println!("✅ Terminated: {}", proc.name());
            }
        }
    }
}

fn generate_code() -> String {
    let mut rng = thread_rng();
    format!("{:06}", rng.gen_range(0..=999999))
}

fn send_2fa_code(email: &str, code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let email = Message::builder()
        .from("noreply@yourdomain.com".parse()?)
        .to(email.parse()?)
        .subject("Your 2FA code")
        .body(format!("Your 2FA code is: {}", code))?;

    let creds = Credentials::new("your_smtp_user".into(), "your_smtp_pass".into());

    let mailer = SmtpTransport::relay("smtp.yourdomain.com")?
        .credentials(creds)
        .build();

    mailer.send(&email)?;
    Ok(())
}

pub fn admin_login(config: &ProtectedConfig) -> Option<String> {
    println!("🔐 Admin login required.");
    print!("Email: ");
    io::stdout().flush().unwrap();

    let mut email = String::new();
    io::stdin().read_line(&mut email).unwrap();
    let email = email.trim();

    let password = prompt_password("Password: ").unwrap();
    let hashed = hash_password(&password);

    match config.admins.get(email) {
        Some(AdminInfo {
            hashed_password,
            two_factor_enabled,
        }) if hashed_password == &hashed => {
            // Check for 2FA bypass via env var
            let bypass_2fa = std::env::var("RM_BYPASS_2FA").unwrap_or_default() == "1";

            if *two_factor_enabled && !bypass_2fa {
                const MAX_2FA_RETRIES: u8 = 3;
                let code = generate_code();

                let mut sent = false;
                for attempt in 1..=MAX_2FA_RETRIES {
                    match send_2fa_code(email, &code) {
                        Ok(_) => {
                            sent = true;
                            break;
                        }
                        Err(e) => {
                            eprintln!("⚠️ 2FA email send failed (attempt {}/{}): {}", attempt, MAX_2FA_RETRIES, e);
                            if attempt < MAX_2FA_RETRIES {
                                thread::sleep(time::Duration::from_secs(2));
                            }
                        }
                    }
                }

                if !sent {
                    eprintln!("❌ Could not send 2FA email after {} attempts. Aborting login.", MAX_2FA_RETRIES);
                    return None;
                }

                print!("Enter 2FA code sent to your email: ");
                io::stdout().flush().unwrap();
                let mut entered = String::new();
                io::stdin().read_line(&mut entered).unwrap();

                if entered.trim() != code {
                    eprintln!("❌ Invalid 2FA code.");
                    return None;
                }
            } else if *two_factor_enabled && bypass_2fa {
                println!("⚠️ 2FA is ENABLED, but bypass is active via RM_BYPASS_2FA.");
            }

            fs::write("session.json", format!("{{\"email\": \"{}\"}}", email)).ok();
            println!("✅ Logged in as admin: {}", email);
            Some(email.to_string())
        }
        _ => {
            eprintln!("❌ Invalid credentials.");
            None
        }
    }
}


pub fn admin_register(config: &mut ProtectedConfig, _: Option<&str>) {
    if config.admins.is_empty() {
        println!("🔐 No admins found. Creating first admin.");
    } else {
        println!("👤 Register new admin (existing admin approval required)");
        let approver = admin_login(config);
        if approver.is_none() {
            eprintln!("❌ Registration failed.");
            return;
        }
    }

    print!("New admin email: ");
    io::stdout().flush().unwrap();
    let mut new_email = String::new();
    io::stdin().read_line(&mut new_email).unwrap();
    let new_email = new_email.trim().to_string();

    if config.admins.contains_key(&new_email) {
        eprintln!("⚠️ Admin already exists.");
        return;
    }

    let new_pass = prompt_password("New admin password: ").unwrap();
    let confirm_pass = prompt_password("Confirm password: ").unwrap();

    if new_pass != confirm_pass {
        eprintln!("❌ Passwords do not match.");
        return;
    }

    config.admins.insert(new_email.clone(), AdminInfo {
        hashed_password: hash_password(&new_pass),
        two_factor_enabled: false,
    });

    save_protected_config(config);
    println!("✅ Admin '{}' registered successfully.", new_email);
}

pub fn current_admin() -> Option<String> {
    if let Ok(mut file) = fs::File::open("session.json") {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
                return json["email"].as_str().map(|s| s.to_string());
            }
        }
    }
    None
}

pub fn set_2fa(config: &mut ProtectedConfig, enable: bool) {
    if let Some(admin) = current_admin() {
        if let Some(info) = config.admins.get_mut(&admin) {
            info.two_factor_enabled = enable;
            save_protected_config(config);
            if enable {
                println!("✅ 2FA has been ENABLED for '{}'", admin);
            } else {
                println!("✅ 2FA has been DISABLED for '{}'", admin);
            }
        } else {
            println!("❌ Admin '{}' not found in config.", admin);
        }
    } else {
        println!("❌ No admin currently logged in.");
    }
}

pub fn unprotect_folder(config: &mut ProtectedConfig, folder: &Path) {
    let canon = folder.canonicalize().unwrap_or_else(|_| folder.to_path_buf());
    let canon_str = canon.to_string_lossy().to_string();

    if let Some(pos) = config.protected.iter().position(|p| p == &canon_str) {
        config.protected.remove(pos);
        save_protected_config(config);
        println!("🧹 Unprotected folder removed: {}", canon_str);
    } else {
        println!("⚠️ Folder was not protected.");
    }
}
