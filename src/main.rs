mod del;

use std::env;
use std::path::PathBuf;
use del::{
    load_protected_config, save_protected_config,
    is_path_protected, delete_path
};

fn expand_tilde_custom(path: &str) -> PathBuf {
    if path.starts_with("~\\") || path.starts_with("~/") {
        let current_dir = env::current_dir().expect("Failed to get current dir");
        return current_dir.join(&path[2..]);
    }
    PathBuf::from(path)
}

fn print_usage_and_exit() {
    eprintln!("Usage:");
    eprintln!("  rm.exe [-rfs | -t] FOLDER");
    eprintln!("  rm.exe -a FOLDER       # Protect folder");
    eprintln!("  rm.exe -d FOLDER       # Unprotect folder");
    eprintln!("  rm.exe --add-admin");
    eprintln!("  rm.exe --login");
    eprintln!("  rm.exe --enable-2FA");
    eprintln!("  rm.exe --disable-2FA");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        print_usage_and_exit();
    }

    let mut recursive = false;
    let mut force = false;
    let mut silent = false;
    let mut terminate = false;
    let mut mode: Option<&str> = None;

    // Simple mode commands
    match args.get(1).map(|s| s.as_str()) {
        Some("--add-admin") => {
            let mut config = load_protected_config();
            del::admin_register(&mut config, None);
            return;
        }
        Some("--login") => {
            let config = load_protected_config();
            let _ = del::admin_login(&config);
            return;
        }
        Some("--enable-2FA") => {
            let mut config = load_protected_config();
            del::set_2fa(&mut config, true);
            return;
        }
        Some("--disable-2FA") => {
            let mut config = load_protected_config();
            del::set_2fa(&mut config, false);
            return;
        }
        _ => {}
    }

    // Handle protect/unprotect before regular flags
    if args.len() == 3 && args[1] == "-a" {
        let folder = expand_tilde_custom(&args[2]);
        let mut config = load_protected_config();

        if del::current_admin().is_none() {
            eprintln!("❌ You must be logged in as an admin to protect folders.");
            std::process::exit(1);
        }

        let canon = folder.canonicalize().unwrap_or(folder);
        let canon_str = canon.to_string_lossy().to_string();

        if config.protected.iter().any(|p| p == &canon_str) {
            println!("🔒 Folder already protected.");
        } else {
            config.protected.push(canon_str.clone());
            save_protected_config(&config);
            println!("✅ Protected folder added: {}", canon_str);
        }
        return;
    }

    if args.len() == 3 && args[1] == "-d" {
        let folder = expand_tilde_custom(&args[2]);
        let mut config = load_protected_config();

        if del::current_admin().is_none() {
            eprintln!("❌ You must be logged in as an admin to unprotect folders.");
            std::process::exit(1);
        }

        del::unprotect_folder(&mut config, &folder);
        return;
    }

    // Parse standard flags and folder
    let mut positional_args = Vec::new();

    for arg in args.iter().skip(1) {
        if arg.starts_with('-') && arg.len() > 2 {
            for ch in arg.chars().skip(1) {
                match ch {
                    'r' => recursive = true,
                    'f' => force = true,
                    's' => silent = true,
                    't' => terminate = true,
                    _ => {
                        eprintln!("Unknown flag: {}", ch);
                        print_usage_and_exit();
                    }
                }
            }
        } else if arg.starts_with('-') {
            match arg.as_str() {
                "-r" => recursive = true,
                "-f" => force = true,
                "-s" => silent = true,
                "-t" => terminate = true,
                _ => {
                    eprintln!("Unknown flag: {}", arg);
                    print_usage_and_exit();
                }
            }
        } else {
            positional_args.push(arg.clone());
        }
    }

    if positional_args.len() != 1 {
        eprintln!("Error: Expected exactly one folder argument.");
        print_usage_and_exit();
    }

    let mut config = load_protected_config();
    let folder = expand_tilde_custom(&positional_args[0]);

    if is_path_protected(&folder) {
        eprintln!("Error: This folder is protected and cannot be deleted.");
        std::process::exit(1);
    }

    if let Err(e) = delete_path(&folder, recursive, force, silent, terminate) {
        eprintln!("Deletion failed: {}", e);
        if !force {
            std::process::exit(1);
        }
    }

    if !silent {
        println!("Deleted: {:?}", folder);
    }
}
