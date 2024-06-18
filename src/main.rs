use std::env;
use std::path::Path;

use filecipher::*;

#[derive(Debug, Eq, PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
}

impl Mode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "encrypt"|"e" => Some(Self::Encrypt),
            "decrypt"|"d" => Some(Self::Decrypt),
            _ => None,
        }
    }
}

enum PathType {
    File,
    Directory,
    Other,
}

impl PathType {
    pub fn from_str(s: &str) -> Self {
        if Path::new(s).is_file() {
            Self::File
        } else if Path::new(s).is_dir() {
            Self::Directory
        } else {
            Self::Other
        }
    }
}

fn main() {
    let args = env::args().collect::<Vec<String>>();
    if args.len() != 3 {
        eprintln!("Usage: {} <encrypt|decrypt> <path>", args[0]);
        return;
    }
    
    let mode = Mode::from_str(&args[1]).expect("Invalid mode.");
    let path = &args[2];

    #[cfg(feature = "dev")]
    let pass = "password";
    #[cfg(not(feature = "dev"))]
    let pass = &rpassword::prompt_password("Enter password: ").unwrap()[..];
    #[cfg(not(feature = "dev"))]
    if mode == Mode::Encrypt {
        let confirm = &rpassword::prompt_password("Confirm password: ").unwrap()[..];
        if pass != confirm {
            eprintln!("Passwords do not match.");
            return;
        }
    }

    #[cfg(feature = "dev")]
    pretty_env_logger::init();

    let key = hash_password(pass);

    let path_type = PathType::from_str(path);

    match mode {
        Mode::Encrypt => match path_type {
            PathType::File => encrypt_file(&path, &key),
            PathType::Directory => encrypt_directory(&path, &key),
            PathType::Other => {
                eprintln!("Invalid path.");
                return;
            },
        },
        Mode::Decrypt => match path_type {
            PathType::File => decrypt_file(&path, &key),
            PathType::Directory => decrypt_directory(&path, &key),
            PathType::Other => {
                eprintln!("Invalid path.");
                return;
            },
        },
    }.unwrap();
}
