//extern crate gcc;

use std::process::Command;
use std::env;
use std::path::Path;

fn llvm_config_get(llvm_config: &str, config: &str) -> String {
    let cmd = Command::new(llvm_config).arg(config).output().unwrap();
    String::from_utf8(cmd.stdout).unwrap().trim().to_string()
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let llvm_config = {
        if let Ok(v) = env::var("LLVM_CONFIG") {
            v
        } else {
            "llvm-config-3.8".to_string()
        }
    };

    macro_rules! get_flags {
        ($arg:expr) => (
            {
                let llvm_flags = llvm_config_get(&llvm_config, $arg);
                let llvm_flags_args: Vec<String> =
                    llvm_flags
                    .split_whitespace()
                    .map(|s| s.to_owned())
                    .collect();
                llvm_flags_args
            }
            )
    }

    let llvm_cxxflags = get_flags!("--cxxflags");
    let llvm_ldflags = get_flags!("--ldflags");
    let llvm_libs = get_flags!("--libs");
    let llvm_syslibs = get_flags!("--system-libs");

    let out_obj = format!("{}/assemble.o", out_dir);
    let out_lib = format!("{}/libassemble.a", out_dir);

    if !Command::new("g++").args(&["src/c/assemble.cc", "-g", "-c", "-fPIC", "-o"])
        .arg(&out_obj)
        .args(&llvm_cxxflags)
        .status().unwrap().success()
    {
        panic!("g++ failed to build");
    }

    if !Command::new("ar").args(&["crus", &out_lib, &out_obj])
        .current_dir(&Path::new(&out_dir))
        .status().unwrap().success()
    {
        panic!("ar failed to build");
    }

    print!("cargo:rustc-flags=");
    for path in llvm_ldflags {
        print!("-L native={} ", &path[2..]);
    }
    for lib in llvm_libs {
        print!("-l {} ", &lib[2..]);
    }
    for lib in llvm_syslibs {
        print!("-l {} ", &lib[2..]);
    }

    println!("");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static={}", "assemble");
}
