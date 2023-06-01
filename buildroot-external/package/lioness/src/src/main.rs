// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2023 SUSE LLC

use std::fs;
use std::fs::File;
use std::io::SeekFrom;
use std::io::{self, prelude::*};
use std::io::Cursor;
use std::io::{Error, ErrorKind};
use std::{thread, time};
use std::env;
use std::os::unix;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command,Stdio};
use std::path::PathBuf;

use fatfs::{FileSystem, FsOptions};
//
// TODO these build env vars should become mandatory for each board
pub const STATUS_LED_PATH: &'static str = match option_env!("STATUS_LED_PATH") {
    Some(v) => v,
    None => "/sys/class/leds/nanopi:blue:status",
};

pub const MUSB_UDC: &'static str = match option_env!("MUSB_UDC") {
    Some(v) => v,
    None => "musb-hdrc.1.auto",
};

fn usage() {
    println!("Usage: lioness <fatfs-device> <configfs-path>");
}

struct Conf {
    key: Vec<u8>,
    salt: Vec<u8>,
    snapshot: bool,
    compression: bool,
    exfat_format: bool,
}

fn from_bool(v: &[u8]) -> Option<bool> {
    return match v {
        [ b't', b'r', b'u', b'e' ] => Some(true),
        [ b'f', b'a', b'l', b's', b'e' ] => Some(false),
        _ => {
            println!("invalid bool val {}", String::from_utf8_lossy(v));
            None
        },
    };  // TODO macroize?
}

fn parse_digested_conf(conf_buf: &[u8]) -> Option<Conf> {
    let mut key: Option<Vec<u8>> = None;
    let mut salt: Option<Vec<u8>> = None;
    let (mut snap, mut compr, mut format) = (None, None, None);
    let mut payload_seen = false;

    // XXX not standard ini! We strictly require the format that was written by
    // lioness.html
    // TODO would be nice if we could construct these arrays at compile time
    // from the corresponding "key = " strings. For now they're vim compiled
    // via: s/\(.\)/b'\1', /g
    for l in conf_buf.split(|c| matches!(c, b'\n')) {
        //println!("tok {:?}", String::from_utf8_lossy(&l));
        match l {
            [b'p', b'a', b'y', b'l', b'o', b'a', b'd', .. ] => {
                // already checked header, just confirm one instance
                if payload_seen {
                    println!("invalid: payload set multiple times");
                    return None;
                }
                payload_seen = true;
            }
            [b'k', b'e', b'y', b' ', b'=', b' ', val @ .. ] => {
                if key.is_some() {
                    println!("invalid: key set multiple times");
                    return None;
                }
                if val.len() != 64 {
                    println!("invalid: key length {}", val.len());
                    return None;
                }
                key = Some(val.to_vec());
            },
            [b's', b'a', b'l', b't', b' ', b'=', b' ', val @ .. ]  => {
                if salt.is_some() {
                    println!("invalid: salt set multiple times");
                    return None;
                }
                if val.len() != 48 {
                    println!("invalid: salt length {}", val.len());
                    return None;
                }
                salt = Some(val.to_vec());
            },
            [b's', b'n', b'a', b'p', b's', b'h', b'o', b't',
             b' ', b'=', b' ', val @ .. ] => {
                if snap.is_some() {
                    println!("invalid: snap set multiple times");
                    return None;
                }
                snap = match from_bool(val) {
                    Some(b) => Some(b),
                    None => return None,
                };
            },
            [b'c', b'o', b'm', b'p', b'r', b'e', b's', b's', b'i', b'o', b'n',
             b' ', b'=', b' ', val @ .. ] => {
                if compr.is_some() {
                    println!("invalid: compr set multiple times");
                    return None;
                }
                compr = match from_bool(val) {
                    Some(b) => Some(b),
                    None => return None,
                };
            },
            [b'f', b'o', b'r', b'm', b'a', b't', b' ', b'=', b' ', val @ .. ] => {
                if format.is_some() {
                    println!("invalid: format set multiple times");
                    return None;
                }
                format = match from_bool(val) {
                    Some(b) => Some(b),
                    None => return None,
                };
            },
            [ unknown @ .. ] => {
                println!("unexpected config entry: {}", String::from_utf8_lossy(unknown));
                return None;
            },
        }
    }
    if key.is_none() || salt.is_none() || snap.is_none() || compr.is_none() || format.is_none() {
        println!("not all expected config keys present");
        return None;
    }

    Some(Conf{
            key: key.unwrap(),
            salt: salt.unwrap(),
            snapshot: snap.unwrap(),
            compression: compr.unwrap(),
            exfat_format: format.unwrap()
        })
}

fn validate_retry(retry_tout: &mut Option<time::Duration>) -> bool {
    if retry_tout.is_none() {
        *retry_tout = Some(time::Duration::from_secs(60 * 60)); // first loop
        return true;
    }

    let sleep_duration = time::Duration::from_secs(1);
    thread::sleep(sleep_duration);
    return match retry_tout.unwrap().checked_sub(sleep_duration) {
        Some(d) => {
            *retry_tout = Some(d);
            true
        },
        None => false,
    };
}

// initialise FAT filesystem on fatfs_dev and return the canonicalized path
fn init_fs(fatfs_dev: &str) -> io::Result<PathBuf> {
    let f = fs::OpenOptions::new().write(true)
                                  .read(true)
                                  .create(true)
                                  .truncate(false)
                                  .open(fatfs_dev)?;
    f.set_len(4 * 1024 * 1024)?;
    let opts = fatfs::FormatVolumeOptions::new().volume_label(*b"Lioness\0\0\0\0");
    fatfs::format_volume(&f, opts)?;
    let fs = FileSystem::new(&f, FsOptions::new())?;

    let root_dir = fs.root_dir();
    // avoid Android creating one automatically. TODO: flag hidden
    root_dir.create_dir("LOST.DIR")?;

    let mut file = root_dir.create_file("setup.html")?;
    file.write_all(include_bytes!("./setup.html"))?;
    f.sync_data()?;

    PathBuf::from(fatfs_dev).canonicalize()
}

fn init_musb(fatfs_dev: &PathBuf, configfs: &str) -> io::Result<PathBuf> {
    // TODO perform configfs mount if needed
    let cfs_usb = PathBuf::from(configfs).join("usb_gadget/confs");
    fs::create_dir_all(cfs_usb.join("strings/0x409"))?;
    fs::create_dir_all(cfs_usb.join("functions/mass_storage.usb0/lun.0"))?;
    fs::create_dir_all(cfs_usb.join("configs/c.1/strings/0x409"))?;
    fs::write(cfs_usb.join("idVendor"), b"0x1d6b")?;    // Linux Foundation
    fs::write(cfs_usb.join("idProduct"),
        b"0x1d6b")?;    // Multifunction Composite Gadget
    fs::write(cfs_usb.join("bcdDevice"), b"0x0090")?;   // v0.9.0

    fs::write(cfs_usb.join("strings/0x409/manufacturer"), b"openSUSE")?;
    fs::write(cfs_usb.join("strings/0x409/product"), b"lioness config")?;

    // convert (hopefully) unique SoC SID to hex for use as serial number
    match File::open("/sys/bus/nvmem/devices/sunxi-sid0/nvmem") {
        Ok(mut sid) => {
            let mut sidbuf = vec![0; 16];
            sid.read_exact(&mut sidbuf)?;
            let hex: String = sidbuf.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>().join("");
            fs::write(cfs_usb.join("strings/0x409/serialnumber"), hex)?;
        },
        Err(_) => println!("sunxi nvmem not available for serialnumber"),
    };

    fs::write(cfs_usb.join("functions/mass_storage.usb0/stall"), b"1")?;
    fs::write(cfs_usb.join("functions/mass_storage.usb0/lun.0/cdrom"), b"0")?;
    fs::write(cfs_usb.join("functions/mass_storage.usb0/lun.0/ro"), b"0")?;
    fs::write(cfs_usb.join("functions/mass_storage.usb0/lun.0/nofua"), b"0")?;
    fs::write(cfs_usb.join("functions/mass_storage.usb0/lun.0/removable"),
              b"1")?;
    fs::write(cfs_usb.join("functions/mass_storage.usb0/lun.0/file"),
              fatfs_dev.as_os_str().as_bytes())?;
    fs::write(cfs_usb.join("configs/c.1/strings/0x409/configuration"),
              b"Config 1: mass-storage")?;
    fs::write(cfs_usb.join("configs/c.1/MaxPower"), b"500")?;
    match unix::fs::symlink(cfs_usb.join("functions/mass_storage.usb0"),
                            cfs_usb.join("configs/c.1/mass_storage.usb0")) {
        Err(e) => {
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(e);
            }
        },
        Ok(_) => (),
    };
    fs::write(cfs_usb.join("UDC"), MUSB_UDC.as_bytes())?;

    cfs_usb.join("functions/mass_storage.usb0/lun.0").canonicalize()
}

fn main() -> io::Result<()> {
    if env::args().len() != 3 {
        usage();
        return Err(Error::from(ErrorKind::InvalidInput));
    }
    let fatfs_path = init_fs(&env::args().nth(1).unwrap())?;
    let cfs_usb_lun = init_musb(&fatfs_path, &env::args().nth(2).unwrap())?;
    let _ = fs::write(PathBuf::from(STATUS_LED_PATH).join("trigger"), b"heartbeat");

    let mut f = match File::open(&fatfs_path) {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to open device {}: {}", fatfs_path.display(), e);
            return Err(e);
        },
    };
    let mut retry_tout: Option<time::Duration> = None;
    let mut validated_conf: Option<Conf> = None;

    while validated_conf.is_none() && validate_retry(&mut retry_tout) {
        let mut contents = vec![0; 4*1024*1024];

        f.seek(SeekFrom::Start(0))?;
        f.read_exact(&mut contents)?;
        // TODO: check for block layer write while reading
        let cur: Cursor<Vec<u8>> = Cursor::new(contents);
        let fat = match FileSystem::new(cur, FsOptions::new()) {
            Ok(fat) => fat,
            Err(e) => {
                println!("retry due to FS error: {}", e);
                continue;
            },
        };
        let root_dir = fat.root_dir();
        // /lioness.txt is currently used as the config file path, as Android
        // automatically adds a ".txt" extension to any download flagged
        // "text/plain".
        let mut file = match root_dir.open_file("lioness.txt") {
            Ok(f) => f,
            Err(e) => {
                println!("retry due to FS open error: {}", e);
                continue;
            },
        };
        let mut buf = vec![];
        match file.read_to_end(&mut buf) {
            Ok(_) => {
                // len varies due to true / false
            },
            Err(e) => {
                println!("retry due to FS read error: {}", e);
                continue;
            },
        };

        let payload_hdr = b"payload = LionessFirstboot1";
        if buf.starts_with(payload_hdr) {
            println!("payload header valid");
        } else {
            println!("retry due to invalid conf payload header");
            continue;
        }

        // XXX not split_at() from end, so just rotate and take it from start
		let digest_pfx = b"digest = SHA-256:";
        let digest_len = digest_pfx.len() + 64;
        if buf.len() < digest_len {
            println!("retry due to invalid conf length");
            continue;
        }
        buf.rotate_right(digest_len);
        let (digest, conf) = buf.split_at(digest_len);
        if digest.starts_with(digest_pfx) {
            println!("digest prefix valid");
        } else {
            println!("retry due to invalid digest prefix");
            continue;
        }

        let sha256 = match digest.get(digest_pfx.len()..) {
            Some(v) => {
                if !v.is_ascii() {
                    println!("retry due to invalid digest content");
                    continue;
                }
                v
            },
            None => {
                println!("retry due to invalid digest content");
                continue;
            }
        };

        // TODO optimize and use kernl AF_ALG to calculate checksum
        let mut proc = Command::new("sha256sum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to execute process");
        {
            let mut stdin = proc.stdin.take().unwrap();
            stdin.write_all(conf).expect("Failed to write to stdin");
        }
        let output = proc.wait_with_output().unwrap();

        if &output.stdout[..sha256.len()] != sha256 {
            println!("retry due to digest mismatch: {} vs calculated {}",
                     String::from_utf8_lossy(sha256),
                     String::from_utf8_lossy(&output.stdout));
            continue;
        }
        // remove trailing newline before now-trimmed digest
        let conf_notrail = match conf.split_last() {
            Some((l, e)) => {
                if l != &b'\n' {
                    return Err(Error::from(ErrorKind::InvalidData));
                }
                e
            },
            None => return Err(Error::from(ErrorKind::InvalidData)),
        };

        validated_conf = match parse_digested_conf(&conf_notrail) {
            Some(c) => {
                println!("user configuration integrity checked and validated");
                Some(c)
            },
            // XXX abort on invalid (but SHA validated) conf for now
            None => return Err(Error::from(ErrorKind::InvalidData)),
        };
    }

    // Eject regardless of timeout or proper validated conf
    match fs::write(cfs_usb_lun.join("forced_eject"), b"1") {
        Ok(_) => println!("configuration device ejected"),
        Err(e) => println!("skipping eject, sysfs write failed: {}", e),
    };

    if validated_conf.is_none() {
        println!("timed out waiting for valid configuration, attempting shutdown");
        let _ = fs::write("/proc/sysrq-trigger", b"o");
        return Err(Error::from(ErrorKind::InvalidData))
    }

    let _ = fs::write(PathBuf::from(STATUS_LED_PATH).join("trigger"), b"none");

    // Unlink the fatfs backing file after processing to free up memory. It may
    // still be locally mounted for testing.
    fs::remove_file(fatfs_path)?;

    // TODO rest of app
    // - store salt (in GPT uuid?)
    // - open dm-crypt dev
    // - mkfs.btrfs
    // - mkfs.exfat file-on-btrfs
    // - on open: hand snapshots (reflink file)
    // - expose file-on-btrfs via USB
    // - FIDO2
    // - unit tests!
    Ok(())
}
