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
use std::os::unix::fs::MetadataExt;
use std::process::{Command,Stdio};
use std::path::PathBuf;
use std::str;

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
    println!("Usage: lioness <fatfs-device> <configfs-path> <proc-cmdline>");
}

struct Conf {
    key: Vec<u8>,
    salt: Vec<u8>,
    date: String,
    conft: ConfType,
}

enum ConfType {
    Setup(SetupConf),
    Unlock(bool),   // manage: bool
}

struct SetupConf {
    img_size: u64,
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

fn parse_setup_conf(conf_buf: &[u8]) -> Option<Conf> {
    let mut key: Option<Vec<u8>> = None;
    let mut salt: Option<Vec<u8>> = None;
    let (mut date, mut snap, mut compr, mut format) = (None, None, None, None);
    let mut img_size = None;
    let mut payload_seen = false;

    // XXX not standard ini! We strictly require the format that was written by
    // lioness setup.html
    // TODO would be nice if we could construct these arrays at compile time
    // from the corresponding "key = " strings. For now they're vim compiled
    // via: s/\(.\)/b'\1', /g
    for l in conf_buf.split(|c| matches!(c, b'\n')) {
        //println!("tok {:?}", String::from_utf8_lossy(&l));
        match l {
            [b'p', b'a', b'y', b'l', b'o', b'a', b'd', b' ', b'=', b' ',
             b'L', b'i', b'o', b'n', b'e', b's', b's',
             b'F', b'i', b'r', b's', b't', b'b', b'o', b'o', b't', b'1'] => {
                // key and value prefix already checked, need to match suffix
                if payload_seen {
                    println!("invalid: payload set multiple times");
                    return None;
                }
                payload_seen = true;
            },
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
                if val.len() != 64 {
                    println!("invalid: salt length {}", val.len());
                    return None;
                }
                salt = Some(val.to_vec());
            },
            [b'd', b'a', b't', b'e', b' ', b'=', b' ', val @ .. ]  => {
                if date.is_some() {
                    println!("invalid: date set multiple times");
                    return None;
                }
                if val.len() != 24 {
                    println!("invalid: date length {}", val.len());
                    return None;
                }
                date = match String::from_utf8(val.to_vec()) {
                    Err(_) => {
                        println!("bad date string");
                        return None;
                    },
                    Ok(d) => Some(d),
                };
            },
            [b'i', b'm', b'g', b'_', b's', b'i', b'z', b'e', b' ', b'=', b' ', val @ .. ]  => {
                if img_size.is_some() {
                    println!("invalid: img_size set multiple times");
                    return None;
                }
                let img_size_str = match String::from_utf8(val.to_vec()) {
                    Err(_) => {
                        println!("bad img_size string");
                        return None;
                    },
                    Ok(s) => s,
                };
                img_size = match img_size_str.parse::<u64>() {
                    Err(_) => {
                        println!("bad img_size value");
                        return None;
                    },
                    Ok(v) => Some(v),
                };
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
                println!("unexpected setup config entry: {}", String::from_utf8_lossy(unknown));
                return None;
            },
        }
    }
    if key.is_none() || salt.is_none() || date.is_none() || img_size.is_none() || snap.is_none() || compr.is_none() || format.is_none() {
        println!("not all expected config keys present");
        return None;
    }

    Some(Conf{
            key: key.unwrap(),
            salt: salt.unwrap(),
            date: date.unwrap(),
            conft: ConfType::Setup(SetupConf{
                img_size: img_size.unwrap(),
                snapshot: snap.unwrap(),
                compression: compr.unwrap(),
                exfat_format: format.unwrap(),
            }),
        })
}

fn parse_unlock_conf(conf_buf: &[u8]) -> Option<Conf> {
    let mut key: Option<Vec<u8>> = None;
    let mut salt: Option<Vec<u8>> = None;
    let (mut date, mut manage) = (None, None);
    let mut payload_seen = false;

    for l in conf_buf.split(|c| matches!(c, b'\n')) {
        match l {
            [b'p', b'a', b'y', b'l', b'o', b'a', b'd', b' ', b'=', b' ',
             b'L', b'i', b'o', b'n', b'e', b's', b's',
             b'U', b'n', b'l', b'o', b'c', b'k', b'1'] => {
                if payload_seen {
                    println!("invalid: payload set multiple times");
                    return None;
                }
                payload_seen = true;
            },
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
                if val.len() != 64 {
                    println!("invalid: salt length {}", val.len());
                    return None;
                }
                salt = Some(val.to_vec());
            },
            [b'd', b'a', b't', b'e', b' ', b'=', b' ', val @ .. ]  => {
                if date.is_some() {
                    println!("invalid: date set multiple times");
                    return None;
                }
                if val.len() != 24 {
                    println!("invalid: date length {}", val.len());
                    return None;
                }
                date = match String::from_utf8(val.to_vec()) {
                    Err(_) => {
                        println!("bad date string");
                        return None;
                    },
                    Ok(d) => Some(d),
                };
            },
            [b'm', b'a', b'n', b'a', b'g', b'e', b' ', b'=', b' ', val @ .. ] => {
                if manage.is_some() {
                    println!("invalid: manage set multiple times");
                    return None;
                }
                manage = match from_bool(val) {
                    Some(b) => Some(b),
                    None => return None,
                };
            },
            [ unknown @ .. ] => {
                println!("unexpected unlock config entry: {}",
                         String::from_utf8_lossy(unknown));
                return None;
            },
        }
    }
    if key.is_none() || salt.is_none() || date.is_none() || manage.is_none() {
        println!("not all expected config keys present");
        return None;
    }

    Some(Conf{
            key: key.unwrap(),
            salt: salt.unwrap(),
            date: date.unwrap(),
            conft: ConfType::Unlock(manage.unwrap()),
        })
}


// returns a Conf if found and validated. ErrorKind::NotFound means that a valid
// conf payload wasn't found (retry). Any other error means don't retry.
fn parse_conf_payload(buf: &mut [u8], firstboot: bool) -> io::Result<Conf> {
        // value suffix differs for firstboot setup and unlock configs
        let payload_hdr = b"payload = Lioness";
        if buf.starts_with(payload_hdr) {
            println!("payload header valid");
        } else {
            println!("retry due to invalid conf payload header");
            return Err(Error::from(ErrorKind::NotFound));
        }

        // XXX not split_at() from end, so just rotate and take it from start
		let digest_pfx = b"digest = SHA-256:";
        let digest_len = digest_pfx.len() + 64;
        if buf.len() < digest_len {
            println!("retry due to invalid conf length");
            return Err(Error::from(ErrorKind::NotFound));
        }
        buf.rotate_right(digest_len);
        let (digest, conf) = buf.split_at(digest_len);
        if digest.starts_with(digest_pfx) {
            println!("digest prefix valid");
        } else {
            println!("retry due to invalid digest prefix");
            return Err(Error::from(ErrorKind::NotFound));
        }

        let sha256 = match digest.get(digest_pfx.len()..) {
            Some(v) => {
                if !v.is_ascii() {
                    println!("retry due to invalid digest content");
                    return Err(Error::from(ErrorKind::NotFound));
                }
                v
            },
            None => {
                println!("retry due to invalid digest content");
                return Err(Error::from(ErrorKind::NotFound));
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
            return Err(Error::from(ErrorKind::NotFound));
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

        let parsed_conf;
        if firstboot {
            parsed_conf = parse_setup_conf(&conf_notrail);
        } else {
            parsed_conf = parse_unlock_conf(&conf_notrail);
        }

        match parsed_conf {
            Some(c) => {
                println!("user configuration integrity checked and validated");
                Ok(c)
            },
            // XXX abort on invalid (but SHA validated) conf for now
            None => Err(Error::from(ErrorKind::InvalidData)),
        }
}

// set a timeout on first call. subsequent calls subtract sleep time from tout
// and return false if lapsed. TODO make timeout duration configurable.
fn validate_retry(retry_tout: &mut Option<time::Duration>) -> bool {
    if retry_tout.is_none() {
        *retry_tout = Some(time::Duration::from_secs(24 * 60 * 60));
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
fn init_fs(fatfs_dev: &str, uuid_to_salt: &str, user_part_size: &str,
           firstboot: bool) -> io::Result<()> {
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

    let fname = match firstboot {
        true => "setup.html",
        false => "unlock.html",
    };
    let mut file = root_dir.create_file(fname)?;
    file.write_all(include_bytes!("setup.html.head.template"))?;
    file.write_all(include_bytes!("setup.html.pre_js.template"))?;
    write!(file, "const template_uboot_salt = new Uint8Array({});\n",
           uuid_to_salt)?;
    write!(file, "const template_user_part_size = {};\n", user_part_size)?;
    write!(file, "const template_is_firstboot = {};\n", firstboot)?;
    file.write_all(include_bytes!("setup.js.template"))?;
    file.write_all(include_bytes!("setup.html.post_js.template"))?;
    f.sync_data()
}

fn init_musb(lun_dev: &str, configfs: &str) -> io::Result<PathBuf> {
    // TODO perform configfs mount if needed
    let cfs_usb = PathBuf::from(configfs).join("usb_gadget/confs");

    // attempt to teardown any existing mass storage LUN
    match fs::write(cfs_usb.join("functions/mass_storage.usb0/lun.0/forced_eject"),
              b"1") {
        Err(_) => {},
        Ok(_) => println!("ejected existing lun.0"),
    };
    match fs::remove_file(cfs_usb.join("configs/c.1/mass_storage.usb0")) {
        Err(_) => {},
        Ok(_) => println!("removed existing mass_storage.usb0"),
    };

    fs::create_dir_all(cfs_usb.join("strings/0x409"))?;
    fs::create_dir_all(cfs_usb.join("functions/mass_storage.usb0/lun.0"))?;
    fs::create_dir_all(cfs_usb.join("configs/c.1/strings/0x409"))?;
    fs::write(cfs_usb.join("idVendor"), b"0x1d6b")?;    // Linux Foundation
    fs::write(cfs_usb.join("idProduct"),
        b"0x1d6b")?;    // Multifunction Composite Gadget
    fs::write(cfs_usb.join("bcdDevice"), b"0x0090")?;   // v0.9.0

    fs::write(cfs_usb.join("strings/0x409/manufacturer"), b"openSUSE")?;
    fs::write(cfs_usb.join("strings/0x409/product"), b"lioness")?;

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
              lun_dev.as_bytes())?;
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

struct Kcli {
    firstboot: bool,
    disk_uuid: String,
    os_uuid: String,
    user_uuid: String,
    user_size: String,
    uuid_to_salt: String,
}

fn push_kcli_part_uuid(uuid: &[u8],
                       mut js_array: Option<&mut String>) -> io::Result<String> {
    let mut uuidstr = String::with_capacity(36);

    for (i, c) in uuid.iter().enumerate() {
        if i > 35 {
                return Err(Error::from(ErrorKind::InvalidData));
        }
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if *c != b'-' {
                return Err(Error::from(ErrorKind::InvalidData));
            }
        } else {
            match c {
                b'a'..=b'f' => {},
                b'A'..=b'F' => {},
                b'0'..=b'9' => {},
                _ => return Err(Error::from(ErrorKind::InvalidData)),
            }
            const LEN_PER_VAL: usize = "0x##,".len();
            match js_array {
                // js values start at index of 1 due to preceeding '[' or ','
                Some(ref mut s) if s.len() % LEN_PER_VAL == 1 => {
                    s.push_str("0x");
                    s.push(char::from(*c));
                },
                Some(ref mut s) if s.len() % LEN_PER_VAL == 4 => {
                    s.push(char::from(*c));
                    s.push(',');
                },
                Some(s) => panic!("unexpected js_array input {}", s), // alread checked
                None => {},
            };
        }
        uuidstr.push(char::from(*c));
    }
    if uuidstr.len() != 36 {
        return Err(Error::from(ErrorKind::InvalidData));
    }

    Ok(uuidstr)
}

// uuid_disk=11017e55-d15c-b007-ed00-7686722c6a20;name=boot,start=0x100000,size=0x2000000,uuid=5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e;name=user,start=0x2100000,size=0xef08fbea0,uuid=6bf3d7d3-7633-4a9a-b43b-174c842e5cc7;
fn parse_kcli_parts(parts: &[u8], kcli: &mut Kcli) -> io::Result<()> {
    for part in parts.split(|c| matches!(c, b';')) {
        let mut this_uuid: Option<String> = None;
        let mut this_size: Option<String> = None;
        let mut in_boot = false;
        let mut in_user = false;

        for k in part.split(|c| matches!(c, b',')) {
            match k {
                [b'u', b'u', b'i', b'd', b'_', b'd', b'i', b's', b'k', b'=',
                 val @ ..] => {
                    kcli.disk_uuid = push_kcli_part_uuid(val, None)
                        .or_else(|e| Err(e))?;
                    println!("got disk uuid {}", kcli.disk_uuid);
                },
                b"name=boot" => in_boot = true,
                b"name=user" => in_user = true,
                [b'u', b'u', b'i', b'd', b'=', val @ ..] => {
                    this_uuid = match push_kcli_part_uuid(val, Some(&mut kcli.uuid_to_salt)) {
                        Err(e) => return Err(e),
                        Ok(u) => Some(u),
                    };
                },
                [b's', b'i', b'z', b'e', b'=', val @ ..] => {
                    this_size = match str::from_utf8(val) {
                        Err(_) => return Err(Error::from(ErrorKind::InvalidData)),
                        Ok(u) => Some(u.to_string()),
                    };
                },
                [ _unused @ .. ] => {},
            }
        }
        if in_boot == true {
            if in_user == true || !kcli.user_uuid.is_empty() {
                // strict ordering is required for uuid_to_salt
                return Err(Error::from(ErrorKind::InvalidData));
            }
            kcli.os_uuid = this_uuid.ok_or(Error::from(ErrorKind::InvalidData))?;
            println!("got os uuid {}", kcli.os_uuid);
        } else if in_user == true {
            if in_boot == true || kcli.os_uuid.is_empty() {
                return Err(Error::from(ErrorKind::InvalidData));
            }
            kcli.user_uuid = this_uuid.ok_or(Error::from(ErrorKind::InvalidData))?;
            kcli.user_size = this_size.ok_or(Error::from(ErrorKind::InvalidData))?;
            println!("got user uuid {} size {}", kcli.user_uuid, kcli.user_size);
        }
    }
    Ok(())
}

fn parse_kcli(proc_cmdline: &str) -> io::Result<Kcli> {
    let kcmdline = fs::read(proc_cmdline)?;
    let mut kcli = Kcli{
        firstboot: false,
        disk_uuid: String::new(),
        os_uuid: String::new(),
        user_uuid: String::new(),
        user_size: String::new(),
        // setup password salt is made up of the concatinated bootloader
        // randomized OS and user partition uuids, which are generated by uboot
        // on firstboot. It's converted directly into a js format array with hex
        // values, i.e. [0x##,0x##,...] -> plus one for leading bracket.
        uuid_to_salt: String::with_capacity(1 + (32 + 32) * 5),
    };
    let mut parts_seen = false;
    kcli.uuid_to_salt.push('[');

    for w in kcmdline.split(|c| matches!(c, b' ')) {
        match w {
            b"lioness.firstboot" => kcli.firstboot = true,
            [b'l', b'i', b'o', b'n', b'e', b's', b's',
             b'.', b'p', b'a', b'r', b't', b's', b'=', val @ ..] => {
                if parts_seen {
                    println!("multiple lioness.parts kcli parameters");
                    return Err(Error::from(ErrorKind::InvalidData));
                }
                parse_kcli_parts(&val, &mut kcli)?;
                parts_seen = true;
            },
            [ _unused @ .. ] => {},
        }
    }

    if parts_seen == false {
        println!("lioness.parts kcli parameter missing");
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if kcli.disk_uuid.is_empty() || kcli.os_uuid.is_empty()
        || kcli.user_uuid.is_empty() || kcli.user_size.is_empty() {
        println!("lioness.parts kcli fields missing");
        return Err(Error::from(ErrorKind::InvalidData));
    }
    let c = kcli.uuid_to_salt.pop();
    assert_eq!(c.unwrap(), ',');
    kcli.uuid_to_salt.push(']');

    Ok(kcli)
}

// might be able to use dm-init.ko in future, but for now...
fn dmsetup_crypt(partdev: String, key: Vec<u8>) -> io::Result<String> {
    let mut sysblk_path = PathBuf::from("/sys/class/block/");
    sysblk_path.push(&partdev);
    sysblk_path.push("size");   // partdev size in blocks
    let size_blocks = fs::read(sysblk_path)?;
    let size_blocks_str = match str::from_utf8(&size_blocks) {
        Err(_) => return Err(Error::from(ErrorKind::InvalidData)),
        Ok(s) => s.trim_end_matches('\n'),
    };

    let key_str = match str::from_utf8(&key) {
        Err(_) => return Err(Error::from(ErrorKind::InvalidData)),
        Ok(s) => s,
    };

    let mut table_parm = String::from("0 ");
    table_parm.push_str(&size_blocks_str);
    table_parm.push_str(" crypt aes-cbc-essiv:sha256 ");
    table_parm.push_str(&key_str);
    table_parm.push_str(" 0 /dev/");
    table_parm.push_str(&partdev);
    table_parm.push_str(" 0");   // why?

    let status = Command::new("dmsetup")
        .args(["create", "crypty", "--table", &table_parm])
        .status()
        .expect("failed to execute process");
    if !status.success() {
        println!("dmsetup failed");
        return Err(Error::from(ErrorKind::InvalidData));
    }

    // FIXME: don't assume dm-0 device name. use crypty when/if we have udev
    Ok("/dev/dm-0".to_string())
}

fn btrfs_mkfs(dev: String) -> io::Result<()> {
    let status = Command::new("mkfs.btrfs")
        .args([dev])
        .status()
        .expect("failed to execute process");
    if !status.success() {
        println!("mkfs.btrfs failed");
        return Err(Error::from(ErrorKind::InvalidData));
    }

    // FIXME: don't assume dm-0 device name. use crypty when/if we have udev
    Ok(())
}

fn btrfs_mount(dev: String, mntpoint: String) -> io::Result<()> {
    let mut args = vec!["-t", "btrfs", "-o", "sync,noatime"];
    args.push(&dev);
    args.push(&mntpoint);
    let status = Command::new("mount")
        .args(args)
        .status()
        .expect("failed to execute process");
    if !status.success() {
        println!("btrfs mount failed");
        return Err(Error::from(ErrorKind::InvalidData));
    }

    Ok(())
}

// TODO use libbtrfs-util bindings
fn btrfs_create_subvolume(vol_path: &str) -> io::Result<()> {
    let args = vec!["subvolume", "create", vol_path];
    let status = Command::new("btrfs")
        .args(args)
        .status()
        .expect("failed to execute process");
    if !status.success() {
        println!("btrfs snapshot failed");
        return Err(Error::from(ErrorKind::InvalidData));
    }

    Ok(())
}

// TODO use libbtrfs-util bindings
fn btrfs_set_compression(img_path: &str) -> io::Result<()> {
    let args = vec!["property", "set", img_path, "compression", "zstd"];
    let status = Command::new("btrfs")
        .args(args)
        .status()
        .expect("failed to execute process");
    if !status.success() {
        println!("btrfs snapshot failed");
        return Err(Error::from(ErrorKind::InvalidData));
    }

    Ok(())
}

fn btrfs_snapshot(vol_path: &str, snap_name: &String) -> io::Result<()> {
    let args = vec!["subvolume", "snapshot", "-r", vol_path, snap_name];
    let status = Command::new("btrfs")
        .args(args)
        .status()
        .expect("failed to execute process");
    if !status.success() {
        println!("btrfs snapshot failed");
        return Err(Error::from(ErrorKind::InvalidData));
    }

    Ok(())
}

fn exfat_mkfs(img_path: &str) -> io::Result<()> {
    let status = Command::new("mkfs.exfat")
        .args([img_path])
        .status()
        .expect("failed to execute process");
    if !status.success() {
        println!("mkfs.exfat failed");
        return Err(Error::from(ErrorKind::InvalidData));
    }

    Ok(())
}

fn main() -> io::Result<()> {
    if env::args().len() != 4 {
        usage();
        return Err(Error::from(ErrorKind::InvalidInput));
    }
    let fatfs_path = env::args().nth(1).unwrap();
    let configfs = env::args().nth(2).unwrap();
    let kcli = parse_kcli(&env::args().nth(3).unwrap())?;
    init_fs(&fatfs_path, &kcli.uuid_to_salt, &kcli.user_size, kcli.firstboot)?;
    let cfs_usb_lun = init_musb(&fatfs_path, &configfs)?;
    let _ = fs::write(PathBuf::from(STATUS_LED_PATH).join("trigger"), b"heartbeat");

    let mut f = match File::open(&fatfs_path) {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to open device {}: {}", fatfs_path, e);
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

        validated_conf = match parse_conf_payload(&mut buf, kcli.firstboot) {
            Ok(c) => Some(c),
            Err(ref e) if e.kind() == ErrorKind::NotFound => None, // retry
            Err(e) => return Err(e),    // non-retriable 
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
    let validated_conf = validated_conf.unwrap();

    let _ = fs::write(PathBuf::from(STATUS_LED_PATH).join("trigger"), b"none");

    // Unlink the fatfs backing file after processing to free up memory. It may
    // still be locally mounted for testing.
    fs::remove_file(fatfs_path)?;

    // FIXME hardcoded device/partition
    let crypt_dev = dmsetup_crypt("mmcblk0p2".to_string(), validated_conf.key)?;

    if kcli.firstboot {
        btrfs_mkfs(crypt_dev.clone())?;
    }

    fs::create_dir_all("/mnt/crypt")?;
    btrfs_mount(crypt_dev, "/mnt/crypt".to_string())?;
    let vol_path = "/mnt/crypt/vol/";
    let img_path = "/mnt/crypt/vol/disk.img";

    if kcli.firstboot {
        let setup_conf = match validated_conf.conft {
            ConfType::Setup(s) => s,
            _ => panic!("non setup conf type for firstboot"),
        };
        if setup_conf.snapshot {
            btrfs_create_subvolume(&vol_path)?;
        } else {
            fs::create_dir_all(&vol_path)?;
        }

        // XXX use partition size as volume size for now - in future we should
        // allow for fine grained over/under provisioning. Compression and
        // snapshots will complicate any provisioning UI significantly.
        {
            let f = fs::OpenOptions::new().write(true)
                                          .read(true)
                                          .create(true)
                                          .truncate(false)
                                          .open(&img_path)?;
            f.set_len(setup_conf.img_size)?;
        }
        if setup_conf.compression {
            btrfs_set_compression(&img_path)?;
        }
        if setup_conf.exfat_format {
            exfat_mkfs(&img_path)?;
        }
    } else {
        let vol_meta = fs::metadata(&vol_path)?;
        if vol_meta.ino() == 256 {
            if btrfs_snapshot(&vol_path, &validated_conf.date).is_err() {
                println!("snapshot creation failed!");
                // ignore snapshot creation errors
            } else {
                println!("snapshot {} created", validated_conf.date);
            }
        }
    }

    let _img_usb_lun = init_musb(&img_path, &configfs)?;
    // TODO expose or cleanup snapshots as requested

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // create a lioness-selftest-XXXXX directory in the current working dir.
    fn tmpdir() -> PathBuf {
        let mut buf = [0u8; 16];
        let mut s = String::from("lioness-selftest-");
        fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut buf)
            .unwrap();
        for i in &buf {
            s.push_str(&format!("{:02x}", i).to_string());
        }

        fs::create_dir(&s).unwrap();
        return PathBuf::from(s);
    }

    #[test]
    fn test_kernel_cmdline_parser() {
        let t = tmpdir();
        let tf = t.join("cmdline");

        fs::write(&tf,
            b"lioness.parts=uuid_disk=11017e55-d15c-b007-ed00-7686722c6a20;name=boot,start=0x100000,size=0x2000000,uuid=5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e;name=user,start=0x2100000,size=0xef08fbea0,uuid=6bf3d7d3-7633-4a9a-b43b-174c842e5cc7;")
            .expect("failed to write tmpfile");
        let kcli = parse_kcli(&tf.to_str().unwrap()).expect("failed to parse kcli");
        assert_eq!(kcli.firstboot, false);
        assert_eq!(kcli.disk_uuid, "11017e55-d15c-b007-ed00-7686722c6a20");
        assert_eq!(kcli.os_uuid, "5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e");
        assert_eq!(kcli.user_uuid, "6bf3d7d3-7633-4a9a-b43b-174c842e5cc7");
        assert_eq!(kcli.user_size, "0xef08fbea0");
        assert_eq!(kcli.uuid_to_salt,
                   concat!("[0x5c,0x6a,0x6b,0x7d,0xcc,0xab,0x4c,0x14,",
                           "0xae,0x06,0xe8,0xa9,0x30,0xd4,0x8f,0x8e,", // join
                           "0x6b,0xf3,0xd7,0xd3,0x76,0x33,0x4a,0x9a,0xb4,0x3b,",
                           "0x17,0x4c,0x84,0x2e,0x5c,0xc7]"));

        fs::write(&tf,
            b"quiet lioness.firstboot splash=silent lioness.parts=uuid_disk=11017e55-d15c-b007-ed00-7686722c6a20;name=boot,start=0x100000,size=0x2000000,uuid=5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e;name=user,start=0x2100000,size=0xef070bea0,uuid=6bf3d7d3-7633-4a9a-b43b-174c842e5cc7;")
            .expect("failed to write tmpfile");
        let kcli = parse_kcli(&tf.to_str().unwrap()).expect("failed to parse kcli");
        assert_eq!(kcli.firstboot, true);
        assert_eq!(kcli.disk_uuid, "11017e55-d15c-b007-ed00-7686722c6a20");
        assert_eq!(kcli.os_uuid, "5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e");
        assert_eq!(kcli.user_uuid, "6bf3d7d3-7633-4a9a-b43b-174c842e5cc7");
        assert_eq!(kcli.user_size, "0xef070bea0");

        // invalid: no disk uuid
        fs::write(&tf,
            b"quiet lioness.firstboot splash=silent lioness.parts=name=boot,start=0x100000,size=0x2000000,uuid=5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e;name=user,start=0x2100000,size=0xef070bea0,uuid=6bf3d7d3-7633-4a9a-b43b-174c842e5cc7;")
            .expect("failed to write tmpfile");
        assert!(parse_kcli(&tf.to_str().unwrap()).is_err());

        // invalid: bad uuid format
        fs::write(&tf,
            b"lioness.parts=uuid_disk=11017e55d15cb007ed007686722c6a20;name=boot,start=0x100000,size=0x2000000,uuid=5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e;name=user,start=0x2100000,size=0xef08fbea0,uuid=6bf3d7d3-7633-4a9a-b43b-174c842e5cc7;")
            .expect("failed to write tmpfile");
        assert!(parse_kcli(&tf.to_str().unwrap()).is_err());

        // invalid: bad uuid char
        fs::write(&tf,
            b"lioness.parts=uuid_disk=nothexxx-d15c-b007-ed00-7686722c6a20;name=boot,start=0x100000,size=0x2000000,uuid=5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e;name=user,start=0x2100000,size=0xef08fbea0,uuid=6bf3d7d3-7633-4a9a-b43b-174c842e5cc7;")
            .expect("failed to write tmpfile");
        assert!(parse_kcli(&tf.to_str().unwrap()).is_err());

        // invalid: short uuid
        fs::write(&tf,
            b"lioness.parts=uuid_disk=11017e55-d15c-b007-ed00;name=boot,start=0x100000,size=0x2000000,uuid=5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e;name=user,start=0x2100000,size=0xef08fbea0,uuid=6bf3d7d3-7633-4a9a-b43b-174c842e5cc7;")
            .expect("failed to write tmpfile");
        assert!(parse_kcli(&tf.to_str().unwrap()).is_err());

        // invalid: long uuid
        fs::write(&tf,
            b"lioness.parts=uuid_disk=11017e55-d15c-b007-ed00-7686722c6a204;name=boot,start=0x100000,size=0x2000000,uuid=5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e;name=user,start=0x2100000,size=0xef08fbea0,uuid=6bf3d7d3-7633-4a9a-b43b-174c842e5cc7;")
            .expect("failed to write tmpfile");
        assert!(parse_kcli(&tf.to_str().unwrap()).is_err());

        // invalid: user before OS
        fs::write(&tf,
            b"lioness.parts=uuid_disk=11017e55-d15c-b007-ed00-7686722c6a20;name=user,start=0x2100000,size=0xef08fbea0,uuid=6bf3d7d3-7633-4a9a-b43b-174c842e5cc7;name=boot,start=0x100000,size=0x2000000,uuid=5c6a6b7d-ccab-4c14-ae06-e8a930d48f8e;")
            .expect("failed to write tmpfile");
        assert!(parse_kcli(&tf.to_str().unwrap()).is_err());

        fs::remove_file(tf).expect("failed to remove tmpfile");
        fs::remove_dir(t).expect("failed to remove tmpdir");
    }

    #[test]
    fn test_mkfatfs() {
        let t = tmpdir();
        let tf = t.join("fatfs.img");
        let uuid_salt = "[0xba,0xd0,0x5a,0x17]";
        let user_part_size = "0xef070bea0";

        init_fs(tf.to_str().unwrap(), &uuid_salt, &user_part_size, false)
            .expect("init_fs failed");
        let contents = fs::read(tf.to_str().unwrap()).expect("failed to read fatfs img");
        let cur: Cursor<Vec<u8>> = Cursor::new(contents);
        let fat = FileSystem::new(cur, FsOptions::new()).expect("fatfs new failed");

        let root_dir = fat.root_dir();
        let mut f = root_dir.open_file("unlock.html").expect("html open failed");
        let mut buf = vec![];
        f.read_to_end(&mut buf).expect("failed to read html");
        assert!(buf.starts_with(b"<!doctype html>"));
        const SALT_OFF: usize = include_bytes!("setup.html.head.template").len()
                                + include_bytes!("setup.html.pre_js.template").len();
        let mut salt_js = String::from("const template_uboot_salt = new Uint8Array(");
        salt_js.push_str(uuid_salt);
        salt_js.push_str(");\n");
        assert_eq!(str::from_utf8(&buf[SALT_OFF..SALT_OFF + salt_js.len()]).unwrap(),
                   salt_js);

        let part_size_off: usize = SALT_OFF + salt_js.len();
        let mut user_part_size_js = String::from("const template_user_part_size = ");
        user_part_size_js.push_str(user_part_size);
        user_part_size_js.push_str(";\n");
        assert_eq!(str::from_utf8(&buf[part_size_off..part_size_off + user_part_size_js.len()]).unwrap(),
                   user_part_size_js);

        let firstboot_off: usize = part_size_off + user_part_size_js.len();
        let firstboot_js = String::from("const template_is_firstboot = false;\n");
        assert_eq!(str::from_utf8(&buf[firstboot_off..firstboot_off + firstboot_js.len()]).unwrap(),
                   firstboot_js);

        assert!(root_dir.open_file("lioness.txt").is_err());

        fs::remove_file(tf).expect("failed to remove tmpfile");
        fs::remove_dir(t).expect("failed to remove tmpdir");
    }

    #[test]
    fn test_mkfatfs_firstboot() {
        let t = tmpdir();
        let tf = t.join("fatfs.img");
        let uuid_salt = "[0xba,0xd0,0x5a,0x18]";
        let user_part_size = "0xef070bea1";

        init_fs(tf.to_str().unwrap(), &uuid_salt, &user_part_size, true)
            .expect("init_fs failed");
        let contents = fs::read(tf.to_str().unwrap()).expect("failed to read fatfs img");
        let cur: Cursor<Vec<u8>> = Cursor::new(contents);
        let fat = FileSystem::new(cur, FsOptions::new()).expect("fatfs new failed");

        let root_dir = fat.root_dir();
        let mut f = root_dir.open_file("setup.html").expect("html open failed");
        let mut buf = vec![];
        f.read_to_end(&mut buf).expect("failed to read html");
        assert!(buf.starts_with(b"<!doctype html>"));
        const SALT_OFF: usize = include_bytes!("setup.html.head.template").len()
                                + include_bytes!("setup.html.pre_js.template").len();
        let mut salt_js = String::from("const template_uboot_salt = new Uint8Array(");
        salt_js.push_str(uuid_salt);
        salt_js.push_str(");\n");
        assert_eq!(str::from_utf8(&buf[SALT_OFF..SALT_OFF + salt_js.len()]).unwrap(),
                   salt_js);

        let part_size_off: usize = SALT_OFF + salt_js.len();
        let mut user_part_size_js = String::from("const template_user_part_size = ");
        user_part_size_js.push_str(user_part_size);
        user_part_size_js.push_str(";\n");
        assert_eq!(str::from_utf8(&buf[part_size_off..part_size_off + user_part_size_js.len()]).unwrap(),
                   user_part_size_js);

        let firstboot_off: usize = part_size_off + user_part_size_js.len();
        let firstboot_js = String::from("const template_is_firstboot = true;\n");
        assert_eq!(str::from_utf8(&buf[firstboot_off..firstboot_off + firstboot_js.len()]).unwrap(),
                   firstboot_js);

        assert!(root_dir.open_file("lioness.txt").is_err());

        fs::remove_file(tf).expect("failed to remove tmpfile");
        fs::remove_dir(t).expect("failed to remove tmpdir");
    }

    #[test]
    fn test_conf() {
        // sample password. Don't waste energy brute-forcing :)
        let t = tmpdir();
        let tf = t.join("lioness.conf");

        fs::write(&tf, b"payload = LionessFirstboot1
key = 4e7f0992a0828e0a5cb8f3bf13f957cd76b08b765a9efb0c968ef88b0b1e59a0
salt = 74337b9f3e304cdb8b03d0e8bbec83fc6e95385d24264bbdbb9106e6c39f0cb2
date = 2023-05-17T20:49:17.335Z
img_size = 54670659
snapshot = true
compression = false
format = true
digest = SHA-256:eec12eaea4ac05447df33657a4cf27ba965003d20fba432baa3968d7e93baf4a")
            .expect("failed to write conf file");
        let mut pl = fs::read(&tf).expect("read failed");
        let conf = parse_conf_payload(&mut pl,
                                      true) // firstboot
            .expect("failed to parse conf payload");
        assert_eq!(str::from_utf8(&conf.key).unwrap(),
                   "4e7f0992a0828e0a5cb8f3bf13f957cd76b08b765a9efb0c968ef88b0b1e59a0");
        assert_eq!(str::from_utf8(&conf.salt).unwrap(),
                   "74337b9f3e304cdb8b03d0e8bbec83fc6e95385d24264bbdbb9106e6c39f0cb2");
        assert_eq!(conf.date, "2023-05-17T20:49:17.335Z");
        let setup_conf = match conf.conft {
            ConfType::Setup(s) => s,
            _ => panic!("non setup conf type for firstboot"),
        };
        assert_eq!(setup_conf.img_size, 54670659);
        assert_eq!(setup_conf.snapshot, true);
        assert_eq!(setup_conf.compression, false);
        assert_eq!(setup_conf.exfat_format, true);

        // digest mismatch
        fs::write(&tf, b"payload = LionessFirstboot1
key = 4e7f0992a0828e0a5cb8f3bf13f957cd76b08b765a9efb0c968ef88b0b1e59a0
salt = 74337b9f3e304cdb8b03d0e8bbec83fc6e95385d24264bbdbb9106e6c39f0cb2
snapshot = true
compression = false
format = true
digest = SHA-256:fffffffffffffffffff3fec343d2c7371cb43804cf3c29389bc591162a8f1f0e")
            .expect("failed to write conf file");
        let mut pl = fs::read(&tf).expect("read failed");
        assert!(parse_conf_payload(&mut pl, true).is_err());

        // bad payload header
        fs::write(&tf, b"payload = LionessLastboot
key = 4e7f0992a0828e0a5cb8f3bf13f957cd76b08b765a9efb0c968ef88b0b1e59a0
salt = 74337b9f3e304cdb8b03d0e8bbec83fc6e95385d24264bbdbb9106e6c39f0cb2
snapshot = true
compression = false
format = true
digest = SHA-256:73da283c2797463de39d43153bcbc5929e4026bdf2e201b0e1088ae09e4f80c2")
            .expect("failed to write conf file");
        let mut pl = fs::read(&tf).expect("read failed");
        assert!(parse_conf_payload(&mut pl, true).is_err());

        // unlock config (expected for firstboot=false)
        fs::write(&tf, b"payload = LionessUnlock1
key = 4e7f0992a0828e0a5cb8f3bf13f957cd76b08b765a9efb0c968ef88b0b1e59a0
salt = 74337b9f3e304cdb8b03d0e8bbec83fc6e95385d24264bbdbb9106e6c39f0cb2
date = 2023-05-17T20:49:17.335Z
manage = false
digest = SHA-256:f6a1689ff46e2f3c1ea6750aa1d466f248637b3d988e8c952e1c4ad6cbb7ddc8")
            .expect("failed to write conf file");
        let mut pl = fs::read(&tf).expect("read failed");
        let conf = parse_conf_payload(&mut pl,
                                      false) // firstboot
            .expect("failed to parse conf payload");
        assert_eq!(str::from_utf8(&conf.key).unwrap(),
                   "4e7f0992a0828e0a5cb8f3bf13f957cd76b08b765a9efb0c968ef88b0b1e59a0");
        assert_eq!(str::from_utf8(&conf.salt).unwrap(),
                   "74337b9f3e304cdb8b03d0e8bbec83fc6e95385d24264bbdbb9106e6c39f0cb2");
        assert_eq!(conf.date, "2023-05-17T20:49:17.335Z");
        let manage = match conf.conft {
            ConfType::Unlock(m) => m,
            _ => panic!("non unlock conf type with firstboot=false"),
        };
        assert_eq!(manage, false);

        fs::remove_file(tf).expect("failed to remove tmpfile");
        fs::remove_dir(t).expect("failed to remove tmpdir");
    }
}
