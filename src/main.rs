#![allow(warnings)]
use std::fs;
use std::mem::MaybeUninit;

#[derive(Default, Debug)]
pub struct _SyscallMetaEntry<'a> {
    _type: Box<&'a str>,
    name: Box<&'a str>,
    offset: Box<&'a str>,
    size: Box<&'a str>,
    signed: Box<&'a str>,
}

#[derive(Default, Debug)]
pub struct _SyscallMeta<'a> {
    file: &'a str,
    fields: Vec<_SyscallMetaEntry<'a>>,
}

#[derive(Default, Debug)]
pub struct SyscallMeta<'a> {
    enter: _SyscallMeta<'a>,
    exit: _SyscallMeta<'a>,
}

static SYSCALL_EVENTS_DIR: &str = "/sys/kernel/tracing/events/syscalls";


fn main() {
    let _syscall_meta = read_syscall_meta("read");

    let syscall_events_paths = fs::read_dir(SYSCALL_EVENTS_DIR).unwrap();

    let metas: Vec<_SyscallMeta> = Vec::new();

    for path in syscall_events_paths {
        let _path = path.unwrap().path().clone();
        let format_path = format!("{}/format", _path.display());
        println!("format file path: {format_path}");

        let lines = fs::read(format_path.clone());
        let lines = match lines {
            Ok(v) => v,
            Err(e) => vec![0u8],
        };
        let lines = std::str::from_utf8(&lines);
        let lines = match lines {
            Ok(v) => v,
            Err(e) => "error",
        };

        let mut fields: Vec<_SyscallMetaEntry> = vec![];

        for line in lines.lines() {
            let line = line.trim();
            if line.starts_with("field") {
                let ent = gen_field(line);
                fields.push(ent);
            }
        }

        let syscall_meta: _SyscallMeta = _SyscallMeta {
            file: &format_path,
            fields: fields
        };

        println!("syscall_meta: {:?}", syscall_meta);
    }
}

fn gen_field<'a>(line: &str) -> _SyscallMetaEntry {
                let tk: Vec<String> = line.split(";").map(|c| c.to_string()).collect();
                if (tk.len() < 4) {
                    return _SyscallMetaEntry { .. Default::default() };
                }
                let mut type_buff = Box::new([0u8; 128]);
                let mut name_buff = Box::new([0u8; 128]);
                let mut offset_buff = Box::new([0u8; 128]);
                let mut size_buff = Box::new([0u8; 128]);
                let mut signed_buff = Box::new([0u8; 128]);
                for item in tk {
                    let item = item.trim();
                    if item.starts_with("field") {
                        let li = item.len();
                        for i in 0..li {
                            if item.chars().nth(li - 1 - i).unwrap() == ' ' {
                                for j in (li - i)..li {
                                    name_buff[j.wrapping_sub(li - i)] =
                                        item.chars().nth(j).unwrap() as u8;
                                }
                                for j in 0..(li - 1 - i) {
                                    type_buff[j] = item.chars().nth(j).unwrap() as u8;
                                }

                                break;
                            }
                        }
                    }

                    if item.starts_with("offset") {
                        let li = item.len();
                        for i in 0..li {
                            if item.chars().nth(i).unwrap() == ':' {
                                for j in i + 1..li {
                                    offset_buff[j] = item.chars().nth(j).unwrap() as u8;
                                }
                                break;
                            }
                        }
                    }

                    if item.starts_with("size") {
                        let li = item.len();
                        for i in 0..li {
                            if item.chars().nth(i).unwrap() == ':' {
                                for j in i + 1..li {
                                    size_buff[j] = item.chars().nth(j).unwrap() as u8;
                                }
                                break;
                            }
                        }
                    }

                    if item.starts_with("signed") {
                        let li = item.len();
                        for i in 0..li {
                            if item.chars().nth(i).unwrap() == ':' {
                                for j in i + 1..li {
                                    signed_buff[j] = item.chars().nth(j).unwrap() as u8;
                                }
                                break;
                            }
                        }
                    }
                }
                let leaked_name_buff = Box::leak(name_buff);
                let mut name = Box::new(
                    std::str::from_utf8(leaked_name_buff)
                        .unwrap()
                        .trim_end_matches(|c| c == '\0')
                );
                let leaked_type_buff = Box::leak(type_buff);
                let mut _type = Box::new(
                    std::str::from_utf8(leaked_type_buff)
                        .unwrap()
                        .trim_end_matches(|c| c == '\0')
                );
                let leaked_offset_buff = Box::leak(offset_buff);
                let mut offset = Box::new(
                    std::str::from_utf8(leaked_offset_buff)
                        .unwrap()
                        .trim_end_matches(|c| c == '\0')
                        .trim_start_matches(|c| c == '\0')
                );
                let leaked_size_buff = Box::leak(size_buff);
                let mut size = Box::new(
                    std::str::from_utf8(leaked_size_buff)
                        .unwrap()
                        .trim_end_matches(|c| c == '\0')
                        .trim_start_matches(|c| c == '\0')
                );
                let leaked_signed_buff = Box::leak(signed_buff);
                let mut signed = Box::new(
                    std::str::from_utf8(leaked_signed_buff)
                        .unwrap()
                        .trim_end_matches(|c| c == '\0')
                        .trim_start_matches(|c| c == '\0')
                );


                let mut meta_ent = _SyscallMetaEntry {
                    name: name,
                    _type: _type,
                    offset: offset,
                    size: size,
                    signed: signed,
                };
                meta_ent
}

fn read_syscall_meta(syscall: &str) -> SyscallMeta {
    let enter_format_path = format!(
        "/sys/kernel/tracing/events/syscalls/sys_enter_{}/format",
        syscall
    );
    println!("enter_format_path: {enter_format_path}");

    let exit_format_path = format!(
        "/sys/kernel/tracing/events/syscalls/sys_exit_{}/format",
        syscall
    );
    println!("exit_format_path: {exit_format_path}");

    unsafe { MaybeUninit::zeroed().assume_init() }
}
