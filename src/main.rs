#![allow(warnings)]
use std::fs;
use std::mem::MaybeUninit;

#[derive(Default, Debug)]
pub struct _SyscallMetaEntry<'a> {
    _type: &'a str,
    name: &'a str,
    offset: u32,
    size: u32,
    signed: u32
}

#[derive(Default, Debug)]
pub struct _SyscallMeta<'a> {
    common: Vec<_SyscallMetaEntry<'a>>,
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

        let mut meta: _SyscallMeta = unsafe { MaybeUninit::zeroed().assume_init() };
        let lines = fs::read(format_path);
        let lines = match lines {
            Ok(v) => v,
            Err(e) => vec![0u8]
        };
        let lines = std::str::from_utf8(&lines);
        let lines = match lines {
            Ok(v) => v,
            Err(e) => "error"
        };
        for line in lines.lines() {
            let line = line.trim();
            if line.starts_with("field") {
                println!("line: {}", line);
                if (meta.common.len() < 5) {
                    let tk: Vec<String> = line.split(";").map(|c| c.to_string()).collect();
                    if (tk.len() < 4) { continue; }
                    let mut meta_ent =  _SyscallMetaEntry {
                        ..Default::default()
                    };
                    for item in tk {
                        if item.starts_with("field") {
                            let li =  item.len();
                            let mut sp = 0;
                            let mut type_buff = [0u8; 128];
                            let mut name_buff = [0u8; 128];
                            for i in 0..li {
                                if item.chars().nth(li - 1 - i).unwrap() == ' ' {
                                    println!("item: {}", item);
                                    println!("space at: {} (li - 1 - i)", (li - 1 - i));
                                    for j in  (li - 1 - i)..li {
                                        name_buff[j.wrapping_sub(li - 1 - i)] = item.chars().nth(j).unwrap() as u8;
                                    }
                                    for j in  0..(li - 1 - i)  {
                                        type_buff[j] = item.chars().nth(j).unwrap() as u8;
                                    }
                                    break;
                                }
                            }
                            println!("item starts with field: name_buff[j] = {}, type_buff[j] = {}", std::str::from_utf8(&name_buff).unwrap(), std::str::from_utf8( &type_buff ).unwrap());
                        }

                        if item.starts_with("offset") {
                            println!("item starts with offset");
                        }

                        if item.starts_with("size") {
                            println!("item starts with size");
                        }

                        if item.starts_with("signed") {
                            println!("item starts with signed");
                        }
                    }
                    // meta.common.push(meta_ent);
                    println!("meta_ent: {:?}", meta_ent);
                }
            }
        }
    }
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
