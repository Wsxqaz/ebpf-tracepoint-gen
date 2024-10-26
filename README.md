# ebpf-tracepoint-gen
ebpf prog generator for syscall tracepoints, prints syscall args

## build

```bash
> cargo build
```

## run

```bash
> mkdir progs
> sudo ./target/debug/ebpf-tracepoint-gen
> ls ./progs
sys_enter_read.c    sys_enter_open.c    ...
```

## run progs and view output

### run progs

see [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf/)

```bash
> ./ecc-rs sys_enter_openat.c
INFO [ecc_rs::bpf_compiler] Compiling bpf object...
INFO [ecc_rs::bpf_compiler] Generating package json..
INFO [ecc_rs::bpf_compiler] Packing ebpf object and config into package.json...

> ./ecli package.json
INFO [faerie::elf] strtab: 0x486 symtab 0x4c0 relocs 0x508 sh_offset 0x508
INFO [bpf_loader_lib::skeleton::poller] Running ebpf program...
```

### view output

```bash
> sudo cat /sys/kernel/debug/tracing/trace_pipe
    systemd-oomd-1093    [000] ...21  7072.626159: bpf_trace_printk: dfd => 00000000ffffff9c
    systemd-oomd-1093    [000] ...21  7072.626159: bpf_trace_printk: filename => 000055b30855bbf0
    systemd-oomd-1093    [000] ...21  7072.626159: bpf_trace_printk: flags => 0000000000080000
    systemd-oomd-1093    [000] ...21  7072.626159: bpf_trace_printk: mode => 0000000000000000
    systemd-oomd-1093    [000] ...21  7072.626160: bpf_trace_printk: sys_enter_openat

```

