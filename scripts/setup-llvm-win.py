import urllib.request
import json
import os
import shutil
import subprocess
import sys

base_dir = r"C:\LLVM21"
os.makedirs(os.path.join(base_dir, "bin"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "lib"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "include", "llvm-c", "Transforms"), exist_ok=True)

# Copy libs and tools from C:\Program Files\LLVM
src_lib = r"C:\Program Files\LLVM\lib\LLVM-C.lib"
src_dll = r"C:\Program Files\LLVM\bin\LLVM-C.dll"
src_clang = r"C:\Program Files\LLVM\bin\clang.exe"

if os.path.exists(src_lib):
    shutil.copy(src_lib, os.path.join(base_dir, "lib", "LLVM-C.lib"))
if os.path.exists(src_dll):
    shutil.copy(src_dll, os.path.join(base_dir, "bin", "LLVM-C.dll"))
if os.path.exists(src_clang):
    shutil.copy(src_clang, os.path.join(base_dir, "bin", "clang.exe"))

# Download headers
def get_contents(path):
    url = f"https://api.github.com/repos/llvm/llvm-project/contents/{path}?ref=release/21.x"
    req = urllib.request.Request(url, headers={"User-Agent": "jockey-setup"})
    return json.loads(urllib.request.urlopen(req).read())

print("Downloading llvm-c headers...")
try:
    for item in get_contents("llvm/include/llvm-c"):
        if item["type"] == "file":
            raw_url = item["download_url"]
            dest = os.path.join(base_dir, "include", "llvm-c", item["name"])
            if not os.path.exists(dest):
                urllib.request.urlretrieve(raw_url, dest)
                print("Downloaded:", item["name"])

    for item in get_contents("llvm/include/llvm-c/Transforms"):
        if item["type"] == "file":
            raw_url = item["download_url"]
            dest = os.path.join(base_dir, "include", "llvm-c", "Transforms", item["name"])
            if not os.path.exists(dest):
                urllib.request.urlretrieve(raw_url, dest)
                print("Downloaded: Transforms/" + item["name"])
except Exception as e:
    print("Error downloading headers:", e, file=sys.stderr)

cfg_dir = os.path.join(base_dir, "include", "llvm", "Config")
os.makedirs(cfg_dir, exist_ok=True)
with open(os.path.join(cfg_dir, "llvm-config.h"), "w", encoding="utf-8") as f:
    f.write("""#ifndef LLVM_CONFIG_H
#define LLVM_CONFIG_H
#define LLVM_DEFAULT_TARGET_TRIPLE "x86_64-pc-windows-msvc"
#define LLVM_HOST_TRIPLE "x86_64-pc-windows-msvc"
#define LLVM_VERSION_MAJOR 21
#define LLVM_VERSION_MINOR 1
#define LLVM_VERSION_PATCH 0
#define LLVM_VERSION_STRING "21.1.0"
#define LLVM_ENABLE_LLVM_C_EXPORT_ANNOTATIONS 1
#endif
""")

targets = ['AArch64', 'ARM', 'BPF', 'NVPTX', 'RISCV', 'WebAssembly', 'X86']
printers = ['AArch64', 'ARM', 'BPF', 'NVPTX', 'RISCV', 'WebAssembly', 'X86']
parsers = ['AArch64', 'ARM', 'BPF', 'RISCV', 'WebAssembly', 'X86']
disasms = ['AArch64', 'ARM', 'BPF', 'RISCV', 'WebAssembly', 'X86']
mcas = ['RISCV', 'X86']

with open(os.path.join(cfg_dir, "Targets.def"), "w", encoding="utf-8") as f:
    for t in targets:
        f.write(f"LLVM_TARGET({t})\n")

with open(os.path.join(cfg_dir, "AsmPrinters.def"), "w", encoding="utf-8") as f:
    for t in printers:
        f.write(f"LLVM_ASM_PRINTER({t})\n")

with open(os.path.join(cfg_dir, "AsmParsers.def"), "w", encoding="utf-8") as f:
    for t in parsers:
        f.write(f"LLVM_ASM_PARSER({t})\n")

with open(os.path.join(cfg_dir, "Disassemblers.def"), "w", encoding="utf-8") as f:
    for t in disasms:
        f.write(f"LLVM_DISASSEMBLER({t})\n")

with open(os.path.join(cfg_dir, "TargetMCAs.def"), "w", encoding="utf-8") as f:
    for t in mcas:
        f.write(f"LLVM_TARGETMCA({t})\n")

# Compile llvm-config.rs
llvm_config_rs = os.path.join(base_dir, "llvm-config.rs")
with open(llvm_config_rs, "w", encoding="utf-8") as f:
    f.write(r'''use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let prefix = env::current_exe()
        .ok()
        .and_then(|p| p.parent().and_then(|p| p.parent().map(|p| p.to_path_buf())))
        .unwrap_or_else(|| std::path::PathBuf::from("C:\\LLVM21"));
    let prefix_str = prefix.to_string_lossy().replace('\\', "/");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--version" => {
                println!("21.1.0");
            }
            "--cflags" => {
                println!("-I{}/include", prefix_str);
            }
            "--libdir" => {
                println!("{}/lib", prefix_str);
            }
            "--build-mode" => {
                println!("Release");
            }
            "--system-libs" => {
                println!();
                if i + 1 < args.len() && args[i + 1].starts_with("--link-") {
                    i += 1;
                }
            }
            "--libnames" => {
                println!("LLVM-C.lib");
                if i + 1 < args.len() && args[i + 1].starts_with("--link-") {
                    i += 1;
                }
            }
            "--shared-mode" => {
                println!("shared");
            }
            "--has-rtti" => {
                println!("YES");
            }
            "--assertion-mode" => {
                println!("OFF");
            }
            _ => {}
        }
        i += 1;
    }
}
''')

llvm_config_exe = os.path.join(base_dir, "bin", "llvm-config.exe")
subprocess.check_call(["rustc", "-O", llvm_config_rs, "-o", llvm_config_exe])
print("Built:", llvm_config_exe)
