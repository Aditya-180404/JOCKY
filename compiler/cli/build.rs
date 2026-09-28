fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "JOCKY");
        res.set("FileDescription", "JOCKY Digital Forensics Platform");
        res.set("CompanyName", "JOCKY");
        res.set("LegalCopyright", "Copyright (c) 2026 JOCKY");
        res.set("OriginalFilename", "jocky.exe");
        res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
        res.set("FileVersion", env!("CARGO_PKG_VERSION"));
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=Failed to compile Windows PE resource: {}", e);
        }
    }
}
