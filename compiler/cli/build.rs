fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "JOCKEY");
        res.set("FileDescription", "JOCKEY Digital Forensics Platform");
        res.set("CompanyName", "JOCKEY");
        res.set("LegalCopyright", "Copyright (c) 2026 JOCKEY");
        res.set("OriginalFilename", "jockey.exe");
        res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
        res.set("FileVersion", env!("CARGO_PKG_VERSION"));
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=Failed to compile Windows PE resource: {}", e);
        }
    }
}
