fn main() {
    println!("cargo:rerun-if-changed=reipa.ico");
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("reipa.ico");
        let _ = res.compile();
    }
}
