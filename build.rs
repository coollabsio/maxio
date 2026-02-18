fn main() {
    let version = std::fs::read_to_string("VERSION")
        .expect("VERSION file not found")
        .trim()
        .to_string();
    println!("cargo:rustc-env=MAXIO_VERSION={version}");
    println!("cargo:rerun-if-changed=VERSION");
}
