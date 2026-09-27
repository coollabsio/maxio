use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-env-changed=SKIP_FRONTEND");
    println!("cargo:rerun-if-changed=ui/package.json");
    println!("cargo:rerun-if-changed=ui/bun.lock");
    println!("cargo:rerun-if-changed=ui/index.html");
    println!("cargo:rerun-if-changed=ui/vite.config.ts");
    println!("cargo:rerun-if-changed=ui/src");
    println!("cargo:rerun-if-changed=ui/public");
    println!("cargo:rerun-if-changed=ui/dist");

    let ui_dir = Path::new("ui");
    let build_dir = ui_dir.join("dist");

    if std::env::var("SKIP_FRONTEND").ok().as_deref() == Some("1") {
        ensure_minimal_frontend(&build_dir);
        return;
    }

    let existing_artifact = build_dir.join("index.html");
    if existing_artifact.exists() && !frontend_inputs_newer_than(&existing_artifact) {
        return;
    }

    run_bun_install_if_needed(ui_dir);
    run(ui_dir, "bun", &["run", "build"]);
}

fn run_bun_install_if_needed(ui_dir: &Path) {
    let node_modules = ui_dir.join("node_modules");
    let package_json = ui_dir.join("package.json");
    let bun_lock = ui_dir.join("bun.lock");

    let needs_install = !node_modules.exists()
        || mtime(&package_json) > mtime(&node_modules)
        || mtime(&bun_lock) > mtime(&node_modules);

    if needs_install {
        run(ui_dir, "bun", &["install", "--frozen-lockfile"]);
    }
}

fn run(cwd: &Path, program: &str, args: &[&str]) {
    let status = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|err| panic!("failed to run {program}: {err}"));

    if !status.success() {
        panic!("{program} {} failed with {status}", args.join(" "));
    }
}

fn frontend_inputs_newer_than(artifact: &Path) -> bool {
    let artifact_mtime = mtime(artifact);
    let roots = [
        PathBuf::from("ui/package.json"),
        PathBuf::from("ui/bun.lock"),
        PathBuf::from("ui/index.html"),
        PathBuf::from("ui/vite.config.ts"),
        PathBuf::from("ui/src"),
        PathBuf::from("ui/public"),
    ];

    roots.iter().any(|path| newest_mtime(path) > artifact_mtime)
}

fn newest_mtime(path: &Path) -> SystemTime {
    if path.is_dir() {
        fs::read_dir(path)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .map(|entry| newest_mtime(&entry.path()))
            .max()
            .unwrap_or(SystemTime::UNIX_EPOCH)
    } else {
        mtime(path)
    }
}

fn mtime(path: &Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

fn ensure_minimal_frontend(build_dir: &Path) {
    fs::create_dir_all(build_dir).expect("create ui/dist for SKIP_FRONTEND");
    let fallback = build_dir.join("index.html");
    if !fallback.exists() {
        fs::write(
            &fallback,
            "<!doctype html><title>MaxIO</title><body>UI build skipped</body>",
        )
        .expect("write minimal ui/dist/index.html");
    }
}
