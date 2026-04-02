// BlackMagic bridge — .bm is source of truth, .rs are symlinked build artifacts
// Recursive: handles src/ and all subdirectories (scanner/, realtime/, etc.)
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

fn link_dir(dir: &Path) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            link_dir(&path); // recurse into subdirs
        } else if path.extension().and_then(|e| e.to_str()) == Some("bm") {
            let rs = path.with_extension("rs");
            if !rs.exists() {
                let bm_name = path.file_name().unwrap();
                let _ = symlink(Path::new(bm_name), &rs);
            }
        }
    }
}

fn main() {
    let src = Path::new("src");
    if src.exists() {
        link_dir(src);
    }
    println!("cargo:rerun-if-changed=src");
}
