use std::path::PathBuf;

pub fn find_path(filename: &str) -> PathBuf {
    if filename.contains('/') {
        return PathBuf::from(filename);
    }
    let paths = match std::env::var("PATH") {
        Ok(x) => x,
        Err(_) => {
            return PathBuf::from(filename);
        }
    };
    let paths_split = paths.split(':');
    for p in paths_split {
        let mut path = PathBuf::from(p);
        path.push(filename);
        if path.exists() {
            return path;
        }
    }
    return PathBuf::from(filename);
}