use std::{fs, path::Path};

pub fn mutate_file(path: &Path, mutation: impl FnOnce(&mut Vec<u8>)) {
    let mut bytes = fs::read(path).expect("fault target must be readable");
    mutation(&mut bytes);
    fs::write(path, bytes).expect("fault target must be writable");
}

pub fn restore_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("fault target must be restorable");
}
