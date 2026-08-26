use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    panic,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

use evertrace_capture::{
    ArchiveMode, CasDigest, CasError, CasStore, DeviceKeyError, DeviceKeyStore, SecretKind, protect,
};
use tempfile::TempDir;

#[path = "../src/fault.rs"]
mod fault;
#[path = "../src/fixture.rs"]
mod fixture;

const CANARY: &[u8] = b"S04_CANARY_SECRET_123456";

fn key_store(root: &Path) -> DeviceKeyStore {
    DeviceKeyStore::new(root.join("device-key"))
}

fn active_key(root: &Path) -> evertrace_capture::DeviceKey {
    key_store(root).load_or_create().unwrap()
}

#[test]
fn detector_distinguishes_exact_redacted_and_non_utf8_inputs() {
    let root = TempDir::new().unwrap();
    let key = active_key(root.path());
    for (name, input, redacted) in fixture::detector_cases() {
        let protected = protect(&input, &key).unwrap();
        assert_eq!(
            protected.archive_mode(),
            if redacted {
                ArchiveMode::Redacted
            } else {
                ArchiveMode::Exact
            },
            "{name}"
        );
        if !redacted {
            assert_eq!(protected.protected_bytes(), input);
            assert_eq!(protected.protected_secret_digest(), None);
        }
    }

    let non_utf8 = b"prefix\xff token=abcdefgh suffix";
    let protected = protect(non_utf8, &key).unwrap();
    assert_eq!(protected.archive_mode(), ArchiveMode::Redacted);
    assert!(!contains(protected.protected_bytes(), b"abcdefgh"));
    assert_eq!(protected.detector_revision(), 1);
    assert_eq!(protected.redaction_revision(), 1);
}

#[test]
fn detector_spans_are_sorted_nonoverlapping_and_priority_is_stable() {
    let root = TempDir::new().unwrap();
    let key = active_key(root.path());
    let input = b"api_key=abcdefgh Authorization: Bearer token=ijklmnop password=qrstuvwx";
    let protected = protect(input, &key).unwrap();
    assert_eq!(protected.spans().len(), 3);
    assert_eq!(protected.spans()[1].kind(), SecretKind::AuthorizationBearer);
    assert!(
        protected
            .spans()
            .windows(2)
            .all(|pair| pair[0].end() <= pair[1].start())
    );

    let pem = b"-----BEGIN RSA PRIVATE KEY-----\napi_key=abcdefgh\n-----END RSA PRIVATE KEY-----";
    let protected = protect(pem, &key).unwrap();
    assert_eq!(protected.spans().len(), 1);
    assert_eq!(protected.spans()[0].kind(), SecretKind::PemPrivateKey);
}

#[test]
fn keyed_digest_is_stable_and_distinguishes_equal_redactions() {
    let root = TempDir::new().unwrap();
    let key = active_key(root.path());
    let first = protect(b"api_key=AAAAAAAA", &key).unwrap();
    let same = protect(b"api_key=AAAAAAAA", &key).unwrap();
    let different = protect(b"api_key=BBBBBBBB", &key).unwrap();
    assert_eq!(first.protected_bytes(), different.protected_bytes());
    assert_eq!(
        first.protected_secret_digest(),
        same.protected_secret_digest()
    );
    assert_ne!(
        first.protected_secret_digest(),
        different.protected_secret_digest()
    );
    assert_eq!(first.key_generation(), 1);
}

#[test]
fn device_key_create_concurrency_reload_rotation_and_backup_exclusion() {
    let root = TempDir::new().unwrap();
    let store = key_store(root.path());
    assert_eq!(store.load(), Err(DeviceKeyError::Missing));
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let key = store.load_or_create().unwrap();
                protect(b"token=abcdefgh", &key)
                    .unwrap()
                    .protected_secret_digest()
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let digests = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert!(digests.iter().all(|digest| digest == &digests[0]));

    let first = store.load().unwrap();
    let first_identity = protect(b"token=abcdefgh", &first)
        .unwrap()
        .protected_secret_digest();
    let rotated = store.rotate().unwrap();
    assert_eq!(rotated.generation(), first.generation() + 1);
    assert_ne!(
        first_identity,
        protect(b"token=abcdefgh", &rotated)
            .unwrap()
            .protected_secret_digest()
    );
    assert_eq!(store.load().unwrap().generation(), rotated.generation());
    assert!(!store.ordinary_backup_includes(&store.active_path()));
    assert!(store.ordinary_backup_includes(&root.path().join("cas")));
}

#[test]
fn device_key_permissions_symlinks_types_and_corruption_fail_closed() {
    let root = TempDir::new().unwrap();
    let store = key_store(root.path());
    store.load_or_create().unwrap();
    fs::set_permissions(store.active_path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(store.load(), Err(DeviceKeyError::WrongPermissions));
    fs::set_permissions(store.active_path(), fs::Permissions::from_mode(0o600)).unwrap();
    fault::mutate_file(&store.active_path(), |bytes| bytes.truncate(10));
    assert_eq!(store.load(), Err(DeviceKeyError::Corrupt));

    let file_link_root = root.path().join("file-link-key");
    fs::create_dir(&file_link_root).unwrap();
    fs::set_permissions(&file_link_root, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(store.active_path(), file_link_root.join("active.key")).unwrap();
    assert_eq!(
        DeviceKeyStore::new(&file_link_root).load(),
        Err(DeviceKeyError::InvalidType)
    );

    let wrong_dir = root.path().join("wrong-dir");
    fs::create_dir(&wrong_dir).unwrap();
    fs::set_permissions(&wrong_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        DeviceKeyStore::new(&wrong_dir).load_or_create(),
        Err(DeviceKeyError::WrongPermissions)
    );
    let file_path = root.path().join("not-dir");
    fs::write(&file_path, b"not a directory").unwrap();
    assert_eq!(
        DeviceKeyStore::new(&file_path).load_or_create(),
        Err(DeviceKeyError::InvalidType)
    );
    let link_path = root.path().join("key-link");
    symlink(&wrong_dir, &link_path).unwrap();
    assert_eq!(
        DeviceKeyStore::new(&link_path).load_or_create(),
        Err(DeviceKeyError::InvalidType)
    );
}

#[test]
fn cas_round_trip_deduplicates_reopens_and_ignores_unknown_staging() {
    let root = TempDir::new().unwrap();
    let key = active_key(root.path());
    let payload = protect(b"api_key=abcdefgh", &key).unwrap();
    let cas_root = root.path().join("cas");
    let store = CasStore::open(&cas_root).unwrap();
    let digest = store.put(&payload).unwrap();
    let path = store.blob_path(&digest);
    let before = fs::metadata(&path).unwrap();
    assert_eq!(store.read(&digest).unwrap(), payload.protected_bytes());
    assert_eq!(store.put(&payload).unwrap(), digest);
    assert_eq!(before.ino(), fs::metadata(&path).unwrap().ino());

    let staging = path
        .parent()
        .unwrap()
        .join(".blob.tmp-owned-by-unknown-test");
    fs::write(&staging, b"torn").unwrap();
    let reopened = CasStore::open(&cas_root).unwrap();
    assert_eq!(reopened.read(&digest).unwrap(), payload.protected_bytes());
    assert!(staging.exists());
}

#[test]
fn cas_rejects_truncation_versions_lengths_digests_and_traversal() {
    let root = TempDir::new().unwrap();
    let key = active_key(root.path());
    let payload = protect(b"ordinary payload", &key).unwrap();
    let store = CasStore::open(root.path().join("cas")).unwrap();
    let digest = store.put(&payload).unwrap();
    let path = store.blob_path(&digest);
    let original = fs::read(&path).unwrap();
    for mutation in 0..7 {
        fault::restore_file(&path, &original);
        fault::mutate_file(&path, |bytes| match mutation {
            0 => bytes.truncate(20),
            1 => bytes[8] = 2,
            2 => bytes[10] = 2,
            3 => bytes[16..24].copy_from_slice(&999_u64.to_be_bytes()),
            4 => bytes[12] = 2,
            5 => bytes[24] ^= 1,
            _ => *bytes.last_mut().unwrap() ^= 1,
        });
        assert_eq!(store.read(&digest), Err(CasError::StoreCorrupt));
    }
    fault::restore_file(&path, &original);
    assert_eq!(
        CasStore::parse_digest("../outside"),
        Err(CasError::InvalidDigest)
    );
    assert_eq!(
        CasStore::parse_digest(&"A".repeat(64)),
        Err(CasError::InvalidDigest)
    );

    let wrong = CasDigest::for_protected_bytes(b"different");
    let wrong_path = store.blob_path(&wrong);
    fs::create_dir(wrong_path.parent().unwrap()).unwrap();
    fs::set_permissions(
        wrong_path.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(&wrong_path, &original).unwrap();
    assert_eq!(store.read(&wrong), Err(CasError::StoreCorrupt));
}

#[test]
fn secret_canary_never_reaches_disk_debug_errors_or_panics() {
    let root = TempDir::new().unwrap();
    let store = key_store(root.path());
    let key = store.load_or_create().unwrap();
    let mut input = b"api_key=".to_vec();
    input.extend_from_slice(CANARY);
    let protected = protect(&input, &key).unwrap();
    assert!(!contains(protected.protected_bytes(), CANARY));
    let debug = format!("{protected:?}");
    assert!(
        !debug
            .as_bytes()
            .windows(CANARY.len())
            .any(|value| value == CANARY)
    );
    let panic_result = panic::catch_unwind(|| CasStore::parse_digest("invalid"));
    assert!(panic_result.is_ok());
    let error = CasStore::parse_digest("invalid").unwrap_err().to_string();
    assert!(
        !error
            .as_bytes()
            .windows(CANARY.len())
            .any(|value| value == CANARY)
    );

    let cas = CasStore::open(root.path().join("cas")).unwrap();
    cas.put(&protected).unwrap();
    assert_no_bytes(root.path(), CANARY);

    let failure_root = root.path().join("failure-target");
    fs::write(&failure_root, b"wrong type").unwrap();
    assert_eq!(CasStore::open(&failure_root), Err(CasError::InvalidType));
    assert_no_bytes(root.path(), CANARY);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn assert_no_bytes(path: &Path, needle: &[u8]) {
    let mut pending = vec![PathBuf::from(path)];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.file_type().unwrap();
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(!contains(&bytes, needle));
            }
        }
    }
}

use std::os::unix::fs::MetadataExt;
