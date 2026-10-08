use super::*;
use sha2::{Digest, Sha256};

const LEGACY_SERVICE: &str = "org.opennow.boosteroid";
const SERVICE: &str = "org.opennow.boosteroid.vault.v1";
const CHUNK_BYTES: usize = 2560;
const MAX_VALUE_BYTES: usize = 320 * 1024;
const MAX_CHUNKS: usize = MAX_VALUE_BYTES / CHUNK_BYTES;
const MAGIC: &[u8; 8] = b"ONBVAULT";
const MANIFEST_BYTES: usize = 44;
static MUTATION: Mutex<()> = Mutex::new(());

pub(super) trait SecretStore {
    fn read(&self, service: &str, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn write(&self, service: &str, key: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, service: &str, key: &str) -> Result<()>;
}

pub(super) struct CredentialStore<B>(B);

impl<B: SecretStore> CredentialStore<B> {
    pub(super) fn new(backend: B) -> Self {
        Self(backend)
    }

    pub(super) fn put(&self, key: &str, value: &str) -> Result<()> {
        let _guard = MUTATION.lock().map_err(|_| Error::internal())?;
        let reference = Reference::new(key)?;
        if value.len() > MAX_VALUE_BYTES {
            return Err(Error::new(Code::ServiceUnavailable));
        }
        if self.0.read(LEGACY_SERVICE, key)?.is_some()
            || self.0.read(SERVICE, &reference.root())?.is_some()
        {
            return Err(Error::new(Code::ServiceUnavailable));
        }
        for index in 0..MAX_CHUNKS {
            if self.0.read(SERVICE, &reference.chunk(index))?.is_some() {
                return Err(Error::new(Code::ServiceUnavailable));
            }
        }
        let manifest = Manifest::new(value.as_bytes());
        for index in 0..manifest.chunks() {
            let start = index * CHUNK_BYTES;
            let end = (start + CHUNK_BYTES).min(value.len());
            if self
                .0
                .write(
                    SERVICE,
                    &reference.chunk(index),
                    &value.as_bytes()[start..end],
                )
                .is_err()
            {
                self.cleanup(&reference, index + 1, false)?;
                return Err(Error::new(Code::ServiceUnavailable));
            }
        }
        if self
            .0
            .write(SERVICE, &reference.root(), &manifest.encode())
            .is_err()
        {
            self.cleanup(&reference, manifest.chunks(), true)?;
            return Err(Error::new(Code::ServiceUnavailable));
        }
        Ok(())
    }

    pub(super) fn get(&self, key: &str) -> Result<Zeroizing<String>> {
        self.read(key).map_err(|_| Error::new(Code::AuthRequired))
    }

    fn read(&self, key: &str) -> Result<Zeroizing<String>> {
        let reference = Reference::new(key)?;
        let Some(raw) = self.0.read(SERVICE, &reference.root())? else {
            let legacy = self
                .0
                .read(LEGACY_SERVICE, key)?
                .ok_or_else(Error::invalid)?;
            if legacy.len() > CHUNK_BYTES || legacy.len() % 2 != 0 {
                return Err(Error::invalid());
            }
            let units = legacy
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
            let mut value = Zeroizing::new(String::with_capacity(legacy.len() / 2 * 3));
            for character in char::decode_utf16(units) {
                value.push(character.map_err(|_| Error::invalid())?);
            }
            return Ok(value);
        };
        let manifest = Manifest::parse(&raw)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(manifest.length));
        for index in 0..manifest.chunks() {
            let chunk = self
                .0
                .read(SERVICE, &reference.chunk(index))?
                .ok_or_else(Error::invalid)?;
            if chunk.len() != (manifest.length - bytes.len()).min(CHUNK_BYTES) {
                return Err(Error::invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        if Sha256::digest(&bytes).as_slice() != manifest.digest {
            return Err(Error::invalid());
        }
        let value = std::str::from_utf8(&bytes).map_err(|_| Error::invalid())?;
        Ok(Zeroizing::new(value.to_owned()))
    }

    pub(super) fn remove(&self, key: &str) -> Result<()> {
        let _guard = MUTATION.lock().map_err(|_| Error::internal())?;
        let reference = Reference::new(key)?;
        let chunks = self.cleanup(&reference, MAX_CHUNKS, true);
        let legacy = self.0.delete(LEGACY_SERVICE, key);
        chunks.and(legacy)
    }

    fn cleanup(&self, reference: &Reference, chunks: usize, root: bool) -> Result<()> {
        let mut result = Ok(());
        if root {
            result = self.0.delete(SERVICE, &reference.root());
        }
        for index in 0..chunks {
            let deleted = self.0.delete(SERVICE, &reference.chunk(index));
            result = result.and(deleted);
        }
        result
    }
}

struct Reference(String);

impl Reference {
    fn new(key: &str) -> Result<Self> {
        if key.is_empty() || key.len() > 512 || key.contains('\0') {
            return Err(Error::new(Code::ServiceUnavailable));
        }
        Ok(Self(hex::encode(Sha256::digest(key.as_bytes()))))
    }

    fn root(&self) -> String {
        format!("manifest-{}", self.0)
    }

    fn chunk(&self, index: usize) -> String {
        format!("chunk-{}-{index}", self.0)
    }
}

struct Manifest {
    length: usize,
    digest: [u8; 32],
}

impl Manifest {
    fn new(value: &[u8]) -> Self {
        Self {
            length: value.len(),
            digest: Sha256::digest(value).into(),
        }
    }

    fn chunks(&self) -> usize {
        self.length.div_ceil(CHUNK_BYTES).max(1)
    }

    fn encode(&self) -> [u8; MANIFEST_BYTES] {
        let mut bytes = [0; MANIFEST_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&(self.length as u32).to_le_bytes());
        bytes[12..].copy_from_slice(&self.digest);
        bytes
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MANIFEST_BYTES || &bytes[..8] != MAGIC {
            return Err(Error::invalid());
        }
        let length =
            u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| Error::invalid())?) as usize;
        if length > MAX_VALUE_BYTES {
            return Err(Error::invalid());
        }
        Ok(Self {
            length,
            digest: bytes[12..].try_into().map_err(|_| Error::invalid())?,
        })
    }
}

#[cfg(windows)]
pub(super) struct OsSecrets;

#[cfg(windows)]
impl SecretStore for OsSecrets {
    fn read(&self, service: &str, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match keyring::Entry::new(service, key).and_then(|entry| entry.get_secret()) {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(Error::new(Code::ServiceUnavailable)),
        }
    }

    fn write(&self, service: &str, key: &str, value: &[u8]) -> Result<()> {
        keyring::Entry::new(service, key)
            .and_then(|entry| entry.set_secret(value))
            .map_err(|_| Error::new(Code::ServiceUnavailable))
    }

    fn delete(&self, service: &str, key: &str) -> Result<()> {
        match keyring::Entry::new(service, key).and_then(|entry| entry.delete_credential()) {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(Error::new(Code::ServiceUnavailable)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeSet;

    type EntryId = (String, String);

    #[derive(Default)]
    struct MemorySecrets {
        entries: RefCell<HashMap<EntryId, Zeroizing<Vec<u8>>>>,
        reads: Cell<usize>,
        writes: RefCell<Vec<EntryId>>,
        deletes: RefCell<Vec<EntryId>>,
        fail_reads: RefCell<BTreeSet<usize>>,
        fail_writes: RefCell<BTreeSet<usize>>,
        fail_after_write: Cell<bool>,
        fail_deletes: RefCell<BTreeSet<usize>>,
    }

    impl MemorySecrets {
        fn seed(&self, service: &str, key: &str, value: &[u8]) {
            self.entries.borrow_mut().insert(
                (service.to_owned(), key.to_owned()),
                Zeroizing::new(value.to_vec()),
            );
        }

        fn legacy(&self, key: &str, value: &str) {
            let bytes = Zeroizing::new(
                value
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            );
            self.seed(LEGACY_SERVICE, key, &bytes);
        }

        fn fail_write(&self, index: usize, after: bool) {
            self.fail_writes.borrow_mut().insert(index);
            self.fail_after_write.set(after);
        }
    }

    impl SecretStore for MemorySecrets {
        fn read(&self, service: &str, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            let index = self.reads.get();
            self.reads.set(index + 1);
            if self.fail_reads.borrow_mut().remove(&index) {
                return Err(Error::new(Code::ServiceUnavailable));
            }
            Ok(self
                .entries
                .borrow()
                .get(&(service.to_owned(), key.to_owned()))
                .cloned())
        }

        fn write(&self, service: &str, key: &str, value: &[u8]) -> Result<()> {
            let index = self.writes.borrow().len();
            self.writes
                .borrow_mut()
                .push((service.to_owned(), key.to_owned()));
            if value.len() > CHUNK_BYTES {
                return Err(Error::new(Code::ServiceUnavailable));
            }
            let fail = self.fail_writes.borrow_mut().remove(&index);
            if !fail || self.fail_after_write.get() {
                self.seed(service, key, value);
            }
            if fail {
                return Err(Error::new(Code::ServiceUnavailable));
            }
            Ok(())
        }

        fn delete(&self, service: &str, key: &str) -> Result<()> {
            let index = self.deletes.borrow().len();
            self.deletes
                .borrow_mut()
                .push((service.to_owned(), key.to_owned()));
            if self.fail_deletes.borrow_mut().remove(&index) {
                return Err(Error::new(Code::ServiceUnavailable));
            }
            self.entries
                .borrow_mut()
                .remove(&(service.to_owned(), key.to_owned()));
            Ok(())
        }
    }

    #[test]
    fn persists_2619_byte_login_with_windows_blob_limit() {
        let store = CredentialStore::new(MemorySecrets::default());
        let value = "a".repeat(2619);
        assert_eq!(value.encode_utf16().count() * 2, 5238);
        assert!(store.put("credential-test", &value).is_ok());
        assert_eq!(store.get("credential-test").unwrap().as_str(), value);
        assert_eq!(store.0.entries.borrow().len(), 3);
        assert_eq!(
            store.0.writes.borrow().last().unwrap().1,
            Reference::new("credential-test").unwrap().root()
        );
        assert!(
            store
                .0
                .entries
                .borrow()
                .values()
                .all(|bytes| bytes.len() <= CHUNK_BYTES)
        );
    }

    #[test]
    fn roundtrips_boundaries_and_split_utf8_across_restarts() {
        for size in [
            0,
            1,
            1280,
            1281,
            CHUNK_BYTES - 1,
            CHUNK_BYTES,
            CHUNK_BYTES + 1,
            MAX_VALUE_BYTES - 1,
            MAX_VALUE_BYTES,
        ] {
            let store = CredentialStore::new(MemorySecrets::default());
            let value = "x".repeat(size);
            store.put("credential-test", &value).unwrap();
            let restarted = CredentialStore::new(store.0);
            assert_eq!(restarted.get("credential-test").unwrap().as_str(), value);
            restarted.remove("credential-test").unwrap();
            assert!(restarted.0.entries.borrow().is_empty());
        }
        let store = CredentialStore::new(MemorySecrets::default());
        let value = format!(
            "{}🦀é漢字{}",
            "x".repeat(CHUNK_BYTES - 1),
            "🦀".repeat(3000)
        );
        store.put("credential-unicode", &value).unwrap();
        assert_eq!(store.get("credential-unicode").unwrap().as_str(), value);
    }

    #[test]
    fn roundtrips_maximum_permitted_credentials_with_json_expansion() {
        use crate::service::Credentials;
        use opennow_plugin_api::provider::SecretString;

        let secret = SecretString::new("\u{1}".repeat(16 * 1024)).unwrap();
        let credentials = Credentials {
            access: secret.clone(),
            refresh: secret.clone(),
            authorization_data: Some(secret),
        };
        let value = Zeroizing::new(serde_json::to_string(&credentials).unwrap());
        assert!(value.len() > 3 * 16 * 1024 * 6);
        let store = CredentialStore::new(MemorySecrets::default());
        store.put("credential-max", &value).unwrap();
        assert_eq!(
            store.get("credential-max").unwrap().as_str(),
            value.as_str()
        );
    }

    #[test]
    fn reads_and_removes_legacy_utf16_entries_without_rewriting() {
        for value in ["", "legacy token", "héllo🦀漢字"] {
            let store = CredentialStore::new(MemorySecrets::default());
            store.0.legacy("legacy", value);
            assert_eq!(store.get("legacy").unwrap().as_str(), value);
            assert!(store.0.writes.borrow().is_empty());
            store.remove("legacy").unwrap();
            store.remove("legacy").unwrap();
            assert!(store.0.entries.borrow().is_empty());
        }
    }

    #[test]
    fn rejects_invalid_legacy_encoding_and_missing_entries() {
        let store = CredentialStore::new(MemorySecrets::default());
        assert_eq!(store.get("missing").unwrap_err().code, Code::AuthRequired);
        for value in [vec![1], vec![0, 0xd8], vec![0; CHUNK_BYTES + 2]] {
            store.0.seed(LEGACY_SERVICE, "legacy", &value);
            assert_eq!(store.get("legacy").unwrap_err().code, Code::AuthRequired);
        }
    }

    #[test]
    fn rejects_oversized_values_and_invalid_references_before_io() {
        let store = CredentialStore::new(MemorySecrets::default());
        assert!(store.put("key", &"x".repeat(MAX_VALUE_BYTES + 1)).is_err());
        for key in ["".to_owned(), "bad\0key".to_owned(), "x".repeat(513)] {
            assert!(store.put(&key, "secret").is_err());
            assert!(store.get(&key).is_err());
            assert!(store.remove(&key).is_err());
        }
        assert_eq!(store.0.reads.get(), 0);
        assert!(store.0.writes.borrow().is_empty());
        assert!(store.0.deletes.borrow().is_empty());
    }

    #[test]
    fn existing_manifests_legacy_entries_and_orphan_chunks_are_immutable() {
        let reference = Reference::new("key").unwrap();
        for (service, key) in [
            (LEGACY_SERVICE, "key".to_owned()),
            (SERVICE, reference.root()),
            (SERVICE, reference.chunk(MAX_CHUNKS - 1)),
        ] {
            let store = CredentialStore::new(MemorySecrets::default());
            store.0.seed(service, &key, b"existing");
            assert!(store.put("key", "replacement").is_err());
            assert!(store.0.writes.borrow().is_empty());
            assert!(store.0.deletes.borrow().is_empty());
            assert_eq!(
                store.0.read(service, &key).unwrap().unwrap().as_slice(),
                b"existing"
            );
        }
        let store = CredentialStore::new(MemorySecrets::default());
        store.put("key", "first").unwrap();
        assert!(store.put("key", "second").is_err());
        assert_eq!(store.get("key").unwrap().as_str(), "first");
    }

    #[test]
    fn preflight_read_failures_never_mutate_the_store() {
        for index in 0..MAX_CHUNKS + 2 {
            let store = CredentialStore::new(MemorySecrets::default());
            store.0.fail_reads.borrow_mut().insert(index);
            assert!(store.put("key", "new secret").is_err());
            assert!(store.0.writes.borrow().is_empty());
            assert!(store.0.deletes.borrow().is_empty());
        }
    }

    #[test]
    fn rolls_back_every_write_failure_including_ambiguous_publication() {
        let value = "a".repeat(CHUNK_BYTES * 2 + 1);
        for after in [false, true] {
            for index in 0..4 {
                let store = CredentialStore::new(MemorySecrets::default());
                store.0.legacy("unrelated", "keep");
                store.0.fail_write(index, after);
                assert!(store.put("key", &value).is_err());
                assert_eq!(store.0.entries.borrow().len(), 1);
                assert_eq!(store.get("unrelated").unwrap().as_str(), "keep");
                assert_eq!(store.get("key").unwrap_err().code, Code::AuthRequired);
                assert_eq!(store.0.writes.borrow().len(), index + 1);
            }
        }
    }

    #[test]
    fn failed_rollback_is_unreadable_and_explicit_removal_retries_all_chunks() {
        for failed_write in [1, 3] {
            let store = CredentialStore::new(MemorySecrets::default());
            store.0.fail_write(failed_write, true);
            store.0.fail_deletes.borrow_mut().insert(0);
            assert!(store.put("key", &"x".repeat(CHUNK_BYTES * 2 + 1)).is_err());
            assert!(!store.0.entries.borrow().is_empty());
            assert_eq!(store.get("key").unwrap_err().code, Code::AuthRequired);
            store.remove("key").unwrap();
            assert!(store.0.entries.borrow().is_empty());
        }
    }

    #[test]
    fn remove_attempts_every_entry_after_any_failure_and_can_be_retried() {
        for index in 0..MAX_CHUNKS + 2 {
            let store = CredentialStore::new(MemorySecrets::default());
            store.put("key", &"x".repeat(CHUNK_BYTES + 1)).unwrap();
            store.0.legacy("key", "old");
            store.0.legacy("unrelated", "keep");
            store.0.fail_deletes.borrow_mut().insert(index);
            assert!(store.remove("key").is_err());
            assert_eq!(store.0.deletes.borrow().len(), MAX_CHUNKS + 2);
            assert_eq!(store.get("unrelated").unwrap().as_str(), "keep");
            store.remove("key").unwrap();
            assert_eq!(store.0.entries.borrow().len(), 1);
        }
    }

    #[test]
    fn malformed_manifests_do_not_fall_back_or_drive_unbounded_reads() {
        let reference = Reference::new("key").unwrap();
        let mut oversized = Manifest::new(b"value").encode();
        oversized[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        for raw in [
            vec![],
            vec![0; MANIFEST_BYTES],
            vec![0; CHUNK_BYTES],
            oversized.to_vec(),
        ] {
            let store = CredentialStore::new(MemorySecrets::default());
            store.0.legacy("key", "legacy");
            store.0.seed(SERVICE, &reference.root(), &raw);
            assert_eq!(store.get("key").unwrap_err().code, Code::AuthRequired);
            assert_eq!(store.0.reads.get(), 1);
            store.remove("key").unwrap();
            assert!(store.0.entries.borrow().is_empty());
        }
    }

    #[test]
    fn missing_corrupt_and_wrong_sized_chunks_never_return_partial_secrets() {
        let reference = Reference::new("key").unwrap();
        for replacement in [
            None,
            Some(vec![]),
            Some(vec![b'x'; CHUNK_BYTES - 1]),
            Some(vec![b'x'; CHUNK_BYTES]),
            Some(vec![b'x'; CHUNK_BYTES + 1]),
        ] {
            let store = CredentialStore::new(MemorySecrets::default());
            store.put("key", &"a".repeat(CHUNK_BYTES + 1)).unwrap();
            store.0.delete(SERVICE, &reference.chunk(0)).unwrap();
            if let Some(value) = replacement {
                store.0.seed(SERVICE, &reference.chunk(0), &value);
            }
            assert_eq!(store.get("key").unwrap_err().code, Code::AuthRequired);
        }
        let store = CredentialStore::new(MemorySecrets::default());
        store
            .0
            .seed(SERVICE, &reference.root(), &Manifest::new(&[0xff]).encode());
        store.0.seed(SERVICE, &reference.chunk(0), &[0xff]);
        assert_eq!(store.get("key").unwrap_err().code, Code::AuthRequired);
    }

    #[test]
    fn read_errors_never_fall_back_to_stale_legacy_values() {
        for index in 0..3 {
            let store = CredentialStore::new(MemorySecrets::default());
            store.put("key", &"x".repeat(CHUNK_BYTES + 1)).unwrap();
            store.0.legacy("key", "stale");
            store
                .0
                .fail_reads
                .borrow_mut()
                .insert(store.0.reads.get() + index);
            assert_eq!(store.get("key").unwrap_err().code, Code::AuthRequired);
        }
    }

    #[test]
    fn cleanup_is_scoped_to_the_reference_even_with_a_corrupt_manifest() {
        let store = CredentialStore::new(MemorySecrets::default());
        store.put("other", &"x".repeat(CHUNK_BYTES + 1)).unwrap();
        let root = Reference::new("key").unwrap().root();
        store.0.seed(SERVICE, &root, b"other");
        store.remove("key").unwrap();
        assert_eq!(
            store.get("other").unwrap().as_str(),
            "x".repeat(CHUNK_BYTES + 1)
        );
        store.remove("other").unwrap();
        assert!(store.0.entries.borrow().is_empty());
    }
}
