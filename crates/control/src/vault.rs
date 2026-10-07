use crate::{Error, Result};
use opennow_plugin_api::provider::ProviderErrorCode as Code;
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

#[cfg(any(windows, test))]
mod windows;

pub trait Vault: Send + Sync {
    fn put(&self, key: &str, value: &str) -> Result<()>;
    fn get(&self, key: &str) -> Result<Zeroizing<String>>;
    fn remove(&self, key: &str) -> Result<()>;
}

pub struct CredentialVault;

#[cfg(not(windows))]
impl Vault for CredentialVault {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        keyring::Entry::new("org.opennow.boosteroid", key)
            .and_then(|entry| entry.set_password(value))
            .map_err(|_| Error::new(Code::ServiceUnavailable))
    }
    fn get(&self, key: &str) -> Result<Zeroizing<String>> {
        keyring::Entry::new("org.opennow.boosteroid", key)
            .and_then(|entry| entry.get_password())
            .map(Zeroizing::new)
            .map_err(|_| Error::new(Code::AuthRequired))
    }
    fn remove(&self, key: &str) -> Result<()> {
        let result = keyring::Entry::new("org.opennow.boosteroid", key)
            .and_then(|entry| entry.delete_credential());
        match result {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(Error::new(Code::ServiceUnavailable)),
        }
    }
}

#[cfg(windows)]
impl Vault for CredentialVault {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        windows::CredentialStore::new(windows::OsSecrets).put(key, value)
    }
    fn get(&self, key: &str) -> Result<Zeroizing<String>> {
        windows::CredentialStore::new(windows::OsSecrets).get(key)
    }
    fn remove(&self, key: &str) -> Result<()> {
        windows::CredentialStore::new(windows::OsSecrets).remove(key)
    }
}

#[derive(Default)]
pub struct TemporaryVault(Mutex<HashMap<String, Zeroizing<String>>>);

impl Vault for TemporaryVault {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        let mut values = self.0.lock().map_err(|_| Error::internal())?;
        if !values.contains_key(key) && values.len() >= 256 {
            return Err(Error::new(Code::BusyBeforeDispatch));
        }
        values.insert(key.to_owned(), Zeroizing::new(value.to_owned()));
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Zeroizing<String>> {
        self.0
            .lock()
            .map_err(|_| Error::internal())?
            .get(key)
            .cloned()
            .ok_or_else(|| Error::new(Code::AuthRequired))
    }
    fn remove(&self, key: &str) -> Result<()> {
        self.0.lock().map_err(|_| Error::internal())?.remove(key);
        Ok(())
    }
}
