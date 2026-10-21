use crate::key_prefix;
use crate::{AssetType, CoFiState, ContributorId, StateKey};
use std::path::Path;

// ---------------------------------------------------------------------------
// StateStore trait
// ---------------------------------------------------------------------------

/// KV persistence for CoFiState. All methods use `&self` — sled is lock-free,
/// and other backends can use interior mutability.
pub trait StateStore {
    type Error: std::error::Error;

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Self::Error>;

    /// Store the Merkle root so it survives restarts.
    fn commit_root(&self, root: &[u8; 32]) -> Result<(), Self::Error> {
        self.put(&[key_prefix::ROOT], root)
    }

    fn load_root(&self) -> Result<Option<[u8; 32]>, Self::Error> {
        match self.get(&[key_prefix::ROOT])? {
            Some(v) if v.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Ok(Some(arr))
            }
            _ => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// SledStore
// ---------------------------------------------------------------------------

pub struct SledStore {
    db: sled::Db,
}

impl SledStore {
    pub fn open(path: &Path) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }
}

impl StateStore for SledStore {
    type Error = sled::Error;

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), sled::Error> {
        self.db.insert(key, value)?;
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, sled::Error> {
        self.db.get(key).map(|opt| opt.map(|iv| iv.to_vec()))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, sled::Error> {
        let mut entries = Vec::new();
        for item in self.db.scan_prefix(prefix) {
            let (key, value) = item?;
            entries.push((key.to_vec(), value.to_vec()));
        }
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// State reconstruction
// ---------------------------------------------------------------------------

/// Errors that can occur when loading state from a store.
pub enum LoadError<S: StateStore> {
    Store(S::Error),
    Corrupt(String),
}

// Manual Debug impl — formats the inner error via Display, so we never need
// S::Error: Debug. This keeps the trait bound minimal.
impl<S: StateStore> std::fmt::Debug for LoadError<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Store(e) => f.debug_tuple("Store").field(&e.to_string()).finish(),
            LoadError::Corrupt(msg) => f.debug_tuple("Corrupt").field(msg).finish(),
        }
    }
}

impl<S: StateStore> std::fmt::Display for LoadError<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Store(e) => write!(f, "store error: {e}"),
            LoadError::Corrupt(msg) => write!(f, "corrupt state: {msg}"),
        }
    }
}

impl<S: StateStore> std::error::Error for LoadError<S> {}

/// Reconstruct a `CoFiState` from a store.
///
/// Scans all `at:`, `cu:`, and total keys, then verifies the result against
/// the stored Merkle root (if one exists).
pub fn load_state<S: StateStore>(store: &S) -> Result<CoFiState, LoadError<S>> {
    let mut state = CoFiState::new();

    // Asset types.
    for (key, value) in store
        .scan_prefix(&[key_prefix::ASSET_TYPE])
        .map_err(LoadError::Store)?
    {
        let sk = StateKey::decode(&key)
            .ok_or_else(|| LoadError::Corrupt("unrecognised state key".into()))?;
        let id = match sk {
            StateKey::AssetType(id) => id,
            _ => return Err(LoadError::Corrupt("expected AssetType key".into())),
        };
        let at: AssetType =
            serde_json::from_slice(&value).map_err(|e| LoadError::Corrupt(e.to_string()))?;
        state.asset_types.insert(id, at);
    }

    // Contributor types.
    for (key, value) in store
        .scan_prefix(&[key_prefix::CONTRIBUTOR_TYPE])
        .map_err(LoadError::Store)?
    {
        let sk = StateKey::decode(&key)
            .ok_or_else(|| LoadError::Corrupt("unrecognised state key".into()))?;
        let id = match sk {
            StateKey::ContributorType(id) => id,
            _ => return Err(LoadError::Corrupt("expected ContributorType key".into())),
        };
        let ct: crate::governance::ContributorType =
            serde_json::from_slice(&value).map_err(|e| LoadError::Corrupt(e.to_string()))?;
        state.contributor_types.insert(id, ct);
    }

    // Contributor units.
    for (key, value) in store
        .scan_prefix(&[key_prefix::CONTRIBUTOR_UNITS])
        .map_err(LoadError::Store)?
    {
        let sk = StateKey::decode(&key)
            .ok_or_else(|| LoadError::Corrupt("unrecognised state key".into()))?;
        let id = match sk {
            StateKey::ContributorUnits(id) => id,
            _ => return Err(LoadError::Corrupt("expected ContributorUnits key".into())),
        };
        let units = u64_from_bytes(&value)?;
        state.contributor_units.insert(id, units);
    }

    // Contributor keys.
    for (key, value) in store
        .scan_prefix(&[key_prefix::CONTRIBUTOR_KEY])
        .map_err(LoadError::Store)?
    {
        let sk = StateKey::decode(&key)
            .ok_or_else(|| LoadError::Corrupt("unrecognised state key".into()))?;
        let id = match sk {
            StateKey::ContributorKey(id) => id,
            _ => return Err(LoadError::Corrupt("expected ContributorKey key".into())),
        };
        let vk: ed25519_dalek::VerifyingKey =
            serde_json::from_slice(&value).map_err(|e| LoadError::Corrupt(e.to_string()))?;
        state.contributor_keys.insert(id, vk);
    }

    // Quorum config.
    if let Some(v) = store
        .get(&StateKey::QuorumConfig.encode())
        .map_err(LoadError::Store)?
    {
        state.quorum_config =
            serde_json::from_slice(&v).map_err(|e| LoadError::Corrupt(e.to_string()))?;
    }

    // Totals.
    if let Some(v) = store
        .get(&StateKey::TotalAsset.encode())
        .map_err(LoadError::Store)?
    {
        state.total_asset_units = u64_from_bytes(&v)?;
    }
    if let Some(v) = store
        .get(&StateKey::TotalContrib.encode())
        .map_err(LoadError::Store)?
    {
        state.total_contribution_units = u64_from_bytes(&v)?;
    }

    // Verify integrity.
    if let Some(stored_root) = store.load_root().map_err(LoadError::Store)? {
        let computed = state.state_root();
        if computed != stored_root {
            return Err(LoadError::Corrupt(
                "Merkle root mismatch — state may have been tampered with".into(),
            ));
        }
    }

    Ok(state)
}

fn u64_from_bytes<S: StateStore>(bytes: &[u8]) -> Result<u64, LoadError<S>> {
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| LoadError::Corrupt("invalid u64 encoding".into()))?;
    Ok(u64::from_le_bytes(arr))
}

// ---------------------------------------------------------------------------
// Convenience: persist after a contribution
// ---------------------------------------------------------------------------

/// Write the keys that changed after `process_contribution`.
///
/// Three keys are always written: the contributor's unit total, and the two
/// accumulator totals. The caller should call `commit_root` afterwards with
/// the new state root.
pub fn flush_contribution<S: StateStore>(
    store: &S,
    state: &CoFiState,
    contributor: &ContributorId,
) -> Result<(), S::Error> {
    let units = state
        .contributor_units
        .get(contributor)
        .copied()
        .unwrap_or(0);

    store.put(
        &StateKey::ContributorUnits(contributor.clone()).encode(),
        &units.to_le_bytes(),
    )?;
    store.put(
        &StateKey::TotalAsset.encode(),
        &state.total_asset_units.to_le_bytes(),
    )?;
    store.put(
        &StateKey::TotalContrib.encode(),
        &state.total_contribution_units.to_le_bytes(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AssetType, Contribution};

    fn temp_store() -> SledStore {
        let dir = tempfile::tempdir().unwrap();
        SledStore::open(dir.path()).unwrap()
    }

    #[test]
    fn put_and_get() {
        let store = temp_store();
        store.put(b"key", b"value").unwrap();
        assert_eq!(store.get(b"key").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn last_write_wins() {
        let store = temp_store();
        store.put(b"key", b"old").unwrap();
        store.put(b"key", b"new").unwrap();
        assert_eq!(store.get(b"key").unwrap(), Some(b"new".to_vec()));
    }

    #[test]
    fn root_roundtrip() {
        let store = temp_store();
        let root = [42u8; 32];
        store.commit_root(&root).unwrap();
        assert_eq!(store.load_root().unwrap(), Some(root));
    }

    #[test]
    fn flush_and_load_roundtrip() {
        let store = temp_store();
        let mut state = CoFiState::new();

        state
            .register_asset_type(AssetType {
                id: "code".into(),
                name: "Code".into(),
                weight: 10,
            })
            .unwrap();

        // Persist the asset type manually (register doesn't auto-flush).
        let at = state.asset_types.get("code").unwrap();
        store
            .put(
                &StateKey::AssetType("code".into()).encode(),
                serde_json::to_vec(at).unwrap().as_slice(),
            )
            .unwrap();

        // Process and flush a contribution.
        state
            .process_contribution(Contribution {
                contributor: "alice".into(),
                asset_type: "code".into(),
                amount: 5,
            })
            .unwrap();

        flush_contribution(&store, &state, &"alice".into()).unwrap();
        let root = state.state_root();
        store.commit_root(&root).unwrap();

        // Reload and verify.
        let loaded = load_state(&store).unwrap();
        assert_eq!(loaded.total_asset_units, state.total_asset_units);
        assert_eq!(loaded.total_contribution_units, state.total_contribution_units);
        assert_eq!(loaded.contributor_units["alice"], state.contributor_units["alice"]);
        assert_eq!(loaded.state_root(), root);
    }

    #[test]
    fn load_detects_tampering() {
        let store = temp_store();
        store.commit_root(&[0u8; 32]).unwrap();
        // Don't write any state — the empty state won't match the bogus root.
        let err = load_state(&store).unwrap_err();
        assert!(matches!(err, LoadError::Corrupt(_)));
    }
}
