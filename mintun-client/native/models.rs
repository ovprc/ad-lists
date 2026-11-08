use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::{account::AccountSnapshot, preferences::ConnectionPreferences};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeedIdentity {
    pub format: i32,
    pub id: String,
    pub name: String,
    pub update_url: String,
    pub encryption_key: String,
    pub signing_public_key: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileContent {
    pub format: i32,
    pub profile_id: String,
    pub revision: i64,
    pub published_utc: String,
    pub minimum_core_version: String,
    pub outbound_tag: String,
    pub config_json: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedConfig {
    pub format: i32,
    pub payload: String,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Invitation {
    pub format: i32,
    pub feed: FeedIdentity,
    pub initial_config: EncryptedConfig,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountCache {
    pub profile_id: String,
    pub snapshot: AccountSnapshot,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientState {
    #[serde(default = "default_state_format")]
    pub format: i32,
    #[serde(default)]
    pub feed: Option<FeedIdentity>,
    #[serde(default)]
    pub profile: Option<ProfileContent>,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub core_directory: String,
    #[serde(default)]
    pub preferences: ConnectionPreferences,
    #[serde(default)]
    pub account: Option<AccountCache>,
}

fn default_state_format() -> i32 { 1 }

impl Default for ClientState {
    fn default() -> Self {
        Self { format: 1, feed: None, profile: None, uuid: String::new(), core_directory: String::new(),
            preferences: ConnectionPreferences::default(), account: None }
    }
}

// Never print imported configuration, personal identifiers or cryptographic material.
macro_rules! redacted_debug {
    ($($name:ty),+ $(,)?) => { $(
        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), " { [REDACTED] }"))
            }
        }
    )+ };
}
redacted_debug!(FeedIdentity, ProfileContent, EncryptedConfig, Invitation, ClientState, AccountCache, ProxyEndpoint, RuntimeConfiguration);

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyEndpoint {
    pub port: u16,
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
pub struct RuntimeConfiguration {
    pub json: String,
    pub proxy: ProxyEndpoint,
    pub interface_name: String,
    pub working_directory: PathBuf,
}

impl Drop for RuntimeConfiguration {
    fn drop(&mut self) { self.json.zeroize(); }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoreRelease {
    pub version: String,
    pub download_url: String,
    pub sha256: String,
    pub size: u64,
    pub prerelease: bool,
}

#[derive(Clone, Debug)]
pub struct StagedCore {
    pub directory: PathBuf,
    pub version: String,
}

#[derive(Clone, Debug)]
pub struct TransferProgress {
    pub received: u64,
    pub total: Option<u64>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationRelease {
    pub version: String,
    pub download_url: String,
    pub sha256: String,
    pub size: u64,
    pub name: String,
}
