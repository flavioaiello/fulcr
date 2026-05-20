use anyhow::Context;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(digest))
}

pub fn digest_json<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(value).context("serializing canonical digest payload")?;
    Ok(digest_bytes(&bytes))
}

pub fn cache_file_name(digest: &str) -> String {
    digest.replace(':', "_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_digest_is_stable() {
        let value = json!({"source":"abc123", "materials":["Cargo.lock"]});
        assert_eq!(digest_json(&value).unwrap(), digest_json(&value).unwrap());
    }
}
