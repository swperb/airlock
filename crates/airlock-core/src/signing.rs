//! Customer-held policy signing.
//!
//! The brief's rule: assume the vendor's own servers are compromised. A policy
//! is only as trustworthy as whoever can write it, so when the operator
//! configures trusted public keys, the gateway refuses to load any policy that
//! is not signed by one of them. A breach of whoever ships or edits policy
//! files cannot loosen enforcement without the customer's private key.
//!
//! Signatures are Ed25519 over a domain-separated message binding the policy's
//! exact bytes (by SHA-256) to a **serial number**. The gateway remembers the
//! highest serial it has accepted (in the state directory) and refuses older
//! ones, so an attacker cannot replay a previously signed but looser policy.
//!
//! File formats are small, line-based text so they can be reviewed by eye:
//!
//! ```text
//! # alice.key  (private, mode 0600)
//! airlock-ed25519-private <64 hex>
//!
//! # alice.pub  (public; a trusted-keys file is any number of these lines)
//! airlock-ed25519-public <64 hex> alice@example.com
//!
//! # policy.toml.sig
//! airlock-policy-signature v1
//! serial 7
//! key 3f9a0c1d2e4b5a69
//! sig <128 hex>
//! ```

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::util::sha256_hex;
use crate::Error;

const PRIVATE_TAG: &str = "airlock-ed25519-private";
const PUBLIC_TAG: &str = "airlock-ed25519-public";
const SIG_HEADER: &str = "airlock-policy-signature v1";
const SERIAL_FILE: &str = "policy-serial";

fn err(msg: impl Into<String>) -> Error {
    Error::Policy(msg.into())
}

/// Short identifier for a public key: the first 16 hex characters of the
/// SHA-256 of its bytes.
pub fn key_id(key: &VerifyingKey) -> String {
    sha256_hex(key.as_bytes())[..16].to_string()
}

/// The exact bytes that are signed.
fn message(serial: u64, policy_bytes: &[u8]) -> Vec<u8> {
    format!(
        "airlock-policy-v1\nserial {serial}\nsha256 {}\n",
        sha256_hex(policy_bytes)
    )
    .into_bytes()
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(s).map_err(|_| err(format!("{what} is not valid hex")))?;
    bytes
        .try_into()
        .map_err(|_| err(format!("{what} must be 32 bytes (64 hex characters)")))
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A private signing key, held by the customer.
pub struct PrivateKey(SigningKey);

impl PrivateKey {
    /// Build a key from 32 bytes of system randomness.
    pub fn from_seed(seed: [u8; 32]) -> PrivateKey {
        PrivateKey(SigningKey::from_bytes(&seed))
    }

    pub fn public(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    /// The private key file's contents.
    pub fn to_file_text(&self) -> String {
        format!("{PRIVATE_TAG} {}\n", hex::encode(self.0.to_bytes()))
    }

    pub fn parse(text: &str) -> Result<PrivateKey, Error> {
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .ok_or_else(|| err("private key file is empty"))?;
        let mut parts = line.split_whitespace();
        if parts.next() != Some(PRIVATE_TAG) {
            return Err(err(format!(
                "not an airlock private key (expected {PRIVATE_TAG})"
            )));
        }
        let seed = parse_hex32(parts.next().unwrap_or(""), "private key")?;
        Ok(PrivateKey::from_seed(seed))
    }

    pub fn load(path: &Path) -> Result<PrivateKey, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| err(format!("reading private key {}: {e}", path.display())))?;
        PrivateKey::parse(&text)
    }
}

/// A public key line for a trusted-keys file.
pub fn public_key_line(key: &VerifyingKey, comment: &str) -> String {
    let comment = comment.trim();
    if comment.is_empty() {
        format!("{PUBLIC_TAG} {}\n", hex::encode(key.as_bytes()))
    } else {
        format!("{PUBLIC_TAG} {} {comment}\n", hex::encode(key.as_bytes()))
    }
}

/// A set of public keys the operator trusts to sign policies.
#[derive(Debug, Clone)]
pub struct TrustedKeys {
    keys: Vec<(String, VerifyingKey, String)>,
}

impl TrustedKeys {
    /// Parse a trusted-keys file: one public key per line; blank lines and
    /// `#` comments are ignored. An empty set is an error, so a truncated
    /// file cannot silently turn signing off.
    pub fn parse(text: &str) -> Result<TrustedKeys, Error> {
        let mut keys = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(3, char::is_whitespace);
            if parts.next() != Some(PUBLIC_TAG) {
                return Err(err(format!(
                    "trusted keys line {}: expected {PUBLIC_TAG}",
                    i + 1
                )));
            }
            let bytes = parse_hex32(
                parts.next().unwrap_or(""),
                &format!("trusted keys line {}", i + 1),
            )?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
                err(format!(
                    "trusted keys line {}: not a valid Ed25519 key",
                    i + 1
                ))
            })?;
            let comment = parts.next().unwrap_or("").trim().to_string();
            keys.push((key_id(&key), key, comment));
        }
        if keys.is_empty() {
            return Err(err("trusted keys file contains no keys"));
        }
        Ok(TrustedKeys { keys })
    }

    pub fn load(path: &Path) -> Result<TrustedKeys, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| err(format!("reading trusted keys {}: {e}", path.display())))?;
        TrustedKeys::parse(&text)
    }

    fn find(&self, id: &str) -> Option<&(String, VerifyingKey, String)> {
        self.keys.iter().find(|(kid, _, _)| kid == id)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

/// A parsed `.sig` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySignature {
    pub serial: u64,
    pub key_id: String,
    sig: [u8; 64],
}

impl PolicySignature {
    pub fn parse(text: &str) -> Result<PolicySignature, Error> {
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        if lines.first() != Some(&SIG_HEADER) {
            return Err(err(format!(
                "signature file must start with {SIG_HEADER:?}"
            )));
        }
        let mut serial = None;
        let mut key = None;
        let mut sig = None;
        for line in &lines[1..] {
            let (field, value) = line
                .split_once(' ')
                .ok_or_else(|| err(format!("malformed signature line {line:?}")))?;
            let slot = match field {
                "serial" => &mut serial,
                "key" => &mut key,
                "sig" => &mut sig,
                other => return Err(err(format!("unknown signature field {other:?}"))),
            };
            if slot.replace(value.trim().to_string()).is_some() {
                return Err(err(format!("duplicate signature field {field:?}")));
            }
        }
        let serial = serial
            .ok_or_else(|| err("signature has no serial"))?
            .parse::<u64>()
            .map_err(|_| err("signature serial must be a non-negative integer"))?;
        let key_id = key.ok_or_else(|| err("signature has no key"))?;
        let sig_bytes = hex::decode(sig.ok_or_else(|| err("signature has no sig"))?)
            .map_err(|_| err("signature is not valid hex"))?;
        let sig: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| err("signature must be 64 bytes (128 hex characters)"))?;
        Ok(PolicySignature {
            serial,
            key_id,
            sig,
        })
    }

    pub fn to_file_text(&self) -> String {
        format!(
            "{SIG_HEADER}\nserial {}\nkey {}\nsig {}\n",
            self.serial,
            self.key_id,
            hex::encode(self.sig)
        )
    }
}

/// Sign policy bytes with a serial number.
pub fn sign(policy_bytes: &[u8], serial: u64, key: &PrivateKey) -> PolicySignature {
    let sig = key.0.sign(&message(serial, policy_bytes));
    PolicySignature {
        serial,
        key_id: key_id(&key.public()),
        sig: sig.to_bytes(),
    }
}

/// What a successful verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub serial: u64,
    pub key_id: String,
    pub key_comment: String,
    pub policy_sha256: String,
}

/// Verify a signature over policy bytes against the trusted keys.
pub fn verify(
    policy_bytes: &[u8],
    sig: &PolicySignature,
    trusted: &TrustedKeys,
) -> Result<Verified, Error> {
    let (_, key, comment) = trusted.find(&sig.key_id).ok_or_else(|| {
        err(format!(
            "policy is signed by key {}, which is not in the trusted keys",
            sig.key_id
        ))
    })?;
    key.verify(
        &message(sig.serial, policy_bytes),
        &Signature::from_bytes(&sig.sig),
    )
    .map_err(|_| {
        err("policy signature does not verify: the policy or its signature was changed")
    })?;
    Ok(Verified {
        serial: sig.serial,
        key_id: sig.key_id.clone(),
        key_comment: comment.clone(),
        policy_sha256: sha256_hex(policy_bytes),
    })
}

/// The signature file that goes with a policy file: `<policy>.sig`.
pub fn signature_path(policy: &Path) -> PathBuf {
    let mut s = policy.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// Rollback protection
// ---------------------------------------------------------------------------

/// Record `serial` as accepted, refusing it if a higher serial was accepted
/// before. The record lives in the state directory, which must be writable
/// only by the gateway.
pub fn check_and_record_serial(state_dir: &Path, serial: u64) -> Result<(), Error> {
    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join(SERIAL_FILE);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(state_dir.join(".policy-serial.lock"))?;
    lock.lock()?;
    let result = (|| {
        let previous = match std::fs::read_to_string(&path) {
            Ok(t) => Some(t.trim().parse::<u64>().map_err(|_| {
                Error::Io(format!(
                    "{} is corrupt; refusing to guess the last accepted serial",
                    path.display()
                ))
            })?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if let Some(prev) = previous {
            if serial < prev {
                return Err(err(format!(
                    "policy serial {serial} is older than serial {prev}, which this gateway already accepted (rollback refused)"
                )));
            }
            if serial == prev {
                return Ok(());
            }
        }
        let tmp = state_dir.join(".policy-serial.tmp");
        std::fs::write(&tmp, format!("{serial}\n"))?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    })();
    let _ = lock.unlock();
    result
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Whether a gateway that is starting should record the accepted serial.
/// Read-only commands (`policy check`, `policy verify`) do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Serial {
    Record,
    CheckOnly,
}

/// A policy as loaded: its parsed form, the hash of the exact bytes it was
/// parsed from, and what signature verification established, if it ran.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub policy: crate::Policy,
    pub sha256: String,
    pub verified: Option<Verified>,
}

/// Load a policy, enforcing signatures when `trusted` is set.
///
/// The file is read once; the same bytes are verified and then parsed, so the
/// policy cannot be swapped between the check and the use. With `trusted`
/// set, a missing, malformed, untrusted or non-matching signature is an error,
/// and so is a serial older than the last one this gateway accepted.
pub fn load_policy(
    path: &Path,
    trusted: Option<&TrustedKeys>,
    serial: Serial,
) -> Result<LoadedPolicy, Error> {
    let bytes = std::fs::read(path).map_err(|e| err(format!("reading {}: {e}", path.display())))?;
    let base = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let sha256 = sha256_hex(&bytes);
    let Some(trusted) = trusted else {
        let text = String::from_utf8(bytes).map_err(|_| err("policy file is not UTF-8"))?;
        let policy = crate::Policy::parse(&text, base)?;
        return Ok(LoadedPolicy {
            policy,
            sha256,
            verified: None,
        });
    };
    let sig_path = signature_path(path);
    let sig_text = std::fs::read_to_string(&sig_path).map_err(|e| {
        err(format!(
            "trusted keys are configured, so the policy must be signed, but {} could not be read: {e}",
            sig_path.display()
        ))
    })?;
    let sig = PolicySignature::parse(&sig_text)?;
    let verified = verify(&bytes, &sig, trusted)?;
    let text = String::from_utf8(bytes).map_err(|_| err("policy file is not UTF-8"))?;
    let policy = crate::Policy::parse(&text, base)?;
    match serial {
        Serial::Record => check_and_record_serial(&policy.state_dir(), verified.serial)?,
        Serial::CheckOnly => {
            let recorded = std::fs::read_to_string(policy.state_dir().join(SERIAL_FILE))
                .ok()
                .and_then(|t| t.trim().parse::<u64>().ok());
            if let Some(prev) = recorded.filter(|prev| verified.serial < *prev) {
                return Err(err(format!(
                    "policy serial {} is older than serial {prev}, which this gateway already accepted (a gateway would refuse it)",
                    verified.serial
                )));
            }
        }
    }
    Ok(LoadedPolicy {
        policy,
        sha256,
        verified: Some(verified),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> PrivateKey {
        PrivateKey::from_seed([n; 32])
    }

    fn trusted(keys: &[&PrivateKey]) -> TrustedKeys {
        let text: String = keys
            .iter()
            .enumerate()
            .map(|(i, k)| public_key_line(&k.public(), &format!("key{i}")))
            .collect();
        TrustedKeys::parse(&text).unwrap()
    }

    const POLICY: &[u8] = b"[[upstream]]\nname = \"db\"\ncommand = [\"x\"]\n";

    #[test]
    fn sign_and_verify_roundtrip_through_files() {
        let k = key(1);
        let sig = sign(POLICY, 7, &k);
        let parsed = PolicySignature::parse(&sig.to_file_text()).unwrap();
        assert_eq!(parsed, sig);
        let v = verify(POLICY, &parsed, &trusted(&[&k])).unwrap();
        assert_eq!(v.serial, 7);
        assert_eq!(v.key_comment, "key0");
        let reloaded = PrivateKey::parse(&k.to_file_text()).unwrap();
        assert_eq!(reloaded.public(), k.public());
    }

    #[test]
    fn any_change_to_the_policy_fails() {
        let k = key(1);
        let sig = sign(POLICY, 1, &k);
        let mut tampered = POLICY.to_vec();
        tampered.push(b' ');
        assert!(verify(&tampered, &sig, &trusted(&[&k])).is_err());
    }

    #[test]
    fn changing_the_serial_fails() {
        let k = key(1);
        let mut sig = sign(POLICY, 1, &k);
        sig.serial = 99;
        assert!(verify(POLICY, &sig, &trusted(&[&k])).is_err());
    }

    #[test]
    fn untrusted_or_wrong_key_fails() {
        let (good, bad) = (key(1), key(2));
        let sig = sign(POLICY, 1, &bad);
        let e = verify(POLICY, &sig, &trusted(&[&good]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("not in the trusted keys"), "{e}");
        // A signature claiming a trusted key id but made with another key.
        let mut forged = sign(POLICY, 1, &bad);
        forged.key_id = key_id(&good.public());
        assert!(verify(POLICY, &forged, &trusted(&[&good])).is_err());
    }

    #[test]
    fn rotation_with_several_trusted_keys() {
        let (old, new) = (key(1), key(2));
        let t = trusted(&[&old, &new]);
        assert!(verify(POLICY, &sign(POLICY, 1, &old), &t).is_ok());
        assert!(verify(POLICY, &sign(POLICY, 2, &new), &t).is_ok());
    }

    #[test]
    fn malformed_files_are_rejected() {
        assert!(TrustedKeys::parse("").is_err());
        assert!(TrustedKeys::parse("# only a comment\n").is_err());
        assert!(TrustedKeys::parse("ssh-ed25519 AAAA").is_err());
        assert!(TrustedKeys::parse("airlock-ed25519-public abcd").is_err());
        assert!(PrivateKey::parse("airlock-ed25519-public 00").is_err());
        let good = sign(POLICY, 1, &key(1)).to_file_text();
        assert!(PolicySignature::parse(&good.replace("v1", "v2")).is_err());
        assert!(PolicySignature::parse(&good.replace("serial 1", "serial -1")).is_err());
        assert!(PolicySignature::parse(&format!("{good}serial 2\n")).is_err());
        assert!(PolicySignature::parse(&format!("{good}extra x\n")).is_err());
        assert!(PolicySignature::parse("airlock-policy-signature v1\nserial 1\nkey a\n").is_err());
    }

    #[test]
    fn rollback_is_refused_and_serials_only_move_forward() {
        let d = tempfile::tempdir().unwrap();
        check_and_record_serial(d.path(), 3).unwrap();
        check_and_record_serial(d.path(), 3).unwrap();
        check_and_record_serial(d.path(), 5).unwrap();
        let e = check_and_record_serial(d.path(), 4)
            .unwrap_err()
            .to_string();
        assert!(e.contains("rollback refused"), "{e}");
        assert_eq!(
            std::fs::read_to_string(d.path().join(SERIAL_FILE))
                .unwrap()
                .trim(),
            "5"
        );
    }

    #[test]
    fn corrupt_serial_record_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(SERIAL_FILE), "not a number").unwrap();
        assert!(check_and_record_serial(d.path(), 10).is_err());
    }

    fn write_signed(dir: &Path, policy: &[u8], serial: u64, k: &PrivateKey) -> PathBuf {
        let p = dir.join("policy.toml");
        std::fs::write(&p, policy).unwrap();
        std::fs::write(signature_path(&p), sign(policy, serial, k).to_file_text()).unwrap();
        p
    }

    const STATEFUL: &[u8] =
        b"[gateway]\nstate_dir = \"state\"\n[[upstream]]\nname = \"db\"\ncommand = [\"x\"]\n";

    #[test]
    fn load_policy_enforces_signature_when_trusted() {
        let d = tempfile::tempdir().unwrap();
        let k = key(1);
        let t = trusted(&[&k]);
        let p = write_signed(d.path(), STATEFUL, 2, &k);
        let loaded = load_policy(&p, Some(&t), Serial::Record).unwrap();
        assert_eq!(loaded.policy.upstreams.len(), 1);
        assert_eq!(loaded.verified.unwrap().serial, 2);
        assert_eq!(loaded.sha256, sha256_hex(STATEFUL));
        // Without trust configured the signature is not consulted.
        assert!(load_policy(&p, None, Serial::Record)
            .unwrap()
            .verified
            .is_none());
        // Tampering after signing is refused.
        std::fs::write(&p, [STATEFUL, b"# loosened\n"].concat()).unwrap();
        assert!(load_policy(&p, Some(&t), Serial::Record).is_err());
        // A missing signature is refused.
        std::fs::write(&p, STATEFUL).unwrap();
        std::fs::remove_file(signature_path(&p)).unwrap();
        let e = load_policy(&p, Some(&t), Serial::Record)
            .unwrap_err()
            .to_string();
        assert!(e.contains("must be signed"), "{e}");
    }

    #[test]
    fn load_policy_refuses_replay_of_an_older_signed_policy() {
        let d = tempfile::tempdir().unwrap();
        let k = key(1);
        let t = trusted(&[&k]);
        let p = write_signed(d.path(), STATEFUL, 5, &k);
        load_policy(&p, Some(&t), Serial::Record).unwrap();
        // An attacker restores an older, validly signed policy.
        let p = write_signed(d.path(), STATEFUL, 4, &k);
        assert!(load_policy(&p, Some(&t), Serial::CheckOnly).is_err());
        let e = load_policy(&p, Some(&t), Serial::Record)
            .unwrap_err()
            .to_string();
        assert!(e.contains("rollback refused"), "{e}");
    }

    #[test]
    fn signature_path_appends_sig() {
        assert_eq!(
            signature_path(Path::new("/etc/a/policy.toml")),
            PathBuf::from("/etc/a/policy.toml.sig")
        );
    }
}
