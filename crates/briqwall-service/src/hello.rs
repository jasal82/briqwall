//! Verification of Windows Hello approvals.
//!
//! Windows Hello ("KeyCredentialManager") keys are RSA-2048 keys held by the
//! TPM. They sign with RSASSA-PKCS1-v1_5 / SHA-256 and only after the user
//! confirmed with fingerprint, face or PIN. Malware running as the user can
//! neither extract the key nor produce a signature without that gesture.

use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;

/// Parse a hex-encoded X.509 SubjectPublicKeyInfo (as returned by
/// `KeyCredential::RetrievePublicKeyWithDefaultBlobType`).
pub fn parse_key(hex_spki: &str) -> Option<RsaPublicKey> {
    let der = briqwall_common::util::unhex(hex_spki)?;
    let key = RsaPublicKey::from_public_key_der(&der).ok()?;
    // Hello keys are 2048 bit; refuse anything weaker.
    (rsa::traits::PublicKeyParts::size(&key) >= 256).then_some(key)
}

pub fn verify(hex_spki: &str, message: &[u8], hex_signature: &str) -> bool {
    let (Some(key), Some(sig)) = (parse_key(hex_spki), briqwall_common::util::unhex(hex_signature)) else {
        return false;
    };
    let Ok(sig) = Signature::try_from(sig.as_slice()) else { return false };
    VerifyingKey::<Sha256>::new(key).verify(message, &sig).is_ok()
}

/// 32 random bytes from the system RNG, hex-encoded.
pub fn nonce() -> String {
    use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    let mut buf = [0u8; 32];
    let st = unsafe { BCryptGenRandom(None, &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    assert!(st.is_ok(), "BCryptGenRandom failed");
    briqwall_common::util::hex(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;
    use briqwall_common::approval_message;
    use briqwall_common::util::hex;

    fn keypair() -> (RsaPrivateKey, String) {
        let private = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();
        (private, hex(spki.as_bytes()))
    }

    #[test]
    fn accepts_valid_signature_and_rejects_tampering() {
        let (private, spki) = keypair();
        let n = nonce();
        let payload = r#"[{"SetMode":"Off"}]"#;
        let msg = approval_message(&n, payload);
        let sig = hex(&SigningKey::<Sha256>::new(private.clone()).sign(&msg).to_bytes());
        assert!(verify(&spki, &msg, &sig));

        // Different payload, different nonce or a foreign key must all fail.
        assert!(!verify(&spki, &approval_message(&n, r#"[{"SetMode":"Relaxed"}]"#), &sig));
        assert!(!verify(&spki, &approval_message(&nonce(), payload), &sig));
        let (_, other) = keypair();
        assert!(!verify(&other, &msg, &sig));
        assert!(!verify(&spki, &msg, "00"));
    }

    #[test]
    fn nonces_are_unique_and_long() {
        let a = nonce();
        assert_eq!(a.len(), 64);
        assert_ne!(a, nonce());
    }

    #[test]
    fn rejects_garbage_keys() {
        assert!(parse_key("zz").is_none());
        assert!(parse_key("3000").is_none());
    }
}
