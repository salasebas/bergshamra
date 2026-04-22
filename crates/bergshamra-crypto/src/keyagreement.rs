#![forbid(unsafe_code)]

//! ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral-Static) key agreement.
//!
//! Computes a shared secret from an originator's public key and a recipient's
//! private key using ECDH, then derives a key-encryption key (KEK) using a
//! key derivation function (ConcatKDF or PBKDF2).

use bergshamra_core::Error;

/// Compute an ECDH shared secret for P-256.
///
/// Takes the originator's (ephemeral) public key as uncompressed SEC1 bytes
/// and the recipient's (static) private key.
pub fn ecdh_p256(
    originator_public: &[u8],
    recipient_private: &p256::SecretKey,
) -> Result<Vec<u8>, Error> {
    kryptering::keyagreement::ecdh_p256(originator_public, recipient_private)
        .map_err(crate::map_kryptering_err)
}

/// Compute an ECDH shared secret for P-384.
pub fn ecdh_p384(
    originator_public: &[u8],
    recipient_private: &p384::SecretKey,
) -> Result<Vec<u8>, Error> {
    kryptering::keyagreement::ecdh_p384(originator_public, recipient_private)
        .map_err(crate::map_kryptering_err)
}

/// Compute an ECDH shared secret for P-521.
pub fn ecdh_p521(
    originator_public: &[u8],
    recipient_private: &p521::SecretKey,
) -> Result<Vec<u8>, Error> {
    kryptering::keyagreement::ecdh_p521(originator_public, recipient_private)
        .map_err(crate::map_kryptering_err)
}

/// Compute an X25519 Diffie-Hellman shared secret (RFC 7748).
///
/// Takes the originator's (ephemeral) public key as raw 32 bytes
/// and the recipient's (static) private key as raw 32 bytes.
/// Returns the 32-byte shared secret.
pub fn ecdh_x25519(originator_public: &[u8], recipient_private: &[u8]) -> Result<Vec<u8>, Error> {
    kryptering::keyagreement::ecdh_x25519(originator_public, recipient_private)
        .map_err(crate::map_kryptering_err)
}

/// Compute a finite-field Diffie-Hellman shared secret (X9.42 DH).
///
/// shared_secret = other_public ^ my_private mod p
///
/// All values are big-endian byte arrays. The result is zero-padded on the left
/// to the byte-length of p (as required by the DH-ES specification). Requires
/// `q` for subgroup validation.
///
/// Backed by `kryptering::hazmat::dh::compute`, which uses
/// `crypto-bigint 0.7`'s `BoxedMontyForm::pow` for constant-time-on-pattern
/// modular exponentiation (bit-length leak closed by padding the exponent
/// to `p.bits()`). See the hazmat module's doc for residual side-channel
/// caveats.
pub fn dh_compute(
    other_public: &[u8],
    my_private: &[u8],
    p: &[u8],
    q: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    kryptering::hazmat::dh::compute(other_public, my_private, p, q)
        .map_err(crate::map_kryptering_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_roundtrip() {
        // Both parties generate key pairs; shared secret must match
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let alice_public = x25519_dalek::PublicKey::from(&alice_secret);

        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        // Alice computes shared secret with Bob's public key
        let shared_alice = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();

        // Bob computes shared secret with Alice's public key
        let shared_bob = ecdh_x25519(alice_public.as_bytes(), bob_secret.as_bytes()).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 32);
    }

    #[test]
    fn x25519_invalid_public_key_length() {
        let secret = [0u8; 32];
        let short_pub = [0u8; 16];
        let err = ecdh_x25519(&short_pub, &secret).unwrap_err();
        assert!(
            err.to_string().contains("invalid X25519 public key length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x25519_invalid_private_key_length() {
        let pub_key = [0u8; 32];
        let short_priv = [0u8; 16];
        let err = ecdh_x25519(&pub_key, &short_priv).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid X25519 private key length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x25519_deterministic() {
        // Same inputs → same output
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        let shared1 = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();
        let shared2 = ecdh_x25519(bob_public.as_bytes(), alice_secret.as_bytes()).unwrap();

        assert_eq!(shared1, shared2);
    }
}
