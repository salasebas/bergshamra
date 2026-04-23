#![forbid(unsafe_code)]

//! Key transport algorithms (RSA PKCS#1 v1.5, RSA-OAEP).

use bergshamra_core::{algorithm, Error};
use kryptering::algorithm::{
    HashAlgorithm, KeyTransportAlgorithm as KKeyTransportAlgorithm, OaepConfig,
};

/// Trait for key transport algorithms.
pub trait KeyTransportAlgorithm: Send {
    fn uri(&self) -> &'static str;
    fn encrypt(&self, public_key: &rsa::RsaPublicKey, key_data: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, private_key: &rsa::RsaPrivateKey, encrypted: &[u8])
        -> Result<Vec<u8>, Error>;
}

/// RSA-OAEP configuration parameters.
#[derive(Debug, Clone, Default)]
pub struct OaepParams {
    /// Digest algorithm URI (default: SHA-1)
    pub digest_uri: Option<String>,
    /// MGF algorithm URI (default: MGF1 with same digest)
    pub mgf_uri: Option<String>,
    /// OAEPparams (optional label, base64-decoded)
    pub oaep_params: Option<Vec<u8>>,
}

/// Create a key transport algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn KeyTransportAlgorithm>, Error> {
    from_uri_with_params(uri, OaepParams::default())
}

/// Create a key transport algorithm from its URI with RSA-OAEP parameters.
pub fn from_uri_with_params(
    uri: &str,
    params: OaepParams,
) -> Result<Box<dyn KeyTransportAlgorithm>, Error> {
    match uri {
        algorithm::RSA_PKCS1 => Ok(Box::new(KrypteringKeyTransport {
            uri: algorithm::RSA_PKCS1,
            algo: KKeyTransportAlgorithm::RsaPkcs1v15,
            label: None,
        })),
        algorithm::RSA_OAEP | algorithm::RSA_OAEP_ENC11 => {
            let static_uri = if uri == algorithm::RSA_OAEP {
                algorithm::RSA_OAEP
            } else {
                algorithm::RSA_OAEP_ENC11
            };
            let digest = resolve_digest(params.digest_uri.as_deref());
            let mgf = resolve_oaep_mgf(uri, &params, digest);
            let config = OaepConfig {
                digest,
                mgf_digest: mgf,
            };
            Ok(Box::new(KrypteringKeyTransport {
                uri: static_uri,
                algo: KKeyTransportAlgorithm::RsaOaep(config),
                label: params.oaep_params,
            }))
        }
        _ => Err(Error::UnsupportedAlgorithm(format!("key transport: {uri}"))),
    }
}

// ── URI resolution helpers ──────────────────────────────────────────

/// Resolve the digest URI to a `HashAlgorithm`.
fn resolve_digest(uri: Option<&str>) -> HashAlgorithm {
    match uri {
        Some(algorithm::SHA256) => HashAlgorithm::Sha256,
        Some(algorithm::SHA384) => HashAlgorithm::Sha384,
        Some(algorithm::SHA512) => HashAlgorithm::Sha512,
        Some(algorithm::SHA224) => HashAlgorithm::Sha224,
        Some(algorithm::SHA1) | None => HashAlgorithm::Sha1,
        #[cfg(feature = "legacy-algorithms")]
        Some(algorithm::RIPEMD160) => HashAlgorithm::Ripemd160,
        #[cfg(feature = "legacy-algorithms")]
        Some(algorithm::MD5) => HashAlgorithm::Md5,
        Some(_other) => {
            #[cfg(feature = "legacy-algorithms")]
            if _other.contains("ripemd160") {
                return HashAlgorithm::Ripemd160;
            }
            #[cfg(feature = "legacy-algorithms")]
            if _other.contains("md5") {
                return HashAlgorithm::Md5;
            }
            HashAlgorithm::Sha1
        }
    }
}

/// Resolve the MGF URI to a `HashAlgorithm`.
fn resolve_mgf(uri: Option<&str>) -> Option<HashAlgorithm> {
    match uri {
        Some(algorithm::MGF1_SHA1) => Some(HashAlgorithm::Sha1),
        Some(algorithm::MGF1_SHA224) => Some(HashAlgorithm::Sha224),
        Some(algorithm::MGF1_SHA256) => Some(HashAlgorithm::Sha256),
        Some(algorithm::MGF1_SHA384) => Some(HashAlgorithm::Sha384),
        Some(algorithm::MGF1_SHA512) => Some(HashAlgorithm::Sha512),
        _ => None,
    }
}

/// Resolve the MGF hash for OAEP.
///
/// For `rsa-oaep-mgf1p` (XML Enc 1.0): MGF1 always uses SHA-1 unless an explicit
/// MGF element overrides it.  The DigestMethod only controls the OAEP label hash.
///
/// For `rsa-oaep` (XML Enc 1.1): MGF defaults to the same hash as DigestMethod
/// when no explicit MGF element is present.
fn resolve_oaep_mgf(uri: &str, params: &OaepParams, digest: HashAlgorithm) -> HashAlgorithm {
    // If an explicit MGF element is present, use it
    if let Some(mgf) = resolve_mgf(params.mgf_uri.as_deref()) {
        return mgf;
    }
    // rsa-oaep-mgf1p: MGF1 defaults to SHA-1
    if uri == algorithm::RSA_OAEP {
        return HashAlgorithm::Sha1;
    }
    // rsa-oaep (enc11): MGF defaults to same as digest
    digest
}

// ── Wrapper that delegates to kryptering ────────────────────────────

struct KrypteringKeyTransport {
    uri: &'static str,
    algo: KKeyTransportAlgorithm,
    label: Option<Vec<u8>>,
}

impl KeyTransportAlgorithm for KrypteringKeyTransport {
    fn uri(&self) -> &'static str {
        self.uri
    }

    fn encrypt(&self, public_key: &rsa::RsaPublicKey, key_data: &[u8]) -> Result<Vec<u8>, Error> {
        kryptering::keytransport::kt_encrypt(self.algo, public_key, key_data, self.label.as_deref())
            .map_err(crate::map_kryptering_err)
    }

    fn decrypt(
        &self,
        private_key: &rsa::RsaPrivateKey,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, Error> {
        kryptering::keytransport::kt_decrypt(
            self.algo,
            private_key,
            encrypted,
            self.label.as_deref(),
        )
        .map_err(crate::map_kryptering_err)
    }
}
