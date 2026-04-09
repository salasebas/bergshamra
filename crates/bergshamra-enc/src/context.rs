#![forbid(unsafe_code)]

//! Encryption context — holds keys and configuration.

use bergshamra_keys::KeysManager;

/// Context for XML-Enc operations.
pub struct EncContext {
    /// Keys manager for key lookup.
    pub keys_manager: KeysManager,
    /// Additional ID attribute names.
    pub id_attrs: Vec<String>,
    /// Whether CipherReference resolution is disabled.
    pub disable_cipher_reference: bool,
    /// Optional HSM-backed decryptor for RSA key transport.
    /// When set, EncryptedKey elements are decrypted using this instead of software RSA keys.
    pub hsm_decryptor: Option<Box<dyn kryptering::Decryptor>>,
    /// Optional HSM-backed key unwrapper for AES-KW key unwrapping.
    pub hsm_key_unwrapper: Option<Box<dyn kryptering::KeyWrapper>>,
    /// Optional HSM-backed encryptor for RSA key transport encryption.
    pub hsm_encryptor: Option<Box<dyn kryptering::Encryptor>>,
    /// Optional HSM-backed key wrapper for AES-KW key wrapping.
    pub hsm_key_wrapper: Option<Box<dyn kryptering::KeyWrapper>>,
}

impl std::fmt::Debug for EncContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncContext")
            .field("keys_manager", &self.keys_manager)
            .field("id_attrs", &self.id_attrs)
            .field("disable_cipher_reference", &self.disable_cipher_reference)
            .field(
                "hsm_decryptor",
                &self.hsm_decryptor.as_ref().map(|_| "<hsm_decryptor>"),
            )
            .field(
                "hsm_key_unwrapper",
                &self
                    .hsm_key_unwrapper
                    .as_ref()
                    .map(|_| "<hsm_key_unwrapper>"),
            )
            .field(
                "hsm_encryptor",
                &self.hsm_encryptor.as_ref().map(|_| "<hsm_encryptor>"),
            )
            .field(
                "hsm_key_wrapper",
                &self.hsm_key_wrapper.as_ref().map(|_| "<hsm_key_wrapper>"),
            )
            .finish()
    }
}

impl EncContext {
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            keys_manager,
            id_attrs: Vec::new(),
            disable_cipher_reference: false,
            hsm_decryptor: None,
            hsm_key_unwrapper: None,
            hsm_encryptor: None,
            hsm_key_wrapper: None,
        }
    }

    pub fn add_id_attr(&mut self, name: &str) {
        self.id_attrs.push(name.to_owned());
    }

    /// Set disable cipher reference (builder style).
    pub fn with_disable_cipher_reference(mut self, disable: bool) -> Self {
        self.disable_cipher_reference = disable;
        self
    }

    /// Set an HSM-backed decryptor for RSA key transport (builder style).
    ///
    /// When set, RSA key transport decryption (unwrapping session keys)
    /// bypasses the `KeysManager` and delegates to the provided
    /// [`kryptering::Decryptor`] implementation. Key material never leaves the HSM.
    pub fn with_hsm_decryptor(mut self, decryptor: Box<dyn kryptering::Decryptor>) -> Self {
        self.hsm_decryptor = Some(decryptor);
        self
    }

    /// Set an HSM-backed key unwrapper for AES-KW key unwrapping (builder style).
    ///
    /// When set, AES key unwrap operations bypass the `KeysManager` and
    /// delegate to the provided [`kryptering::KeyWrapper`] implementation.
    pub fn with_hsm_key_unwrapper(mut self, unwrapper: Box<dyn kryptering::KeyWrapper>) -> Self {
        self.hsm_key_unwrapper = Some(unwrapper);
        self
    }

    /// Set an HSM-backed encryptor for RSA key transport encryption (builder style).
    ///
    /// When set, RSA key transport encryption (wrapping session keys)
    /// bypasses the `KeysManager` and delegates to the provided
    /// [`kryptering::Encryptor`] implementation.
    pub fn with_hsm_encryptor(mut self, encryptor: Box<dyn kryptering::Encryptor>) -> Self {
        self.hsm_encryptor = Some(encryptor);
        self
    }

    /// Set an HSM-backed key wrapper for AES-KW key wrapping (builder style).
    ///
    /// When set, AES key wrap operations bypass the `KeysManager` and
    /// delegate to the provided [`kryptering::KeyWrapper`] implementation.
    pub fn with_hsm_key_wrapper(mut self, wrapper: Box<dyn kryptering::KeyWrapper>) -> Self {
        self.hsm_key_wrapper = Some(wrapper);
        self
    }
}
