//! Cryptography types, abstractions and utilities.

use crypto_bigint::modular::constant_mod::ResidueParams;
use crypto_bigint::{impl_modulus, NonZero, RandomMod, U256};

use crate::errors::CryptoError;

// Order of the `Secp256k1` elliptic curve a `crypto-bigint` modulus type.
// Ref: <https://www.secg.org/sec2-v2.pdf>.
// Ref: <https://en.bitcoin.it/wiki/Secp256k1>.
impl_modulus!(
    Secp256k1Order,
    U256,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

/// A verifying key (e.g an ECDSA/secp256k1 public key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    /// The verifying key as a sequence of bytes.
    pub key: Vec<u8>,
    /// The signature algorithm.
    pub algo: SignatureAlgorithm,
    /// The elliptic curve.
    pub curve: EllipticCurve,
    /// The encoding standard used for the verifying key.
    pub enc: KeyEncoding,
}

/// A Signature (e.g a ECDSA/secp256k1/SHA-256 signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// The signature as a sequence of bytes.
    pub sig: Vec<u8>,
    /// The signature algorithm.
    pub algo: SignatureAlgorithm,
    /// The elliptic curve.
    pub curve: EllipticCurve,
    /// The hash function.
    pub hash: HashFunction,
    /// The encoding standard used for the signature.
    pub enc: SignatureEncoding,
}

/// A signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// Ref: <https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>.
    ECDSA,
    /// Ref: <https://en.wikipedia.org/wiki/EdDSA>.
    EdDSA,
}

/// An elliptic curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    /// Ref: <https://www.secg.org/sec2-v2.pdf>.
    Secp256k1,
    /// Ref: <https://en.wikipedia.org/wiki/Curve25519>.
    Curve25519,
}

/// A cryptographic hash function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFunction {
    /// Ref: <https://en.wikipedia.org/wiki/SHA-2>.
    SHA256,
    /// Ref: <https://en.wikipedia.org/wiki/SHA-3>.
    KECCAK256,
}

/// A key encoding format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEncoding {
    /// Ref: <https://www.secg.org/sec1-v2.pdf>.
    SEC1,
    /// Ref: <https://eips.ethereum.org/EIPS/eip-55>.
    EIP55,
}

/// A signature encoding format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureEncoding {
    /// Ref: <https://en.wikipedia.org/wiki/X.690#DER_encoding>.
    DER,
    /// Ref: <https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/>.
    RLP,
}

/// Generate a cryptographically secure random `U256` which is less than the order of the `Secp256k1` elliptic curve.
pub fn random_mod() -> U256 {
    let mut rng = rand::thread_rng();
    let modulus = NonZero::new(Secp256k1Order::MODULUS)
        .expect("The order of the `Secp256k1` curve should be non-zero");
    U256::random_mod(&mut rng, &modulus)
}

/// Returns an `Ok` result for valid signature for the message, or an appropriate `Err` result otherwise.
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    if verifying_key.algo != signature.algo {
        // Signature algorithms should match.
        Err(CryptoError::SignatureAlgorithmMismatch)
    } else if verifying_key.curve != signature.curve {
        // Elliptic curves should match.
        Err(CryptoError::EllipticCurveMismatch)
    } else {
        match verifying_key.algo {
            SignatureAlgorithm::ECDSA => match verifying_key.curve {
                EllipticCurve::Secp256k1 => match verifying_key.enc {
                    KeyEncoding::SEC1 => match signature.enc {
                        SignatureEncoding::DER => match signature.hash {
                            HashFunction::SHA256 => {
                                // Deserialize verifying key.
                                // `k256::ecdsa::VerifyingKey` uses `Secp256k1` and `SHA-256`.
                                let ver_key =
                                    k256::ecdsa::VerifyingKey::from_sec1_bytes(&verifying_key.key);
                                // Deserialize signature.
                                let sig = k256::ecdsa::Signature::from_der(&signature.sig)
                                    .map_err(|_| CryptoError::InvalidSignature)?;
                                // Verify ECDSA/Secp256k1/SHA-256 signature.
                                use k256::ecdsa::signature::Verifier;
                                ver_key
                                    .map_err(|_| CryptoError::InvalidVerifyingKey)?
                                    .verify(msg, &sig)
                                    .map_err(|_| CryptoError::InvalidSignature)
                            }
                            _ => Err(CryptoError::UnsupportedHashFunction),
                        },
                        _ => Err(CryptoError::UnsupportedSignatureEncoding),
                    },
                    _ => Err(CryptoError::UnsupportedKeyEncoding),
                },
                _ => Err(CryptoError::UnsupportedEllipticCurve),
            },
            _ => Err(CryptoError::UnsupportedSignatureAlgorithm),
        }
    }
}
