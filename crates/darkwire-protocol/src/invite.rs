use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const INVITE_PREFIX: &str = "DL1:";
pub const INVITE_VERSION: u8 = 1;
pub const TOKEN_MIN_LEN: usize = 12;
pub const TOKEN_MAX_LEN: usize = 16;
pub const MAX_TTL_SECONDS: u32 = 24 * 60 * 60;
const IDENTITY_HINT_BYTES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvitePayloadV1 {
    pub v: u8,
    pub r: Vec<String>,
    pub c: String,
    pub e: u32,
    pub o: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
}

impl InvitePayloadV1 {
    pub fn validate(&self) -> Result<(), InviteError> {
        if self.v != INVITE_VERSION {
            return Err(InviteError::UnsupportedVersion(self.v));
        }

        if !(1..=3).contains(&self.r.len()) {
            return Err(InviteError::InvalidRelayCount(self.r.len()));
        }

        if self.r.iter().any(|relay| relay.trim().is_empty()) {
            return Err(InviteError::EmptyRelayUrl);
        }

        let token_len = self.c.len();
        if !(TOKEN_MIN_LEN..=TOKEN_MAX_LEN).contains(&token_len) {
            return Err(InviteError::InvalidTokenLength(token_len));
        }

        if !self.c.bytes().all(is_upper_base32_char) {
            return Err(InviteError::InvalidTokenChars);
        }

        if self.e == 0 || self.e > MAX_TTL_SECONDS {
            return Err(InviteError::InvalidTtlSeconds(self.e));
        }

        if let Some(identity_hint) = self.k.as_deref() {
            let decoded_hint = BASE64URL_NOPAD
                .decode(identity_hint.as_bytes())
                .map_err(InviteError::InvalidIdentityHintEncoding)?;
            if decoded_hint.len() != IDENTITY_HINT_BYTES {
                return Err(InviteError::InvalidIdentityHintLength(decoded_hint.len()));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum InviteError {
    #[error("invite must start with DL1:")]
    InvalidPrefix,
    #[error("invite format must be DL1:<payload_b64url>.<crc32_base32>")]
    InvalidFormat,
    #[error("unsupported invite payload version: {0}")]
    UnsupportedVersion(u8),
    #[error("invite must contain between 1 and 3 relay URLs, got {0}")]
    InvalidRelayCount(usize),
    #[error("relay URLs cannot be empty")]
    EmptyRelayUrl,
    #[error("token must be 12-16 chars, got {0}")]
    InvalidTokenLength(usize),
    #[error("token must use uppercase base32 alphabet A-Z2-7")]
    InvalidTokenChars,
    #[error("TTL seconds must be in 1..={MAX_TTL_SECONDS}, got {0}")]
    InvalidTtlSeconds(u32),
    #[error("identity hint is not valid base64url: {0}")]
    InvalidIdentityHintEncoding(data_encoding::DecodeError),
    #[error("identity hint must decode to 32 bytes, got {0}")]
    InvalidIdentityHintLength(usize),
    #[error("payload is not valid base64url: {0}")]
    InvalidPayloadEncoding(data_encoding::DecodeError),
    #[error("checksum is not valid base32: {0}")]
    InvalidChecksumEncoding(data_encoding::DecodeError),
    #[error("checksum payload must decode to 4 bytes, got {0}")]
    InvalidChecksumLength(usize),
    #[error("checksum mismatch")]
    ChecksumMismatch,
    #[error("payload JSON serialization failed: {0}")]
    SerializePayload(serde_json::Error),
    #[error("payload JSON decode failed: {0}")]
    InvalidPayloadJson(serde_json::Error),
}

pub fn encode_invite(payload: &InvitePayloadV1) -> Result<String, InviteError> {
    payload.validate()?;

    let payload_bytes = serde_json::to_vec(payload).map_err(InviteError::SerializePayload)?;
    let payload_b64 = BASE64URL_NOPAD.encode(&payload_bytes);

    let checksum = crc32fast::hash(&payload_bytes);
    let checksum_b32 = BASE32_NOPAD.encode(&checksum.to_be_bytes());

    Ok(format!("{INVITE_PREFIX}{payload_b64}.{checksum_b32}"))
}

pub fn decode_invite(raw_invite: &str) -> Result<InvitePayloadV1, InviteError> {
    let body = raw_invite
        .strip_prefix(INVITE_PREFIX)
        .ok_or(InviteError::InvalidPrefix)?;

    let (payload_b64, checksum_b32) = body.split_once('.').ok_or(InviteError::InvalidFormat)?;

    if payload_b64.is_empty() || checksum_b32.is_empty() || checksum_b32.contains('.') {
        return Err(InviteError::InvalidFormat);
    }

    let payload_bytes = BASE64URL_NOPAD
        .decode(payload_b64.as_bytes())
        .map_err(InviteError::InvalidPayloadEncoding)?;

    let checksum_raw = BASE32_NOPAD
        .decode(checksum_b32.to_ascii_uppercase().as_bytes())
        .map_err(InviteError::InvalidChecksumEncoding)?;

    if checksum_raw.len() != 4 {
        return Err(InviteError::InvalidChecksumLength(checksum_raw.len()));
    }

    let expected_checksum = u32::from_be_bytes(
        checksum_raw
            .as_slice()
            .try_into()
            .expect("checksum is checked to 4 bytes"),
    );
    let actual_checksum = crc32fast::hash(&payload_bytes);

    if expected_checksum != actual_checksum {
        return Err(InviteError::ChecksumMismatch);
    }

    let payload: InvitePayloadV1 =
        serde_json::from_slice(&payload_bytes).map_err(InviteError::InvalidPayloadJson)?;
    payload.validate()?;

    Ok(payload)
}

fn is_upper_base32_char(c: u8) -> bool {
    c.is_ascii_uppercase() || matches!(c, b'2'..=b'7')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> InvitePayloadV1 {
        InvitePayloadV1 {
            v: INVITE_VERSION,
            r: vec!["ws://127.0.0.1:7000".to_string()],
            c: "J7K4M2Q7RTW6A3BZ".to_string(),
            e: 600,
            o: true,
            k: None,
        }
    }

    #[test]
    fn invite_roundtrip_encode_decode() {
        let payload = sample_payload();
        let invite = encode_invite(&payload).expect("encode invite");

        assert!(invite.starts_with(INVITE_PREFIX));

        let decoded = decode_invite(&invite).expect("decode invite");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decode_rejects_bad_checksum() {
        let payload = sample_payload();
        let invite = encode_invite(&payload).expect("encode invite");

        let (prefix_payload, checksum) = invite
            .split_once('.')
            .expect("encoded invite must contain checksum part");
        let mut tampered_checksum = checksum.to_string();
        let last = tampered_checksum
            .pop()
            .expect("checksum from encoded invite is never empty");
        tampered_checksum.push(if last == 'A' { 'B' } else { 'A' });
        let tampered = format!("{prefix_payload}.{tampered_checksum}");

        let err = decode_invite(&tampered).expect_err("checksum should fail");
        assert!(matches!(err, InviteError::ChecksumMismatch));
    }

    #[test]
    fn decode_rejects_invalid_prefix() {
        let err = decode_invite("XX1:abc.def").expect_err("prefix should fail");
        assert!(matches!(err, InviteError::InvalidPrefix));
    }

    #[test]
    fn validate_rejects_invalid_token() {
        let mut payload = sample_payload();
        payload.c = "invalid-12".to_string();

        let err = payload.validate().expect_err("token chars should fail");
        assert!(matches!(err, InviteError::InvalidTokenLength(_)));

        payload.c = "ABCDEF123456".to_string();
        let err = payload
            .validate()
            .expect_err("non-base32 chars should fail");
        assert!(matches!(err, InviteError::InvalidTokenChars));
    }

    #[test]
    fn validate_rejects_invalid_relay_count() {
        let mut payload = sample_payload();
        payload.r = vec![];
        let err = payload.validate().expect_err("empty relays should fail");
        assert!(matches!(err, InviteError::InvalidRelayCount(0)));

        payload.r = vec![
            "ws://1".to_string(),
            "ws://2".to_string(),
            "ws://3".to_string(),
            "ws://4".to_string(),
        ];
        let err = payload.validate().expect_err("relay list >3 should fail");
        assert!(matches!(err, InviteError::InvalidRelayCount(4)));
    }

    #[test]
    fn validate_rejects_invalid_identity_hint() {
        let mut payload = sample_payload();
        payload.k = Some("not_base64url".to_string());
        let err = payload
            .validate()
            .expect_err("invalid base64url identity hint should fail");
        assert!(matches!(err, InviteError::InvalidIdentityHintEncoding(_)));

        payload.k = Some("QQ".to_string());
        let err = payload
            .validate()
            .expect_err("identity hint length must be 32 bytes");
        assert!(matches!(err, InviteError::InvalidIdentityHintLength(1)));
    }
}
