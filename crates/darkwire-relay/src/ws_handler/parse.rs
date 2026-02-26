use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IncomingEnvelope {
    #[serde(rename = "pv")]
    pub(super) protocol_version: Option<u8>,
    #[serde(rename = "t")]
    pub(super) event_type: String,
    #[serde(rename = "rid")]
    pub(super) request_id: Option<String>,
    #[serde(rename = "d")]
    pub(super) data: serde_json::Value,
}

pub(super) fn parse_incoming_envelope(raw: &str) -> Option<IncomingEnvelope> {
    let parsed: IncomingEnvelope = serde_json::from_str(raw).ok()?;
    if !parsed.data.is_object() {
        return None;
    }
    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkwire_protocol::events;

    #[test]
    fn parse_incoming_envelope_extracts_fields() {
        let raw = r#"{"pv":2,"t":"invite.use","rid":"req-42","d":{"invite":"DL1:abc.def"}}"#;
        let envelope = parse_incoming_envelope(raw).expect("envelope should parse");

        assert_eq!(envelope.protocol_version, Some(2));
        assert_eq!(envelope.event_type, events::names::INVITE_USE);
        assert_eq!(envelope.request_id.as_deref(), Some("req-42"));
        assert_eq!(envelope.data["invite"], "DL1:abc.def");
    }

    #[test]
    fn parse_incoming_envelope_returns_none_for_invalid_json() {
        assert!(parse_incoming_envelope("not-json").is_none());
    }

    #[test]
    fn parse_incoming_envelope_rejects_unknown_top_level_fields() {
        let raw = r#"{"pv":2,"t":"invite.use","rid":"req-42","d":{"invite":"DL1:abc.def"},"x":1}"#;
        assert!(parse_incoming_envelope(raw).is_none());
    }

    #[test]
    fn parse_incoming_envelope_rejects_non_object_data() {
        let raw = r#"{"pv":2,"t":"invite.use","rid":"req-42","d":"not-object"}"#;
        assert!(parse_incoming_envelope(raw).is_none());
    }
}
