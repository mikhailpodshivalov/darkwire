use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct IncomingEnvelope {
    #[serde(rename = "t")]
    pub(super) event_type: String,
    #[serde(rename = "rid")]
    pub(super) request_id: Option<String>,
    #[serde(rename = "d", default)]
    pub(super) data: serde_json::Value,
}

pub(super) fn parse_incoming_envelope(raw: &str) -> Option<IncomingEnvelope> {
    serde_json::from_str(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkwire_protocol::events;

    #[test]
    fn parse_incoming_envelope_extracts_fields() {
        let raw = r#"{"t":"invite.use","rid":"req-42","d":{"invite":"DL1:abc.def"}}"#;
        let envelope = parse_incoming_envelope(raw).expect("envelope should parse");

        assert_eq!(envelope.event_type, events::names::INVITE_USE);
        assert_eq!(envelope.request_id.as_deref(), Some("req-42"));
        assert_eq!(envelope.data["invite"], "DL1:abc.def");
    }

    #[test]
    fn parse_incoming_envelope_returns_none_for_invalid_json() {
        assert!(parse_incoming_envelope("not-json").is_none());
    }
}
