use crate::app_state::ConnId;
use tracing::{debug, warn};

pub fn log_inbound_event(
    conn_id: ConnId,
    event_type: &str,
    request_id: Option<&str>,
    payload_bytes: usize,
) {
    debug!(
        %conn_id,
        event_type,
        request_id = request_id.unwrap_or("-"),
        payload_bytes,
        "connection.event_received"
    );
}

pub fn log_invalid_json(conn_id: ConnId, payload_bytes: usize) {
    debug!(
        %conn_id,
        payload_bytes,
        "connection.event_invalid_json"
    );
}

pub fn log_handshake_failure(conn_id: ConnId, event_type: &str, reason: &str) {
    warn!(
        %conn_id,
        event_type,
        reason,
        "connection.handshake_failure"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        io::Write,
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::{fmt::MakeWriter, prelude::*};
    use uuid::Uuid;

    #[derive(Clone, Default)]
    struct SharedWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedWriter {
        fn into_string(self) -> String {
            let bytes = self.buf.lock().expect("buffer lock poisoned").clone();
            String::from_utf8(bytes).expect("log output should be utf8")
        }
    }

    impl<'a> MakeWriter<'a> for SharedWriter {
        type Writer = SharedWriterGuard;

        fn make_writer(&'a self) -> Self::Writer {
            SharedWriterGuard {
                buf: Arc::clone(&self.buf),
            }
        }
    }

    struct SharedWriterGuard {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedWriterGuard {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.buf
                .lock()
                .expect("buffer lock poisoned")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn logs_only_metadata_without_payload_contents() {
        let writer = SharedWriter::default();

        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .without_time()
                .with_writer(writer.clone()),
        );

        let invite_code = "DL1:ZXhhbXBsZS5jb2Rl.ABCDEFG";
        let secret_text = "secret message body";

        tracing::subscriber::with_default(subscriber, || {
            log_inbound_event(Uuid::new_v4(), "invite.use", Some("req-1"), 321);
            log_invalid_json(Uuid::new_v4(), 144);
            log_handshake_failure(Uuid::new_v4(), "e2e.prekey.get", "prekey_not_found");

            // These values should never be present in log output.
            let _ = invite_code;
            let _ = secret_text;
        });

        let output = writer.into_string();

        assert!(output.contains("connection.event_received"));
        assert!(output.contains("invite.use"));
        assert!(output.contains("req-1"));
        assert!(output.contains("connection.handshake_failure"));
        assert!(output.contains("prekey_not_found"));
        assert!(!output.contains(invite_code));
        assert!(!output.contains(secret_text));
    }
}
