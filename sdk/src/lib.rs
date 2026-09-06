//! Stable NodeWe integration contracts.
//!
//! The SDK is deliberately transport-neutral and dependency-free. Consumers
//! can validate routing identifiers and protocol envelopes before choosing an
//! HTTP, TLS or future WebSocket adapter.

pub const PROTOCOL_VERSION: u16 = 1;
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub protocol_version: u16,
    pub agent_version: String,
    pub node_id: String,
    pub request_id: String,
    pub message_type: String,
    /// A JSON object supplied by the transport adapter. The SDK does not
    /// interpret ability-specific payloads.
    pub payload_json: String,
}

impl Envelope {
    pub fn new(
        agent_version: impl Into<String>,
        node_id: impl Into<String>,
        request_id: impl Into<String>,
        message_type: impl Into<String>,
        payload_json: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let envelope = Self {
            protocol_version: PROTOCOL_VERSION,
            agent_version: agent_version.into(),
            node_id: node_id.into(),
            request_id: request_id.into(),
            message_type: message_type.into(),
            payload_json: payload_json.into(),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported protocol version");
        }
        if self.agent_version.is_empty()
            || self.node_id.is_empty()
            || self.node_id.len() > 128
            || self.request_id.is_empty()
            || self.request_id.len() > 128
        {
            return Err("invalid envelope identity");
        }
        if !self.node_id.bytes().all(|byte| {
            byte.is_ascii_graphic()
                && !matches!(byte, b'/' | b'\\' | b'?' | b'&' | b'=' | b'#' | b'%')
        }) {
            return Err("invalid node id");
        }
        if !self.message_type.bytes().enumerate().all(|(index, byte)| {
            (index == 0 && byte.is_ascii_lowercase())
                || (index > 0
                    && (byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'.' | b'-')))
        }) {
            return Err("invalid message type");
        }
        let payload = self.payload_json.trim();
        if !payload.starts_with('{') || !payload.ends_with('}') {
            return Err("payload must be a JSON object");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRef {
    pub task_id: String,
    pub node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRef {
    pub grant_code: String,
    pub expires_at_ms: u64,
}

pub mod endpoint {
    pub const HEALTH: &str = "/health";
    pub const NODES: &str = "/v1/nodes";
    pub const GRANTS: &str = "/v1/grants";
    pub const TASKS: &str = "/v1/tasks";
    pub const AGENT_WS: &str = "/v1/agent/ws";
    pub const AUDIT: &str = "/v1/audit";
}

#[cfg(test)]
mod tests {
    use super::{endpoint, Envelope, PROTOCOL_VERSION};

    #[test]
    fn envelope_validates_protocol_shape() {
        let envelope = Envelope::new("0.1.0", "lab-a", "req-1", "task.start", "{}").unwrap();
        assert_eq!(envelope.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn envelope_rejects_path_like_node_ids_and_non_objects() {
        assert!(Envelope::new("0.1.0", "../lab", "req-1", "task.start", "{}").is_err());
        assert!(Envelope::new("0.1.0", "lab&other", "req-1", "task.start", "{}").is_err());
        assert!(Envelope::new("0.1.0", "lab-a", "req-1", "task.start", "[]").is_err());
    }

    #[test]
    fn endpoint_constants_are_stable() {
        assert_eq!(endpoint::TASKS, "/v1/tasks");
        assert_eq!(endpoint::AGENT_WS, "/v1/agent/ws");
    }
}
