//! Optional adapter contracts. Adapters translate external device protocols
//! into audited NodeWe task requests without expanding the Agent core.
use nodewe_sdk::TaskRef;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterRequest {
    pub node_id: String,
    pub ability: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterResult {
    pub task: TaskRef,
    pub output_json: String,
}

pub trait Adapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn abilities(&self) -> &'static [&'static str];
    fn translate(&self, request: AdapterRequest) -> Result<AdapterRequest, String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ComputerUseAdapter;
impl Adapter for ComputerUseAdapter {
    fn name(&self) -> &'static str {
        "computer-use"
    }
    fn abilities(&self) -> &'static [&'static str] {
        &["screen.capture", "input.request"]
    }
    fn translate(&self, request: AdapterRequest) -> Result<AdapterRequest, String> {
        if !self.abilities().contains(&request.ability.as_str()) {
            return Err("unsupported adapter ability".into());
        }
        if request.node_id.is_empty() || request.payload_json.trim().is_empty() {
            return Err("invalid adapter request".into());
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn computer_use_is_explicitly_allowlisted() {
        let adapter = ComputerUseAdapter;
        assert!(adapter
            .translate(AdapterRequest {
                node_id: "n1".into(),
                ability: "screen.capture".into(),
                payload_json: "{}".into()
            })
            .is_ok());
        assert!(adapter
            .translate(AdapterRequest {
                node_id: "n1".into(),
                ability: "shell".into(),
                payload_json: "{}".into()
            })
            .is_err());
    }
}
