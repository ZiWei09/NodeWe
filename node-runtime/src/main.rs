use nodewe_runtime::{resolve_command, NodeId, Operation, Scope};
use ring::digest::{digest as ring_digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
};
use serde_json::Value;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

struct TlsOptions {
    config: std::sync::Arc<ClientConfig>,
    server_name: String,
}

const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const PROTOCOL_VERSION: u16 = 1;
const SUPPORTED_ABILITIES: &[&str] = &["file.read", "file.write", "task.exec", "system.inspect"];
const SUPPORTED_ABILITIES_CSV: &str = "file.read,file.write,task.exec,system.inspect";

enum HttpStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for HttpStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for HttpStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args == ["--version"] {
        println!("node-runtime 0.1.0");
        return;
    }
    if args.is_empty() || args[0] == "--help" {
        println!("node-runtime enroll --endpoint <host:port> --node-id <id> --grant-code CODE --grant-signature SIG --token-file FILE [--name NAME --labels a,b] [--tls-ca CA --tls-cert CERT --tls-key KEY --tls-server-name NAME]\nnode-runtime run --scope <path> [--timeout-ms N] -- <allowed-program> [args...]\nnode-runtime connect --endpoint <host:port> --node-id <id> --scope <path> [--token <credential>] [--transport polling|websocket] [--interval-ms N] [--tls-ca CA --tls-cert CERT --tls-key KEY --tls-server-name NAME]\n  token may also be supplied as NODEWE_NODE_TOKEN or NODEWE_NODE_TOKEN_FILE (recommended for services)");
        return;
    }
    let result = if args[0] == "enroll" {
        enroll(&args)
    } else if args[0] == "connect" {
        connect(&args)
    } else {
        run(&args)
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn enroll(args: &[String]) -> Result<(), String> {
    let endpoint = option(args, "--endpoint").ok_or("--endpoint is required")?;
    let node_id = option(args, "--node-id").ok_or("--node-id is required")?;
    NodeId::new(node_id.clone()).map_err(|_| "invalid node id".to_owned())?;
    let grant_code = option(args, "--grant-code").ok_or("--grant-code is required")?;
    let grant_signature =
        option(args, "--grant-signature").ok_or("--grant-signature is required")?;
    let token_file = option(args, "--token-file")
        .or_else(|| env::var("NODEWE_NODE_TOKEN_FILE").ok())
        .ok_or("--token-file or NODEWE_NODE_TOKEN_FILE is required")?;
    let name = option(args, "--name").unwrap_or_else(|| node_id.clone());
    let labels = option(args, "--labels").unwrap_or_default();
    if !valid_labels(&labels) {
        return Err("labels contain an unsafe or oversized value".into());
    }
    let tls = load_tls_options(args, &endpoint)?;
    ensure_endpoint_safe(&endpoint, tls.is_some())?;
    let body = format!(
        "{{\"grant_code\":\"{}\",\"grant_signature\":\"{}\",\"node_id\":\"{}\",\"name\":\"{}\",\"labels\":\"{}\",\"platform\":\"{}\",\"architecture\":\"{}\",\"version\":\"0.1.0\"}}",
        escape(&grant_code),
        escape(&grant_signature),
        escape(&node_id),
        escape(&name),
        escape(&labels),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );
    let response = post_json_unauthenticated(&endpoint, "/v1/grants/redeem", &body, tls.as_ref())?;
    let credential = json_value(&response, "credential")
        .ok_or("enrollment response did not include credential")?;
    write_token_file(&PathBuf::from(&token_file), &credential)?;
    println!(
        "{{\"node_id\":\"{}\",\"enrolled\":true,\"token_file\":\"{}\"}}",
        escape(&node_id),
        escape(&token_file)
    );
    Ok(())
}

fn connect(args: &[String]) -> Result<(), String> {
    let transport = option(args, "--transport")
        .or_else(|| env::var("NODEWE_AGENT_TRANSPORT").ok())
        .unwrap_or_else(|| "polling".into());
    match transport.as_str() {
        "polling" => connect_polling(args),
        "websocket" | "wss" => connect_websocket(args),
        _ => Err("--transport must be polling or websocket".into()),
    }
}

fn connect_polling(args: &[String]) -> Result<(), String> {
    let endpoint = option(args, "--endpoint").ok_or("--endpoint is required")?;
    let node_id = option(args, "--node-id").ok_or("--node-id is required")?;
    let token = load_node_token(args)?;
    let scope_path = option(args, "--scope").ok_or("--scope is required")?;
    let interval = option(args, "--interval-ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(10_000);
    let tls = load_tls_options(args, &endpoint)?;
    ensure_endpoint_safe(&endpoint, tls.is_some())?;
    let mut backoff_ms = 1_000_u64;
    loop {
        let body = format!(
            "{{\"protocol_version\":{PROTOCOL_VERSION},\"node_id\":\"{}\",\"abilities\":\"{SUPPORTED_ABILITIES_CSV}\",\"platform\":\"{}\",\"architecture\":\"{}\",\"version\":\"0.1.0\"}}",
            escape(&node_id),
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        let response = match post_json(
            &endpoint,
            "/v1/agent/heartbeat",
            &body,
            &token,
            tls.as_ref(),
        ) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("heartbeat failed; retrying in {backoff_ms}ms: {error}");
                thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms.saturating_mul(2)).min(30_000);
                continue;
            }
        };
        validate_heartbeat_ack(&response)?;
        backoff_ms = 1_000;
        println!("{response}");
        let queued = match get_json(
            &endpoint,
            &format!("/v1/agent/tasks?node_id={}", escape(&node_id)),
            &token,
            tls.as_ref(),
        ) {
            Ok(queued) => queued,
            Err(error) => {
                eprintln!("task poll failed; reconnecting: {error}");
                thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms.saturating_mul(2)).min(30_000);
                continue;
            }
        };
        for task in json_objects(&queued) {
            let task_id = json_value(&task, "task_id").ok_or("task response missing task_id")?;
            let request_id = json_value(&task, "request_id").unwrap_or_else(|| task_id.clone());
            let lease_token =
                json_value(&task, "lease_token").ok_or("task response missing lease_token")?;
            let timeout_ms = json_number(&task, "timeout_ms")
                .filter(|value| *value > 0 && *value <= 300_000)
                .unwrap_or(30_000);
            let output_limit = json_number(&task, "output_limit")
                .filter(|value| *value > 0 && *value <= MAX_OUTPUT as u64)
                .map(|value| value as usize)
                .unwrap_or(MAX_OUTPUT);
            let ability = json_value(&task, "ability").unwrap_or_else(|| "task.exec".into());
            let program = json_value(&task, "program").ok_or("task response missing program")?;
            let argument = json_value(&task, "argument").unwrap_or_default();
            let result = execute_task_with_limit(
                &ability,
                &program,
                &argument,
                &scope_path,
                timeout_ms,
                output_limit,
            );
            let (state, output, exit_code) = match result {
                Ok((output, code)) => {
                    (if code == 0 { "succeeded" } else { "failed" }, output, code)
                }
                Err(error) => ("failed", error, 1),
            };
            let result_body = format!(
                "{{\"node_id\":\"{}\",\"request_id\":\"{}\",\"lease_token\":\"{}\",\"state\":\"{}\",\"output\":\"{}\",\"output_sha256\":\"{}\",\"exit_code\":\"{}\"}}",
                escape(&node_id),
                escape(&request_id),
                escape(&lease_token),
                state,
                escape(&output),
                sha256_hex(output.as_bytes()),
                exit_code
            );
            match post_json(
                &endpoint,
                &format!("/v1/agent/tasks/{task_id}/result"),
                &result_body,
                &token,
                tls.as_ref(),
            ) {
                Ok(response) => println!("{response}"),
                Err(error) => eprintln!("task result upload failed for {task_id}: {error}"),
            }
        }
        thread::sleep(Duration::from_millis(interval));
    }
}

fn connect_websocket(args: &[String]) -> Result<(), String> {
    let endpoint = option(args, "--endpoint").ok_or("--endpoint is required")?;
    let node_id = option(args, "--node-id").ok_or("--node-id is required")?;
    let token = load_node_token(args)?;
    let scope_path = option(args, "--scope").ok_or("--scope is required")?;
    let interval = option(args, "--interval-ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(10_000);
    let tls = load_tls_options(args, &endpoint)?;
    ensure_endpoint_safe(&endpoint, tls.is_some())?;
    let mut backoff_ms = 1_000_u64;
    loop {
        match websocket_session(
            &endpoint,
            &node_id,
            &token,
            &scope_path,
            interval,
            tls.as_ref(),
        ) {
            Ok(()) => {
                backoff_ms = 1_000;
                thread::sleep(Duration::from_millis(backoff_ms));
            }
            Err(error) => {
                eprintln!("websocket connection failed; retrying in {backoff_ms}ms: {error}");
                thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = backoff_ms.saturating_mul(2).min(30_000);
            }
        }
    }
}

fn websocket_session(
    endpoint: &str,
    node_id: &str,
    token: &str,
    scope_path: &str,
    interval: u64,
    tls: Option<&TlsOptions>,
) -> Result<(), String> {
    let mut stream = connect_stream(endpoint, tls)?;
    websocket_handshake(&mut stream, endpoint, node_id, token)?;
    loop {
        let heartbeat = format!(
            "{{\"protocol_version\":{PROTOCOL_VERSION},\"agent_version\":\"0.1.0\",\"node_id\":\"{}\",\"request_id\":\"{}\",\"type\":\"heartbeat\",\"abilities\":\"{SUPPORTED_ABILITIES_CSV}\",\"platform\":\"{}\",\"architecture\":\"{}\",\"version\":\"0.1.0\"}}",
            escape(node_id),
            websocket_request_id(),
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        let heartbeat_response = websocket_request(&mut stream, &heartbeat)?;
        validate_heartbeat_ack(&heartbeat_response)?;
        println!("{heartbeat_response}");
        let tasks_request = format!(
            "{{\"protocol_version\":1,\"agent_version\":\"0.1.0\",\"node_id\":\"{}\",\"request_id\":\"{}\",\"type\":\"tasks.request\"}}",
            escape(node_id),
            websocket_request_id()
        );
        let tasks_response = websocket_request(&mut stream, &tasks_request)?;
        let queued =
            json_payload(&tasks_response).ok_or("websocket tasks response is missing payload")?;
        for task in json_objects(&queued) {
            let task_id = json_value(&task, "task_id").ok_or("task response missing task_id")?;
            let request_id = json_value(&task, "request_id").unwrap_or_else(|| task_id.clone());
            let lease_token =
                json_value(&task, "lease_token").ok_or("task response missing lease_token")?;
            let timeout_ms = json_number(&task, "timeout_ms")
                .filter(|value| *value > 0 && *value <= 300_000)
                .unwrap_or(30_000);
            let output_limit = json_number(&task, "output_limit")
                .filter(|value| *value > 0 && *value <= MAX_OUTPUT as u64)
                .map(|value| value as usize)
                .unwrap_or(MAX_OUTPUT);
            let ability = json_value(&task, "ability").unwrap_or_else(|| "task.exec".into());
            let program = json_value(&task, "program").ok_or("task response missing program")?;
            let argument = json_value(&task, "argument").unwrap_or_default();
            let result = execute_task_with_limit(
                &ability,
                &program,
                &argument,
                scope_path,
                timeout_ms,
                output_limit,
            );
            let (state, output, exit_code) = match result {
                Ok((output, code)) => {
                    (if code == 0 { "succeeded" } else { "failed" }, output, code)
                }
                Err(error) => ("failed", error, 1),
            };
            let result_message = format!(
                "{{\"protocol_version\":1,\"agent_version\":\"0.1.0\",\"node_id\":\"{}\",\"request_id\":\"{}\",\"type\":\"task.result\",\"task_id\":\"{}\",\"lease_token\":\"{}\",\"state\":\"{}\",\"output\":\"{}\",\"output_sha256\":\"{}\",\"exit_code\":\"{}\"}}",
                escape(node_id),
                escape(&request_id),
                escape(&task_id),
                escape(&lease_token),
                state,
                escape(&output),
                sha256_hex(output.as_bytes()),
                exit_code
            );
            let _ = websocket_request(&mut stream, &result_message)?;
        }
        thread::sleep(Duration::from_millis(interval));
    }
}

fn websocket_handshake<S: Read + Write>(
    stream: &mut S,
    endpoint: &str,
    node_id: &str,
    token: &str,
) -> Result<(), String> {
    let key = websocket_client_key()?;
    let request = format!(
        "GET /v1/agent/ws?node_id={} HTTP/1.1\r\nHost: {endpoint}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {token}\r\n\r\n",
        escape(node_id)
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("websocket handshake write failed: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("websocket handshake flush failed: {error}"))?;
    let response = read_headers(stream)?;
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 101 {
        return Err(format!("websocket handshake returned HTTP {status}"));
    }
    let expected = websocket_accept(&key);
    if ws_header_value(&response, "sec-websocket-accept") != Some(expected.as_str()) {
        return Err("websocket handshake response has an invalid accept key".into());
    }
    Ok(())
}

fn websocket_request<S: Read + Write>(stream: &mut S, message: &str) -> Result<String, String> {
    websocket_write_frame(stream, 0x1, message.as_bytes())?;
    loop {
        let Some((opcode, payload)) = websocket_read_frame(stream)? else {
            return Err("websocket peer closed the connection".into());
        };
        match opcode {
            0x1 => {
                return String::from_utf8(payload)
                    .map_err(|_| "websocket response is not UTF-8".into());
            }
            0x8 => return Err("websocket peer sent close".into()),
            0x9 => websocket_write_frame(stream, 0xA, &payload)?,
            0xA => {}
            _ => return Err("unsupported websocket response frame".into()),
        }
    }
}

fn read_headers<S: Read>(stream: &mut S) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    while bytes.len() <= 16 * 1024 {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("websocket handshake read failed: {error}"))?;
        if read == 0 {
            return Err("websocket peer closed during handshake".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            return String::from_utf8(bytes[..index + 4].to_vec())
                .map_err(|_| "websocket handshake response is not UTF-8".into());
        }
    }
    Err("websocket handshake response is too large".into())
}

fn ws_header_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn websocket_client_key() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    let mut file = std::fs::File::open("/dev/urandom")
        .map_err(|error| format!("secure random source unavailable: {error}"))?;
    file.read_exact(&mut bytes)
        .map_err(|error| format!("secure random source unavailable: {error}"))?;
    Ok(base64_encode(&bytes))
}

fn websocket_request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("request_{nanos:x}")
}

fn websocket_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + 36);
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64_encode(ring_digest(&SHA1_FOR_LEGACY_USE_ONLY, &input).as_ref())
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as usize;
        let b = chunk.get(1).copied().unwrap_or(0) as usize;
        let c = chunk.get(2).copied().unwrap_or(0) as usize;
        output.push(TABLE[a >> 2] as char);
        output.push(TABLE[((a & 3) << 4) | (b >> 4)] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((b & 15) << 2) | (c >> 6)] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[c & 63] as char
        } else {
            '='
        });
    }
    output
}

fn sha256_hex(value: &[u8]) -> String {
    ring_digest(&SHA256, value)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn websocket_read_frame<S: Read>(stream: &mut S) -> Result<Option<(u8, Vec<u8>)>, String> {
    let mut first = [0_u8; 1];
    if stream
        .read(&mut first)
        .map_err(|error| format!("websocket frame read failed: {error}"))?
        == 0
    {
        return Ok(None);
    }
    let mut second = [0_u8; 1];
    stream
        .read_exact(&mut second)
        .map_err(|error| format!("websocket frame read failed: {error}"))?;
    if first[0] & 0x80 == 0 {
        return Err("fragmented websocket frames are not supported".into());
    }
    if first[0] & 0x70 != 0 {
        return Err("websocket extensions are not negotiated".into());
    }
    if second[0] & 0x80 != 0 {
        return Err("server websocket frames must not be masked".into());
    }
    let length = match second[0] & 0x7F {
        0..=125 => (second[0] & 0x7F) as u64,
        126 => {
            let mut bytes = [0_u8; 2];
            stream
                .read_exact(&mut bytes)
                .map_err(|error| format!("websocket frame read failed: {error}"))?;
            u16::from_be_bytes(bytes) as u64
        }
        127 => {
            let mut bytes = [0_u8; 8];
            stream
                .read_exact(&mut bytes)
                .map_err(|error| format!("websocket frame read failed: {error}"))?;
            u64::from_be_bytes(bytes)
        }
        _ => unreachable!(),
    };
    let opcode = first[0] & 0x0F;
    if length > 1024 * 1024 || (opcode >= 8 && length > 125) {
        return Err("websocket frame too large".into());
    }
    let mut payload = vec![0_u8; length as usize];
    stream
        .read_exact(&mut payload)
        .map_err(|error| format!("websocket frame read failed: {error}"))?;
    Ok(Some((opcode, payload)))
}

fn websocket_write_frame<S: Write>(
    stream: &mut S,
    opcode: u8,
    payload: &[u8],
) -> Result<(), String> {
    if payload.len() > 1024 * 1024 || (opcode >= 8 && payload.len() > 125) {
        return Err("websocket frame too large".into());
    }
    let mut mask = [0_u8; 4];
    let mut random = std::fs::File::open("/dev/urandom")
        .map_err(|error| format!("secure random source unavailable: {error}"))?;
    random
        .read_exact(&mut mask)
        .map_err(|error| format!("secure random source unavailable: {error}"))?;
    let mut header = vec![0x80 | (opcode & 0x0F)];
    match payload.len() {
        0..=125 => header.push(0x80 | payload.len() as u8),
        126..=65_535 => {
            header.push(0x80 | 126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            header.push(0x80 | 127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    header.extend_from_slice(&mask);
    let mut masked = payload.to_vec();
    for (index, byte) in masked.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    stream
        .write_all(&header)
        .and_then(|_| stream.write_all(&masked))
        .and_then(|_| stream.flush())
        .map_err(|error| format!("websocket frame write failed: {error}"))
}

fn json_payload(object: &str) -> Option<String> {
    serde_json::from_str::<Value>(object)
        .ok()?
        .get("payload")
        .map(Value::to_string)
}

fn ensure_endpoint_safe(endpoint: &str, tls_enabled: bool) -> Result<(), String> {
    let host = endpoint
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(endpoint);
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]");
    if tls_enabled || loopback || env::var("NODEWE_ALLOW_INSECURE_HTTP").as_deref() == Ok("1") {
        Ok(())
    } else {
        Err("refusing plaintext Control Plane transport for a non-loopback endpoint; terminate TLS/mTLS locally or explicitly set NODEWE_ALLOW_INSECURE_HTTP=1 for development".into())
    }
}

fn load_tls_options(args: &[String], endpoint: &str) -> Result<Option<TlsOptions>, String> {
    let ca = option(args, "--tls-ca").or_else(|| env::var("NODEWE_TLS_CA").ok());
    let certificate = option(args, "--tls-cert").or_else(|| env::var("NODEWE_TLS_CERT").ok());
    let private_key = option(args, "--tls-key").or_else(|| env::var("NODEWE_TLS_KEY").ok());
    if ca.is_none() && certificate.is_none() && private_key.is_none() {
        return Ok(None);
    }
    let ca = ca.ok_or("--tls-ca/NODEWE_TLS_CA is required when TLS is enabled")?;
    let certificate =
        certificate.ok_or("--tls-cert/NODEWE_TLS_CERT is required when TLS is enabled")?;
    let private_key =
        private_key.ok_or("--tls-key/NODEWE_TLS_KEY is required when TLS is enabled")?;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(&ca)
        .map_err(|error| format!("cannot read TLS CA: {error}"))?
    {
        roots
            .add(certificate.map_err(|error| format!("cannot parse TLS CA: {error}"))?)
            .map_err(|error| format!("invalid TLS CA certificate: {error}"))?;
    }
    if roots.is_empty() {
        return Err("TLS CA contains no certificates".into());
    }
    let certificates = CertificateDer::pem_file_iter(&certificate)
        .map_err(|error| format!("cannot read TLS client certificate: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot parse TLS client certificate: {error}"))?;
    if certificates.is_empty() {
        return Err("TLS client certificate contains no certificates".into());
    }
    let key = PrivateKeyDer::from_pem_file(&private_key)
        .map_err(|error| format!("cannot parse TLS client key: {error}"))?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, key)
        .map_err(|error| format!("cannot build TLS client config: {error}"))?;
    let server_name = option(args, "--tls-server-name")
        .or_else(|| env::var("NODEWE_TLS_SERVER_NAME").ok())
        .unwrap_or_else(|| endpoint_host(endpoint).to_owned());
    ServerName::try_from(server_name.clone())
        .map_err(|error| format!("invalid TLS server name: {error}"))?;
    Ok(Some(TlsOptions {
        config: std::sync::Arc::new(config),
        server_name,
    }))
}

fn endpoint_host(endpoint: &str) -> &str {
    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']))
        .unwrap_or(endpoint)
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn load_node_token(args: &[String]) -> Result<String, String> {
    if let Some(token) = option(args, "--token") {
        if token.is_empty() {
            return Err("--token cannot be empty".into());
        }
        validate_header_value(&token)?;
        return Ok(token);
    }
    if let Ok(token) = env::var("NODEWE_NODE_TOKEN") {
        if token.is_empty() {
            return Err("NODEWE_NODE_TOKEN cannot be empty".into());
        }
        validate_header_value(&token)?;
        return Ok(token);
    }
    let path = env::var_os("NODEWE_NODE_TOKEN_FILE")
        .ok_or("--token, NODEWE_NODE_TOKEN or NODEWE_NODE_TOKEN_FILE is required")?;
    let path = PathBuf::from(path);
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("cannot read token file {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 && mode != 0o400 {
            return Err(format!(
                "token file must be mode 0600 or 0400 (got {mode:o})"
            ));
        }
    }
    let token = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read token file {}: {error}", path.display()))?;
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err("NODEWE_NODE_TOKEN_FILE cannot be empty".into());
    }
    validate_header_value(&token)?;
    Ok(token)
}

fn validate_header_value(value: &str) -> Result<(), String> {
    if value.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
        return Err("token contains an invalid HTTP header character".into());
    }
    Ok(())
}

fn valid_labels(value: &str) -> bool {
    value
        .split(',')
        .filter(|label| !label.trim().is_empty())
        .all(|label| {
            let label = label.trim();
            label.len() <= 64
                && label.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+')
                })
        })
}

fn write_token_file(path: &PathBuf, credential: &str) -> Result<(), String> {
    if credential.is_empty() || credential.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err("enrollment returned an invalid credential".into());
    }
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing token file {}",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create token directory: {error}"))?;
    }
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("cannot create token file: {error}"))?;
    restrict_file(&temporary);
    file.write_all(credential.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("cannot write token file: {error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("cannot install token file: {error}"))?;
    restrict_file(path);
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        let _ = fs::set_permissions(path, permissions);
    }
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

fn get_json(
    endpoint: &str,
    path: &str,
    token: &str,
    tls: Option<&TlsOptions>,
) -> Result<String, String> {
    let mut stream = connect_stream(endpoint, tls)?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {endpoint}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let response = read_response(&mut stream)?;
    response_body(response)
}

fn post_json(
    endpoint: &str,
    path: &str,
    body: &str,
    token: &str,
    tls: Option<&TlsOptions>,
) -> Result<String, String> {
    let mut stream = connect_stream(endpoint, tls)?;
    let request = format!("POST {path} HTTP/1.1\r\nHost: {endpoint}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let response = read_response(&mut stream)?;
    response_body(response)
}

fn post_json_unauthenticated(
    endpoint: &str,
    path: &str,
    body: &str,
    tls: Option<&TlsOptions>,
) -> Result<String, String> {
    let mut stream = connect_stream(endpoint, tls)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {endpoint}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|error| error.to_string())?;
    let response = read_response(&mut stream)?;
    response_body(response)
}

fn connect_stream(endpoint: &str, tls: Option<&TlsOptions>) -> Result<HttpStream, String> {
    let stream = TcpStream::connect(endpoint).map_err(|e| format!("connect failed: {e}"))?;
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(HTTP_TIMEOUT)))
        .map_err(|error| format!("cannot configure connection timeout: {error}"))?;
    if let Some(tls) = tls {
        let server_name = ServerName::try_from(tls.server_name.clone())
            .map_err(|error| format!("invalid TLS server name: {error}"))?;
        let connection = ClientConnection::new(tls.config.clone(), server_name)
            .map_err(|error| format!("TLS handshake setup failed: {error}"))?;
        Ok(HttpStream::Tls(Box::new(StreamOwned::new(
            connection, stream,
        ))))
    } else {
        Ok(HttpStream::Plain(stream))
    }
}

fn read_response<S: Read>(stream: &mut S) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("cannot read control plane response: {error}"))?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > MAX_HTTP_RESPONSE_BYTES {
            return Err("control plane response exceeds the 8 MiB limit".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(bytes).map_err(|_| "control plane response is not valid UTF-8".into())
}

fn response_body(response: String) -> Result<String, String> {
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or(&response)
        .to_owned();
    if (200..300).contains(&status) {
        Ok(body)
    } else {
        Err(format!("control plane returned HTTP {status}: {body}"))
    }
}

fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32))
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn json_value(object: &str, key: &str) -> Option<String> {
    serde_json::from_str::<Value>(object)
        .ok()?
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn json_number(object: &str, key: &str) -> Option<u64> {
    serde_json::from_str::<Value>(object)
        .ok()?
        .get(key)
        .and_then(Value::as_u64)
}

fn validate_heartbeat_ack(response: &str) -> Result<(), String> {
    let parsed = serde_json::from_str::<Value>(response)
        .map_err(|_| "control plane heartbeat response is not valid JSON".to_owned())?;
    let body = parsed
        .get("payload")
        .filter(|value| value.is_object())
        .unwrap_or(&parsed);
    if body.get("protocol_version").and_then(Value::as_u64) != Some(PROTOCOL_VERSION as u64) {
        return Err("control plane negotiated an unsupported protocol version".into());
    }
    let negotiated = body
        .get("negotiated_abilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if SUPPORTED_ABILITIES
        .iter()
        .any(|ability| !negotiated.contains(ability))
    {
        return Err("control plane did not negotiate all required agent abilities".into());
    }
    Ok(())
}

fn json_objects(array: &str) -> Vec<String> {
    serde_json::from_str::<Value>(array)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|value| value.is_object())
        .map(|value| value.to_string())
        .collect()
}

fn read_pipe_bounded<R: Read>(mut reader: R, limit: usize) -> Result<(Vec<u8>, bool), String> {
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Ok((output, truncated));
        }
        if output.len() < limit {
            let keep = (limit - output.len()).min(read);
            output.extend_from_slice(&buffer[..keep]);
            if keep < read {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
}

fn join_pipe(
    handle: JoinHandle<Result<(Vec<u8>, bool), String>>,
) -> Result<(Vec<u8>, bool), String> {
    handle
        .join()
        .map_err(|_| "pipe reader panicked".to_owned())?
}

fn execute(
    command: &[String],
    scope_path: &str,
    timeout_ms: u64,
    output_limit: usize,
) -> Result<(String, i32), String> {
    let scope = Scope::new(scope_path).map_err(|e| e.to_string())?;
    scope
        .authorize(".", Operation::Execute)
        .map_err(|e| e.to_string())?;
    let command = resolve_command(command, &["echo", "pwd", "ls", "cat", "printf", "uname"])
        .map_err(|e| e.to_string())?;
    validate_command_arguments(&command, &scope)?;
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .current_dir(scope.root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("stdout pipe unavailable")?;
    let stderr = child.stderr.take().ok_or("stderr pipe unavailable")?;
    let stdout_reader = thread::spawn(move || read_pipe_bounded(stdout, output_limit));
    let stderr_reader = thread::spawn(move || read_pipe_bounded(stderr, output_limit));
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("task_timeout".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    let (stdout, _stdout_truncated) = join_pipe(stdout_reader)?;
    let (stderr, _stderr_truncated) = join_pipe(stderr_reader)?;
    let mut text = String::from_utf8_lossy(&stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&stderr));
    text = redact_sensitive(&text);
    text = truncate_utf8(&text, output_limit);
    Ok((text, status.code().unwrap_or(1)))
}

#[cfg(test)]
fn execute_task(
    ability: &str,
    program: &str,
    argument: &str,
    scope_path: &str,
    timeout_ms: u64,
) -> Result<(String, i32), String> {
    execute_task_with_limit(
        ability, program, argument, scope_path, timeout_ms, MAX_OUTPUT,
    )
}

fn execute_task_with_limit(
    ability: &str,
    program: &str,
    argument: &str,
    scope_path: &str,
    timeout_ms: u64,
    output_limit: usize,
) -> Result<(String, i32), String> {
    match ability {
        "task.exec" => {
            let command = if argument.is_empty() {
                vec![program.to_owned()]
            } else {
                vec![program.to_owned(), argument.to_owned()]
            };
            execute(&command, scope_path, timeout_ms, output_limit)
        }
        "file.read" => {
            let scope = Scope::new(scope_path).map_err(|error| error.to_string())?;
            let path = scope
                .authorize(program, Operation::Read)
                .map_err(|error| error.to_string())?;
            let bytes = read_scoped_file(&path)?;
            if bytes.len() > output_limit {
                return Err("file_output_too_large".into());
            }
            let output = truncate_utf8(
                &redact_sensitive(&String::from_utf8_lossy(&bytes)),
                output_limit,
            );
            Ok((output, 0))
        }
        "file.write" => {
            if argument.len() > MAX_OUTPUT {
                return Err("file_input_too_large".into());
            }
            let scope = Scope::new(scope_path).map_err(|error| error.to_string())?;
            let path = scope
                .authorize(program, Operation::Write)
                .map_err(|error| error.to_string())?;
            write_scoped_file(&path, argument.as_bytes())?;
            Ok((format!("wrote {} bytes", argument.len()), 0))
        }
        "system.inspect" => Ok((
            format!(
                "{{\"platform\":\"{}\",\"architecture\":\"{}\",\"agent_version\":\"0.1.0\"}}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
            0,
        )),
        _ => Err("ability_not_implemented".into()),
    }
}

/// Truncate text by byte budget without splitting a UTF-8 code point.
fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = 0;
    for (index, character) in value.char_indices() {
        let next = index + character.len_utf8();
        if next > max_bytes {
            break;
        }
        end = next;
    }
    value[..end].to_owned()
}

fn validate_command_arguments(command: &[String], scope: &Scope) -> Result<(), String> {
    let program = command
        .first()
        .and_then(|value| Path::new(value).file_name())
        .and_then(|value| value.to_str())
        .ok_or("invalid command")?;
    let path_arguments = match program {
        "cat" => {
            if command.len() == 1 {
                return Err("cat requires an explicit Scope-relative path".into());
            }
            true
        }
        "ls" => true,
        _ => false,
    };
    if !path_arguments {
        return Ok(());
    }
    for argument in &command[1..] {
        if argument.is_empty() || argument.starts_with('-') {
            return Err("command options are not allowed; use a Scope-relative path".into());
        }
        scope
            .authorize(argument, Operation::Read)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn read_scoped_file(path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    {
        let mut file = secure_open_file(path, false)?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() {
            return Err("file.read requires a regular file".into());
        }
        if metadata.len() > MAX_OUTPUT as u64 {
            return Err("file_output_too_large".into());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        fs::read(path).map_err(|error| error.to_string())
    }
}

fn write_scoped_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut file = secure_open_file(path, true)?;
        file.write_all(contents)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents).map_err(|error| error.to_string())
    }
}

#[cfg(unix)]
fn secure_open_file(path: &Path, write: bool) -> Result<std::fs::File, String> {
    use std::ffi::CString;
    use std::os::unix::{ffi::OsStrExt, io::FromRawFd};
    let mut components = path.components();
    let root = components.next().ok_or("invalid path")?;
    let root_c = CString::new(root.as_os_str().as_bytes()).map_err(|_| "invalid path")?;
    let mut fd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    for component in components {
        let name = component.as_os_str().as_bytes();
        if name.is_empty() {
            continue;
        }
        let c = CString::new(name).map_err(|_| "invalid path")?;
        let is_last = component == path.components().next_back().unwrap();
        let flags = if write && is_last {
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC
        } else {
            libc::O_RDONLY | if is_last { 0 } else { libc::O_DIRECTORY }
        } | libc::O_CLOEXEC
            | libc::O_NOFOLLOW;
        let next = unsafe { libc::openat(fd, c.as_ptr(), flags, 0o600) };
        unsafe {
            libc::close(fd);
        }
        if next < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        fd = next;
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

fn redact_sensitive(text: &str) -> String {
    text.lines()
        .map(|line| {
            let upper = line.to_ascii_uppercase();
            if ["TOKEN=", "SECRET=", "PASSWORD=", "API_KEY=", "PRIVATE_KEY="]
                .iter()
                .any(|marker| upper.contains(marker))
            {
                "[REDACTED]".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn run(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) != Some("run") {
        return Err("usage: node-runtime run --scope <path> -- <command>".into());
    }
    let scope_path = args
        .windows(2)
        .find(|pair| pair[0] == "--scope")
        .map(|pair| pair[1].clone())
        .ok_or("--scope is required")?;
    let timeout_ms = args
        .windows(2)
        .find(|pair| pair[0] == "--timeout-ms")
        .and_then(|pair| pair[1].parse::<u64>().ok())
        .unwrap_or(30_000);
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("use `--` before the command")?;
    let command = &args[separator + 1..];
    if command.is_empty() {
        return Err("command is required".into());
    }
    let scope = Scope::new(scope_path).map_err(|e| e.to_string())?;
    scope
        .authorize(".", Operation::Execute)
        .map_err(|e| e.to_string())?;
    let command = resolve_command(command, &["echo", "pwd", "ls", "cat", "printf", "uname"])
        .map_err(|e| e.to_string())?;
    validate_command_arguments(&command, &scope)?;
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .current_dir(scope.root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("stdout pipe unavailable")?;
    let stderr = child.stderr.take().ok_or("stderr pipe unavailable")?;
    let stdout_reader = thread::spawn(move || read_pipe_bounded(stdout, MAX_OUTPUT));
    let stderr_reader = thread::spawn(move || read_pipe_bounded(stderr, MAX_OUTPUT));
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("task_timeout".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    let (stdout, _) = join_pipe(stdout_reader)?;
    let (stderr, _) = join_pipe(stderr_reader)?;
    println!(
        "{{\"result\":\"{}\",\"exit_code\":{}}}",
        if status.success() {
            "succeeded"
        } else {
            "failed"
        },
        status.code().map_or("null".into(), |code| code.to_string())
    );
    print!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    if status.success() {
        Ok(())
    } else {
        Err("task_failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_endpoint_safe, execute_task, execute_task_with_limit, json_objects, json_value,
        read_response, redact_sensitive, validate_header_value, validate_heartbeat_ack,
        websocket_accept, websocket_request_id, write_token_file, MAX_HTTP_RESPONSE_BYTES,
        MAX_OUTPUT,
    };
    use std::io::Cursor;

    #[test]
    fn redacts_common_secret_assignments() {
        assert_eq!(redact_sensitive("TOKEN=secret\nhello"), "[REDACTED]\nhello");
    }

    #[test]
    fn refuses_plaintext_remote_endpoint_by_default() {
        assert!(ensure_endpoint_safe("example.invalid:8787", false).is_err());
    }

    #[test]
    fn permits_loopback_endpoint() {
        assert!(ensure_endpoint_safe("127.0.0.1:8787", false).is_ok());
    }

    #[test]
    fn websocket_accept_matches_rfc6455_example() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn heartbeat_ack_requires_protocol_and_all_negotiated_abilities() {
        let response = r#"{"protocol_version":1,"negotiated_abilities":["file.read","file.write","task.exec","system.inspect"]}"#;
        assert!(validate_heartbeat_ack(response).is_ok());
        assert!(validate_heartbeat_ack(
            r#"{"protocol_version":1,"negotiated_abilities":["file.read"]}"#
        )
        .is_err());
        assert!(validate_heartbeat_ack(
            r#"{"protocol_version":2,"negotiated_abilities":["file.read","file.write","task.exec","system.inspect"]}"#
        )
        .is_err());
    }

    #[test]
    fn file_abilities_stay_inside_scope_and_do_not_echo_writes() {
        let root =
            std::env::temp_dir().join(format!("nodewe-agent-test-{}", websocket_request_id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("input.txt"), b"hello").unwrap();
        let root_string = root.to_string_lossy().into_owned();
        let (read, code) = execute_task("file.read", "input.txt", "", &root_string, 1_000).unwrap();
        assert_eq!((read, code), ("hello".to_owned(), 0));
        let (command_output, code) =
            execute_task("task.exec", "cat", "input.txt", &root_string, 1_000).unwrap();
        assert_eq!((command_output, code), ("hello".to_owned(), 0));
        assert!(execute_task("task.exec", "cat", "/etc/passwd", &root_string, 1_000).is_err());
        assert!(execute_task("task.exec", "cat", "", &root_string, 1_000).is_err());
        assert!(execute_task("task.exec", "ls", "/", &root_string, 1_000).is_err());
        let (write, code) =
            execute_task("file.write", "output.txt", "secret", &root_string, 1_000).unwrap();
        assert_eq!((write, code), ("wrote 6 bytes".to_owned(), 0));
        assert_eq!(
            std::fs::read_to_string(root.join("output.txt")).unwrap(),
            "secret"
        );
        assert!(execute_task("file.read", "../outside.txt", "", &root_string, 1_000).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn output_limits_do_not_split_utf8() {
        let root =
            std::env::temp_dir().join(format!("nodewe-output-limit-{}", websocket_request_id()));
        std::fs::create_dir_all(&root).unwrap();
        let root_string = root.to_string_lossy().into_owned();
        let (output, code) =
            execute_task_with_limit("task.exec", "printf", "你好", &root_string, 1_000, 1).unwrap();
        assert_eq!((output, code), (String::new(), 0));
        let (output, code) =
            execute_task_with_limit("task.exec", "printf", "你好", &root_string, 1_000, 3).unwrap();
        assert_eq!((output, code), ("你".to_owned(), 0));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn json_task_parser_handles_braces_and_unicode() {
        let tasks = json_objects(r#"[{"task_id":"one","argument":"a},{b\u4f60"}]"#);
        assert_eq!(tasks.len(), 1);
        assert_eq!(
            json_value(&tasks[0], "argument").as_deref(),
            Some("a},{b你")
        );
    }

    #[test]
    fn large_child_output_does_not_block_until_timeout() {
        let root =
            std::env::temp_dir().join(format!("nodewe-large-output-{}", websocket_request_id()));
        std::fs::create_dir_all(&root).unwrap();
        let root_string = root.to_string_lossy().into_owned();
        let output = "x".repeat(70_000);
        let (result, code) = execute_task_with_limit(
            "task.exec",
            "printf",
            &output,
            &root_string,
            1_000,
            MAX_OUTPUT,
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(result.len(), output.len());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn node_tokens_cannot_inject_http_headers() {
        assert!(validate_header_value("safe-token").is_ok());
        assert!(validate_header_value("bad\r\nX-Injected: yes").is_err());
    }

    #[test]
    fn enrollment_token_file_is_restricted_and_not_overwritten() {
        let path = std::env::temp_dir().join(format!("nodewe-token-{}", websocket_request_id()));
        write_token_file(&path, "credential-value").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "credential-value\n"
        );
        assert!(write_token_file(&path, "replacement").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn response_reader_rejects_oversized_payloads() {
        let payload = vec![b'x'; MAX_HTTP_RESPONSE_BYTES + 1];
        assert!(read_response(&mut Cursor::new(payload)).is_err());
    }
}
