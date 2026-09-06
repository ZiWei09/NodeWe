use nodewe_runtime::{resolve_command, NodeId, Operation, Scope, TaskRecord, TaskState};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
};
use serde_json::Value;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

struct TlsOptions {
    config: Arc<ClientConfig>,
    server_name: String,
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeEntry {
    id: String,
    name: String,
    online: bool,
    labels: Vec<String>,
}

fn main() {
    if let Err(error) = dispatch(&env::args().skip(1).collect::<Vec<_>>()) {
        if env::var("NODEWE_OUTPUT").as_deref() == Ok("json") {
            eprintln!(
                "{{\"code\":\"{}\",\"message\":\"{}\",\"request_id\":\"{}\"}}",
                error_code(&error),
                json_escape(&error),
                json_escape(&now_id("req"))
            );
        } else {
            eprintln!("{error}");
        }
        std::process::exit(1);
    }
}

fn dispatch(raw_args: &[String]) -> Result<(), String> {
    let args = normalize_args(raw_args)?;
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        print_help();
        return Ok(());
    }
    if args == ["--version"] {
        println!("nodewe {VERSION}");
        return Ok(());
    }
    match args[0].as_str() {
        "auth" => auth(&args[1..]),
        "node" => node(&args[1..]),
        "group" => group(&args[1..]),
        "scope" => scope(&args[1..]),
        "task" => task(&args[1..]),
        "grant" => grant(&args[1..]),
        "approval" => approval(&args[1..]),
        "audit" => audit(&args[1..]),
        "doctor" => doctor(),
        other => Err(format!("unknown command `{other}`; run `nodewe --help`")),
    }
}

fn normalize_args(raw_args: &[String]) -> Result<Vec<String>, String> {
    let mut args = Vec::with_capacity(raw_args.len());
    let mut after_separator = false;
    let mut index = 0;
    while index < raw_args.len() {
        let argument = &raw_args[index];
        if argument == "--" {
            after_separator = true;
            args.push(argument.clone());
            index += 1;
            continue;
        }
        if !after_separator && argument == "--json" {
            env::set_var("NODEWE_OUTPUT", "json");
            index += 1;
            continue;
        }
        if !after_separator && argument == "--output" {
            let format = raw_args
                .get(index + 1)
                .ok_or("--output requires a format")?;
            if format != "json" {
                return Err("only --output json is supported".into());
            }
            env::set_var("NODEWE_OUTPUT", "json");
            index += 2;
            continue;
        }
        if !after_separator && argument == "--non-interactive" {
            index += 1;
            continue;
        }
        if !after_separator && argument == "--timeout" {
            let value = raw_args
                .get(index + 1)
                .ok_or("--timeout requires milliseconds")?;
            args.push("--timeout-ms".into());
            args.push(value.clone());
            index += 2;
            continue;
        }
        if !after_separator && argument == "--profile" {
            let profile = raw_args.get(index + 1).ok_or("--profile requires a name")?;
            NodeId::new(profile.clone()).map_err(|_| "invalid profile name".to_owned())?;
            env::set_var("NODEWE_PROFILE", profile);
            index += 2;
            continue;
        }
        args.push(argument.clone());
        index += 1;
    }
    Ok(args)
}

fn error_code(error: &str) -> &'static str {
    let value = error.to_ascii_lowercase();
    if value.contains("file_output_too_large") {
        "file_output_too_large"
    } else if value.contains("file_input_too_large") {
        "file_input_too_large"
    } else if value.contains("ability_not_implemented") {
        "ability_not_implemented"
    } else if value.contains("auth") || value.contains("token") {
        "unauthenticated"
    } else if value.contains("permission") || value.contains("policy") || value.contains("allowed")
    {
        "policy_denied"
    } else if value.contains("offline") || value.contains("connection") {
        "node_unavailable"
    } else if value.contains("timeout") {
        "task_timeout"
    } else if value.contains("task") && value.contains("failed") {
        "task_failed"
    } else {
        "invalid_request"
    }
}

fn print_help() {
    println!(
        "NodeWe CLI {VERSION}\n\nGlobal options: --output json (or --json) --non-interactive --timeout MS --profile NAME\nCommands:\n  auth login|logout|status\n  node list|pair|enroll|inspect|revoke <node-id> [--labels a,b]\n  group create --id <id> (--nodes a,b | --label label)\n  group list|show|run --group <id> --scope <path> [--max-concurrency N] -- <program> [args...]\n  scope list|inspect <path>\n  task run --node <id> --scope <path> [--timeout-ms N] -- <program> [args...]\n  task submit --node <id> --ability <ability> [--program P --argument A --output-limit N --approval-id ID|--approved]\n    file.read: P is a Scope path; file.write: P is a Scope path and A is content\n  task show|logs|cancel <task-id>\n  grant create|list|revoke <grant-code>\n  approval create|list --node <id> [--program P --argument A]\n  audit list\n  doctor"
    );
}

fn state_dir() -> Result<PathBuf, String> {
    let mut root = env::var_os("NODEWE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".nodewe")))
        .unwrap_or_else(|| PathBuf::from(".nodewe"));
    if let Some(profile) = env::var_os("NODEWE_PROFILE") {
        root = root.join("profiles").join(profile);
    }
    fs::create_dir_all(root.join("tasks"))
        .map_err(|e| format!("cannot initialize NodeWe state: {e}"))?;
    restrict_directory(&root);
    restrict_directory(&root.join("tasks"));
    Ok(root)
}

fn now_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}_{nanos:x}")
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn random_token() -> String {
    let mut bytes = [0_u8; 18];
    if let Ok(mut file) = fs::File::open("/dev/urandom") {
        use std::io::Read as _;
        if file.read_exact(&mut bytes).is_ok() {
            return bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        }
    }
    now_id("grant")
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn auth(args: &[String]) -> Result<(), String> {
    let dir = state_dir()?;
    match args.first().map(String::as_str) {
        Some("login") => {
            let session = dir.join("session");
            fs::write(&session, now_id("session")).map_err(|e| e.to_string())?;
            restrict_file(&session);
            println!("authenticated");
        }
        Some("logout") => {
            let _ = fs::remove_file(dir.join("session"));
            println!("logged out");
        }
        Some("status") => println!("{{\"authenticated\":{}}}", dir.join("session").exists()),
        _ => return Err("usage: nodewe auth login|logout|status".into()),
    }
    Ok(())
}

fn remote_config(args: &[String]) -> Result<Option<(String, String)>, String> {
    let Ok(endpoint) = env::var("NODEWE_CONTROL_PLANE") else {
        return Ok(None);
    };
    let token = if args.first().map(String::as_str) == Some("enroll") {
        remote_token_optional()?
    } else {
        remote_token()?
    };
    Ok(Some((endpoint, token)))
}

fn remote_token_optional() -> Result<String, String> {
    if env::var_os("NODEWE_TOKEN").is_some() || env::var_os("NODEWE_TOKEN_FILE").is_some() {
        remote_token()
    } else {
        Ok(String::new())
    }
}

fn remote_node(args: &[String], endpoint: &str, token: &str) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("list") => println!("{}", http_get_json(endpoint, "/v1/nodes", token)?),
        Some("pair") => {
            let id = option(args, "--id").unwrap_or_else(|| now_id("node"));
            NodeId::new(id.clone()).map_err(|_| "invalid node id".to_owned())?;
            let name = option(args, "--name").unwrap_or_else(|| id.clone());
            let labels = option(args, "--labels").unwrap_or_default();
            parse_labels(&labels)?;
            let body = format!(
                "{{\"node_id\":\"{}\",\"name\":\"{}\",\"labels\":\"{}\"}}",
                json_escape(&id),
                json_escape(&name),
                json_escape(&labels)
            );
            let response = http_post_json(endpoint, "/v1/nodes", &body, token)?;
            save_remote_credential(&id, &response)?;
            println!(
                "{{\"node_id\":\"{}\",\"name\":\"{}\",\"enrolled\":true}}",
                json_escape(&id),
                json_escape(&name)
            );
        }
        Some("enroll") => {
            let id = option(args, "--id").ok_or("--id is required")?;
            NodeId::new(id.clone()).map_err(|_| "invalid node id".to_owned())?;
            let code = option(args, "--grant-code").ok_or("--grant-code is required")?;
            let signature =
                option(args, "--grant-signature").ok_or("--grant-signature is required")?;
            let name = option(args, "--name").unwrap_or_else(|| id.clone());
            let labels = option(args, "--labels").unwrap_or_default();
            parse_labels(&labels)?;
            let body = format!(
                "{{\"grant_code\":\"{}\",\"grant_signature\":\"{}\",\"node_id\":\"{}\",\"name\":\"{}\",\"labels\":\"{}\"}}",
                json_escape(&code),
                json_escape(&signature),
                json_escape(&id),
                json_escape(&name),
                json_escape(&labels)
            );
            let response = http_post_json_unauthenticated(endpoint, "/v1/grants/redeem", &body)?;
            save_remote_credential(&id, &response)?;
            println!(
                "{{\"node_id\":\"{}\",\"name\":\"{}\",\"enrolled\":true}}",
                json_escape(&id),
                json_escape(&name)
            );
        }
        Some("inspect") | Some("show") => {
            let id = args.get(1).ok_or("node id is required")?;
            let nodes = http_get_json(endpoint, "/v1/nodes", token)?;
            let node = find_json_object_by_string(&nodes, "node_id", id)
                .ok_or_else(|| "node not found".to_owned())?;
            println!("{node}");
        }
        Some("revoke") => {
            let id = args.get(1).ok_or("node id is required")?;
            NodeId::new(id.clone()).map_err(|_| "invalid node id".to_owned())?;
            println!(
                "{}",
                http_post_json(endpoint, &format!("/v1/nodes/{id}/revoke"), "{}", token)?
            );
        }
        _ => return Err("usage: nodewe node list|pair|enroll|inspect|revoke".into()),
    }
    Ok(())
}

fn remote_grant(args: &[String], endpoint: &str, token: &str) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("create") => println!("{}", http_post_json(endpoint, "/v1/grants", "{}", token)?),
        Some("list") => println!("{}", http_get_json(endpoint, "/v1/grants", token)?),
        Some("revoke") => {
            let code = args.get(1).ok_or("grant code is required")?;
            NodeId::new(code.clone()).map_err(|_| "invalid grant code".to_owned())?;
            println!(
                "{}",
                http_post_json(endpoint, &format!("/v1/grants/{code}/revoke"), "{}", token)?
            );
        }
        _ => return Err("usage: nodewe grant create|list|revoke <grant-code>".into()),
    }
    Ok(())
}

fn save_remote_credential(node_id: &str, response: &str) -> Result<(), String> {
    let credential = json_string_field(response, "credential")
        .ok_or("Control Plane response did not include a node credential")?;
    let dir = state_dir()?.join("credentials");
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    restrict_directory(&dir);
    let path = dir.join(format!("{node_id}.token"));
    fs::write(&path, credential).map_err(|error| error.to_string())?;
    restrict_file(&path);
    Ok(())
}

fn find_json_object_by_string(array: &str, key: &str, expected: &str) -> Option<String> {
    serde_json::from_str::<Value>(array)
        .ok()?
        .as_array()?
        .iter()
        .find(|object| object.get(key).and_then(Value::as_str) == Some(expected))
        .map(Value::to_string)
}

fn node(args: &[String]) -> Result<(), String> {
    if let Some((endpoint, token)) = remote_config(args)? {
        return remote_node(args, &endpoint, &token);
    }
    let dir = state_dir()?;
    let path = dir.join("nodes.tsv");
    match args.first().map(String::as_str) {
        Some("pair") | Some("enroll") => {
            let id = option(args, "--id").unwrap_or_else(|| now_id("node"));
            let name = option(args, "--name").unwrap_or_else(|| id.clone());
            let labels = parse_labels(&option(args, "--labels").unwrap_or_default())?;
            NodeId::new(id.clone()).map_err(|e| e.to_string())?;
            let mut entries = read_nodes(&path)?;
            if entries.iter().any(|entry| entry.id == id) {
                return Err("node already exists".into());
            }
            entries.push(NodeEntry {
                id: id.clone(),
                name: name.clone(),
                online: true,
                labels,
            });
            write_nodes(&path, &entries)?;
            restrict_file(&path);
            append_audit(
                &dir,
                &format!(
                    "{{\"event\":\"node.paired\",\"node_id\":\"{}\"}}",
                    json_escape(&id)
                ),
            )?;
            println!(
                "{{\"node_id\":\"{}\",\"name\":\"{}\",\"online\":true}}",
                json_escape(&id),
                json_escape(&name)
            );
        }
        Some("list") => {
            let entries = read_nodes(&path)?;
            print!("[");
            for (index, entry) in entries.iter().enumerate() {
                if index > 0 {
                    print!(",");
                }
                print!(
                    "{{\"node_id\":\"{}\",\"name\":\"{}\",\"online\":{},\"labels\":[{}]}}",
                    json_escape(&entry.id),
                    json_escape(&entry.name),
                    entry.online,
                    labels_json(&entry.labels)
                );
            }
            println!("]");
        }
        Some("inspect") => {
            let id = args.get(1).ok_or("usage: nodewe node inspect <node-id>")?;
            let entries = read_nodes(&path)?;
            let Some(entry) = entries.iter().find(|entry| entry.id == *id) else {
                return Err("node not found".into());
            };
            println!(
                "{{\"node_id\":\"{}\",\"name\":\"{}\",\"online\":{},\"revoked\":{},\"labels\":[{}]}}",
                json_escape(&entry.id),
                json_escape(&entry.name),
                entry.online,
                !entry.online,
                labels_json(&entry.labels)
            );
        }
        Some("revoke") => {
            let id = args.get(1).ok_or("usage: nodewe node revoke <node-id>")?;
            let mut entries = read_nodes(&path)?;
            let mut found = false;
            for entry in &mut entries {
                if entry.id == *id {
                    entry.online = false;
                    found = true;
                }
            }
            if !found {
                return Err("node not found".into());
            }
            write_nodes(&path, &entries)?;
            append_audit(
                &dir,
                &format!(
                    "{{\"event\":\"node.revoked\",\"node_id\":\"{}\"}}",
                    json_escape(id)
                ),
            )?;
            println!("{{\"node_id\":\"{}\",\"revoked\":true}}", json_escape(id));
        }
        _ => return Err("usage: nodewe node list|pair|enroll|inspect|revoke <node-id>".into()),
    }
    Ok(())
}

fn group(args: &[String]) -> Result<(), String> {
    let dir = state_dir()?;
    let path = dir.join("groups.tsv");
    match args.first().map(String::as_str) {
        Some("create") => {
            let id = option(args, "--id").ok_or("--id is required")?;
            let nodes = option(args, "--nodes");
            let label = option(args, "--label");
            if id.is_empty() || nodes.is_none() && label.is_none() {
                return Err("invalid group".into());
            }
            NodeId::new(id.clone()).map_err(|_| "invalid group id".to_owned())?;
            let entries = read_nodes(&dir.join("nodes.tsv"))?;
            let selected = select_group_nodes(&entries, nodes.as_deref(), label.as_deref())?;
            let mut groups = read_groups(&path)?;
            if groups.iter().any(|(existing, _)| existing == &id) {
                return Err("group already exists".into());
            }
            groups.push((id.clone(), selected.clone()));
            write_groups(&path, &groups)?;
            restrict_file(&path);
            append_audit(
                &dir,
                &format!(
                    "{{\"event\":\"group.created\",\"group_id\":\"{}\"}}",
                    json_escape(&id)
                ),
            )?;
            println!(
                "{{\"group_id\":\"{}\",\"nodes\":[{}]}}",
                json_escape(&id),
                selected
                    .iter()
                    .map(|node| format!("\"{}\"", json_escape(node)))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        Some("list") => {
            let groups = read_groups(&path)?;
            println!(
                "[{}]",
                groups
                    .iter()
                    .map(|(id, nodes)| format!(
                        "{{\"group_id\":\"{}\",\"node_count\":{}}}",
                        json_escape(id),
                        nodes.len()
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        Some("show") => {
            let id = args.get(1).ok_or("usage: nodewe group show <group-id>")?;
            let groups = read_groups(&path)?;
            let Some((group_id, nodes)) = groups.iter().find(|(group_id, _)| group_id == id) else {
                return Err("group not found".into());
            };
            println!(
                "{{\"group_id\":\"{}\",\"nodes\":[{}]}}",
                json_escape(group_id),
                nodes
                    .iter()
                    .map(|node| format!("\"{}\"", json_escape(node)))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        Some("run") => return run_group(args),
        _ => return Err("usage: nodewe group create|list|show <group-id>".into()),
    }
    Ok(())
}

fn run_group(args: &[String]) -> Result<(), String> {
    let group_id = option(args, "--group")
        .or_else(|| args.get(1).cloned())
        .ok_or("--group is required")?;
    let scope_path = option(args, "--scope").ok_or("--scope is required")?;
    let max_concurrency = option(args, "--max-concurrency")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    let failure_policy = option(args, "--failure-policy").unwrap_or_else(|| "stop".into());
    if !matches!(failure_policy.as_str(), "stop" | "continue") {
        return Err("--failure-policy must be stop or continue".into());
    }
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("use `--` before the command")?;
    let command = args[separator + 1..].to_vec();
    if command.is_empty() {
        return Err("command is required after `--`".into());
    }
    let groups = read_groups(&state_dir()?.join("groups.tsv"))?;
    let (_, nodes) = groups
        .iter()
        .find(|(id, _)| id == &group_id)
        .ok_or("group not found")?;
    if nodes.is_empty() {
        return Err("group has no nodes".into());
    }
    let queue = Arc::new(Mutex::new(nodes.clone()));
    let mut workers = Vec::new();
    for _ in 0..max_concurrency.min(nodes.len()) {
        let queue = Arc::clone(&queue);
        let scope = scope_path.clone();
        let command = command.clone();
        let policy = failure_policy.clone();
        workers.push(thread::spawn(move || {
            let mut failures = Vec::new();
            loop {
                let node = queue.lock().ok().and_then(|mut queue| queue.pop());
                let Some(node) = node else { break };
                let mut task_args = vec![
                    "run".into(),
                    "--node".into(),
                    node.clone(),
                    "--scope".into(),
                    scope.clone(),
                    "--".into(),
                ];
                task_args.extend(command.clone());
                if let Err(error) = run_task(&task_args) {
                    failures.push(format!("{node}: {error}"));
                    if policy == "stop" {
                        break;
                    }
                }
            }
            failures
        }));
    }
    let failures = workers
        .into_iter()
        .flat_map(|worker| {
            worker
                .join()
                .unwrap_or_else(|_| vec!["worker panicked".into()])
        })
        .collect::<Vec<_>>();
    if failures.is_empty() {
        println!(
            "{{\"group_id\":\"{}\",\"status\":\"succeeded\"}}",
            json_escape(&group_id)
        );
        Ok(())
    } else {
        Err(format!("group run failed: {}", failures.join("; ")))
    }
}

fn scope(args: &[String]) -> Result<(), String> {
    let action = args.first().map(String::as_str).unwrap_or("inspect");
    let path = args.get(1).map(String::as_str).unwrap_or(".");
    let scope = Scope::new(path).map_err(|e| e.to_string())?;
    match action {
        "inspect" => println!(
            "{{\"root\":\"{}\",\"operations\":[\"read\",\"write\",\"execute\"]}}",
            json_escape(&scope.root().display().to_string())
        ),
        "list" => println!("{}", scope_listing(&scope)?),
        _ => return Err("usage: nodewe scope list|inspect <path>".into()),
    }
    Ok(())
}

fn scope_listing(scope: &Scope) -> Result<String, String> {
    let mut entries = fs::read_dir(scope.root())
        .map_err(|error| format!("cannot list Scope: {error}"))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
                return None;
            }
            let file_type = entry.file_type().ok()?;
            let kind = if file_type.is_dir() {
                "directory"
            } else if file_type.is_file() {
                "file"
            } else {
                "other"
            };
            let size = if file_type.is_file() {
                entry.metadata().map(|metadata| metadata.len()).unwrap_or(0)
            } else {
                0
            };
            Some((name, kind, size))
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(format!(
        "[{}]",
        entries
            .into_iter()
            .map(|(name, kind, size)| format!(
                "{{\"name\":\"{}\",\"kind\":\"{}\",\"size\":{size}}}",
                json_escape(&name),
                kind
            ))
            .collect::<Vec<_>>()
            .join(",")
    ))
}

fn task(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("run") => run_task(args),
        Some("submit") => submit_task(args),
        Some("show") | Some("logs") | Some("cancel") => task_action(args),
        _ => Err("usage: nodewe task run|show|logs|cancel ...".into()),
    }
}

fn submit_task(args: &[String]) -> Result<(), String> {
    let endpoint = env::var("NODEWE_CONTROL_PLANE")
        .map_err(|_| "NODEWE_CONTROL_PLANE is required".to_owned())?;
    let token = remote_token()?;
    let node_id = option(args, "--node").ok_or("--node is required")?;
    let ability = option(args, "--ability").ok_or("--ability is required")?;
    let program = option(args, "--program").unwrap_or_else(|| "echo".into());
    let argument = option(args, "--argument").unwrap_or_default();
    let output_limit = option(args, "--output-limit")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "--output-limit must be a positive integer".to_owned())
        })
        .transpose()?
        .unwrap_or(1024 * 1024);
    if output_limit == 0 || output_limit > 1024 * 1024 {
        return Err("--output-limit must be between 1 and 1048576".into());
    }
    let idempotency_key = option(args, "--idempotency-key").unwrap_or_else(|| now_id("request"));
    let actor = option(args, "--actor");
    let approval_id = option(args, "--approval-id");
    let approved = has_flag(args, "--approved");
    let request_id = now_id("request");
    let actor_field = actor
        .as_deref()
        .map(|value| format!(",\"actor\":\"{}\"", json_escape(value)))
        .unwrap_or_default();
    let approval_field = approval_id
        .as_deref()
        .map(|value| format!(",\"approval_id\":\"{}\"", json_escape(value)))
        .unwrap_or_default();
    let approved_field = if approved { ",\"approved\":true" } else { "" };
    let body = format!("{{\"request_id\":\"{}\"{},\"node_id\":\"{}\",\"ability\":\"{}\",\"program\":\"{}\",\"argument\":\"{}\",\"idempotency_key\":\"{}\",\"output_limit\":{output_limit}{approval_field}{approved_field}}}", json_escape(&request_id), actor_field, json_escape(&node_id), json_escape(&ability), json_escape(&program), json_escape(&argument), json_escape(&idempotency_key));
    println!("{}", http_post_json(&endpoint, "/v1/tasks", &body, &token)?);
    Ok(())
}

fn grant(args: &[String]) -> Result<(), String> {
    if let Some((endpoint, token)) = remote_config(args)? {
        return remote_grant(args, &endpoint, &token);
    }
    let dir = state_dir()?;
    let path = dir.join("grants.tsv");
    match args.first().map(String::as_str) {
        Some("create") => {
            let code = random_token();
            let expires = now_millis() + 300_000;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| e.to_string())?;
            writeln!(file, "{code}\t{expires}\tunused").map_err(|e| e.to_string())?;
            restrict_file(&path);
            append_audit(
                &dir,
                &format!("{{\"event\":\"grant.created\",\"expires_at\":{expires}}}"),
            )?;
            println!(
                "{{\"grant_code\":\"{}\",\"expires_at\":{expires}}}",
                json_escape(&code)
            );
        }
        Some("list") => {
            if path.exists() {
                for line in fs::read_to_string(path).map_err(|e| e.to_string())?.lines() {
                    let mut fields = line.splitn(3, '\t');
                    if let (Some(code), Some(expires), Some(status)) =
                        (fields.next(), fields.next(), fields.next())
                    {
                        println!(
                            "{{\"grant_code\":\"{}\",\"expires_at\":{},\"status\":\"{}\"}}",
                            json_escape(code),
                            expires,
                            status
                        );
                    }
                }
            }
        }
        Some("revoke") => {
            let code = args
                .get(1)
                .ok_or("usage: nodewe grant revoke <grant-code>")?;
            let contents = fs::read_to_string(&path).unwrap_or_default();
            let mut found = false;
            let rewritten = contents
                .lines()
                .map(|line| {
                    let fields: Vec<_> = line.splitn(3, '\t').collect();
                    if fields.first().copied() == Some(code.as_str()) {
                        found = true;
                        format!(
                            "{}\t{}\trevoked",
                            fields[0],
                            fields.get(1).copied().unwrap_or("0")
                        )
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !found {
                return Err("grant not found".into());
            }
            fs::write(&path, format!("{rewritten}\n")).map_err(|e| e.to_string())?;
            restrict_file(&path);
            append_audit(
                &dir,
                &format!(
                    "{{\"event\":\"grant.revoked\",\"grant_code\":\"{}\"}}",
                    json_escape(code)
                ),
            )?;
            println!(
                "{{\"grant_code\":\"{}\",\"revoked\":true}}",
                json_escape(code)
            );
        }
        _ => return Err("usage: nodewe grant create|list|revoke <grant-code>".into()),
    }
    Ok(())
}

fn approval(args: &[String]) -> Result<(), String> {
    let endpoint = env::var("NODEWE_CONTROL_PLANE")
        .map_err(|_| "NODEWE_CONTROL_PLANE is required".to_owned())?;
    let token = remote_token()?;
    match args.first().map(String::as_str) {
        Some("create") => {
            let node_id = option(args, "--node").ok_or("--node is required")?;
            let program = option(args, "--program").unwrap_or_else(|| "echo".into());
            let argument = option(args, "--argument").unwrap_or_default();
            let actor = option(args, "--actor");
            let actor_field = actor
                .as_deref()
                .map(|value| format!(",\"actor\":\"{}\"", json_escape(value)))
                .unwrap_or_default();
            let body = format!(
                "{{\"node_id\":\"{}\",\"ability\":\"task.exec\",\"program\":\"{}\",\"argument\":\"{}\"{actor_field}}}",
                json_escape(&node_id),
                json_escape(&program),
                json_escape(&argument),
            );
            println!(
                "{}",
                http_post_json(&endpoint, "/v1/approvals", &body, &token)?
            );
        }
        Some("list") => println!("{}", http_get_json(&endpoint, "/v1/approvals", &token)?),
        _ => {
            return Err(
                "usage: nodewe approval create|list --node <id> [--program P --argument A]".into(),
            )
        }
    }
    Ok(())
}

fn run_task(args: &[String]) -> Result<(), String> {
    let dir = state_dir()?;
    let node_id = option(args, "--node").ok_or("--node is required")?;
    let scope_path = option(args, "--scope").ok_or("--scope is required")?;
    let timeout_ms = option(args, "--timeout-ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30_000);
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("use `--` before the command")?;
    let command: Vec<String> = args[separator + 1..].to_vec();
    if command.is_empty() {
        return Err("command is required after `--`".into());
    }
    let nodes = read_nodes(&dir.join("nodes.tsv"))?;
    if !nodes
        .iter()
        .any(|entry| entry.id == node_id && entry.online)
    {
        return Err("node is not paired or has been revoked".into());
    }
    let scope = Scope::new(&scope_path).map_err(|e| e.to_string())?;
    scope
        .authorize(".", Operation::Execute)
        .map_err(|e| e.to_string())?;
    let command = resolve_command(&command, &["echo", "pwd", "ls", "cat", "printf", "uname"])
        .map_err(|e| e.to_string())?;
    let node = NodeId::new(node_id.clone()).map_err(|e| e.to_string())?;
    let id = now_id("task");
    let mut record =
        TaskRecord::new(id.clone(), node, command.clone()).map_err(|e| e.to_string())?;
    record
        .transition(TaskState::Approved)
        .map_err(|e| e.to_string())?;
    record
        .transition(TaskState::Running)
        .map_err(|e| e.to_string())?;
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .current_dir(scope.root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start task: {e}"))?;
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
            record
                .transition(TaskState::TimedOut)
                .map_err(|e| e.to_string())?;
            persist_task(&dir, &record, "", "timed out")?;
            append_audit(
                &dir,
                &format!(
                    "{{\"event\":\"task.timeout\",\"task_id\":\"{}\",\"node_id\":\"{}\"}}",
                    id,
                    json_escape(&node_id)
                ),
            )?;
            return Err(format!("task {id} timed out"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    let (stdout, _) = join_pipe(stdout_reader)?;
    let (stderr, _) = join_pipe(stderr_reader)?;
    let stdout = truncate(&stdout);
    let stderr = truncate(&stderr);
    let state = if status.success() {
        TaskState::Succeeded
    } else {
        TaskState::Failed
    };
    record
        .transition(state.clone())
        .map_err(|e| e.to_string())?;
    persist_task(&dir, &record, &stdout, &stderr)?;
    append_audit(&dir, &format!("{{\"event\":\"task.completed\",\"task_id\":\"{}\",\"node_id\":\"{}\",\"result\":\"{}\"}}", id, json_escape(&node_id), if status.success() { "succeeded" } else { "failed" }))?;
    println!(
        "{{\"task_id\":\"{}\",\"node_id\":\"{}\",\"state\":\"{}\",\"exit_code\":{}}}",
        id,
        json_escape(&node_id),
        state_name(&state),
        status.code().map_or("null".into(), |code| code.to_string())
    );
    Ok(())
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
            truncated |= keep < read;
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

fn task_action(args: &[String]) -> Result<(), String> {
    let dir = state_dir()?;
    let id = args.get(1).ok_or("task id is required")?;
    if let Ok(endpoint) = env::var("NODEWE_CONTROL_PLANE") {
        let token = remote_token()?;
        match args[0].as_str() {
            "show" => {
                println!(
                    "{}",
                    http_get_json(&endpoint, &format!("/v1/tasks/{id}"), &token)?
                );
                return Ok(());
            }
            "logs" => {
                let task = http_get_json(&endpoint, &format!("/v1/tasks/{id}"), &token)?;
                print!("{}", json_string_field(&task, "output").unwrap_or_default());
                return Ok(());
            }
            "cancel" => {
                println!(
                    "{}",
                    http_post_json(&endpoint, &format!("/v1/tasks/{id}/cancel"), "{}", &token)?
                );
                return Ok(());
            }
            _ => {}
        }
    }
    let file = dir.join("tasks").join(format!("{id}.meta"));
    if !file.exists() {
        return Err("task not found".into());
    }
    match args[0].as_str() {
        "show" => print_task_meta(&file),
        "logs" => {
            let stdout = fs::read_to_string(dir.join("tasks").join(format!("{id}.stdout")))
                .unwrap_or_default();
            let stderr = fs::read_to_string(dir.join("tasks").join(format!("{id}.stderr")))
                .unwrap_or_default();
            print!("{stdout}{stderr}");
            Ok(())
        }
        "cancel" => {
            Err("local NodeWe tasks are foreground-only; provide NODEWE_CONTROL_PLANE and NODEWE_TOKEN for remote cancellation".into())
        }
        _ => unreachable!(),
    }
}

fn audit(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) != Some("list") {
        return Err("usage: nodewe audit list".into());
    }
    let path = state_dir()?.join("audit.jsonl");
    if path.exists() {
        print!("{}", fs::read_to_string(path).map_err(|e| e.to_string())?);
    }
    Ok(())
}

fn doctor() -> Result<(), String> {
    let dir = state_dir()?;
    println!("{{\"state_dir\":\"{}\",\"state_writable\":true,\"protocol_version\":1,\"agent\":\"{}\",\"mode\":\"local-mvp\"}}", json_escape(&dir.display().to_string()), VERSION);
    Ok(())
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|argument| argument == name)
}

fn remote_token() -> Result<String, String> {
    if let Ok(token) = env::var("NODEWE_TOKEN") {
        if token.is_empty() {
            return Err("NODEWE_TOKEN cannot be empty".into());
        }
        validate_header_value(&token)?;
        return Ok(token);
    }
    let path = env::var_os("NODEWE_TOKEN_FILE")
        .ok_or_else(|| "NODEWE_TOKEN or NODEWE_TOKEN_FILE is required".to_owned())?;
    let path = PathBuf::from(path);
    let metadata =
        fs::metadata(&path).map_err(|error| format!("cannot read token file: {error}"))?;
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
        return Err("NODEWE_TOKEN_FILE cannot be empty".into());
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

fn http_post_json(endpoint: &str, path: &str, body: &str, token: &str) -> Result<String, String> {
    let tls = load_tls_options(endpoint)?;
    ensure_endpoint_safe(endpoint, tls.is_some())?;
    let mut stream = connect_stream(endpoint, tls.as_ref())?;
    let request = format!("POST {path} HTTP/1.1\r\nHost: {endpoint}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let response = read_response(&mut stream)?;
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

fn http_post_json_unauthenticated(
    endpoint: &str,
    path: &str,
    body: &str,
) -> Result<String, String> {
    let tls = load_tls_options(endpoint)?;
    ensure_endpoint_safe(endpoint, tls.is_some())?;
    let mut stream = connect_stream(endpoint, tls.as_ref())?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {endpoint}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let response = read_response(&mut stream)?;
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

fn http_get_json(endpoint: &str, path: &str, token: &str) -> Result<String, String> {
    let tls = load_tls_options(endpoint)?;
    ensure_endpoint_safe(endpoint, tls.is_some())?;
    let mut stream = connect_stream(endpoint, tls.as_ref())?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {endpoint}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let response = read_response(&mut stream)?;
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

fn json_string_field(object: &str, key: &str) -> Option<String> {
    serde_json::from_str::<Value>(object)
        .ok()?
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn load_tls_options(endpoint: &str) -> Result<Option<TlsOptions>, String> {
    let ca = env::var_os("NODEWE_CLI_TLS_CA");
    let certificate = env::var_os("NODEWE_CLI_TLS_CERT");
    let private_key = env::var_os("NODEWE_CLI_TLS_KEY");
    if ca.is_none() && certificate.is_none() && private_key.is_none() {
        return Ok(None);
    }
    let ca = ca.ok_or("NODEWE_CLI_TLS_CA is required when CLI TLS is enabled")?;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(&ca)
        .map_err(|error| format!("cannot read CLI TLS CA: {error}"))?
    {
        roots
            .add(certificate.map_err(|error| format!("cannot parse CLI TLS CA: {error}"))?)
            .map_err(|error| format!("invalid CLI TLS CA certificate: {error}"))?;
    }
    if roots.is_empty() {
        return Err("NODEWE_CLI_TLS_CA contains no certificates".into());
    }
    let config = match (certificate, private_key) {
        (None, None) => ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        (Some(certificate), Some(private_key)) => {
            let certificates = CertificateDer::pem_file_iter(&certificate)
                .map_err(|error| format!("cannot read CLI TLS client certificate: {error}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("cannot parse CLI TLS client certificate: {error}"))?;
            if certificates.is_empty() {
                return Err("NODEWE_CLI_TLS_CERT contains no certificates".into());
            }
            let key = PrivateKeyDer::from_pem_file(&private_key)
                .map_err(|error| format!("cannot parse CLI TLS client key: {error}"))?;
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_client_auth_cert(certificates, key)
                .map_err(|error| format!("cannot build CLI TLS client config: {error}"))?
        }
        _ => {
            return Err(
                "NODEWE_CLI_TLS_CERT and NODEWE_CLI_TLS_KEY must be supplied together".into(),
            )
        }
    };
    let server_name = env::var("NODEWE_CLI_TLS_SERVER_NAME")
        .unwrap_or_else(|_| endpoint_host(endpoint).to_owned());
    ServerName::try_from(server_name.clone())
        .map_err(|error| format!("invalid CLI TLS server name: {error}"))?;
    Ok(Some(TlsOptions {
        config: Arc::new(config),
        server_name,
    }))
}

fn endpoint_host(endpoint: &str) -> &str {
    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']))
        .unwrap_or(endpoint)
}

fn connect_stream(endpoint: &str, tls: Option<&TlsOptions>) -> Result<HttpStream, String> {
    let stream = TcpStream::connect(endpoint)
        .map_err(|error| format!("control plane connection failed: {error}"))?;
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(HTTP_TIMEOUT)))
        .map_err(|error| format!("cannot configure connection timeout: {error}"))?;
    let Some(tls) = tls else {
        return Ok(HttpStream::Plain(stream));
    };
    let server_name = ServerName::try_from(tls.server_name.clone())
        .map_err(|error| format!("invalid CLI TLS server name: {error}"))?;
    let connection = ClientConnection::new(tls.config.clone(), server_name)
        .map_err(|error| format!("CLI TLS handshake setup failed: {error}"))?;
    Ok(HttpStream::Tls(Box::new(StreamOwned::new(
        connection, stream,
    ))))
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

fn read_nodes(path: &Path) -> Result<Vec<NodeEntry>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| {
                    let mut fields = line.splitn(4, '\t');
                    Some(NodeEntry {
                        id: fields.next()?.to_owned(),
                        name: fields.next()?.to_owned(),
                        online: fields.next()? == "online",
                        labels: parse_labels(fields.next().unwrap_or_default()).ok()?,
                    })
                })
                .collect()
        })
}

fn write_nodes(path: &Path, entries: &[NodeEntry]) -> Result<(), String> {
    let contents = entries
        .iter()
        .map(|entry| {
            format!(
                "{}\t{}\t{}\t{}\n",
                entry.id.replace('\t', " "),
                entry.name.replace('\t', " "),
                if entry.online { "online" } else { "revoked" },
                entry.labels.join(",")
            )
        })
        .collect::<String>();
    fs::write(path, contents).map_err(|e| e.to_string())
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

#[cfg(unix)]
fn restrict_directory(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        let _ = fs::set_permissions(path, permissions);
    }
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) {}

fn read_groups(path: &Path) -> Result<Vec<(String, Vec<String>)>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(fs::read_to_string(path)
        .map_err(|e| e.to_string())?
        .lines()
        .filter_map(|line| {
            let (id, nodes) = line.split_once('\t')?;
            Some((
                id.to_owned(),
                nodes
                    .split(',')
                    .filter(|node| !node.is_empty())
                    .map(str::to_owned)
                    .collect(),
            ))
        })
        .collect())
}

fn parse_labels(value: &str) -> Result<Vec<String>, String> {
    let mut labels = Vec::new();
    for raw in value.split(',') {
        let label = raw.trim();
        if label.is_empty() {
            continue;
        }
        if label.len() > 64
            || !label.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
        {
            return Err("labels must be comma-separated safe identifiers".into());
        }
        if !labels.iter().any(|existing| existing == label) {
            labels.push(label.to_owned());
        }
    }
    Ok(labels)
}

fn select_group_nodes(
    entries: &[NodeEntry],
    explicit_nodes: Option<&str>,
    label: Option<&str>,
) -> Result<Vec<String>, String> {
    if explicit_nodes.is_none() && label.is_none() {
        return Err("group requires --nodes and/or --label".into());
    }
    let explicit = explicit_nodes
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if explicit_nodes.is_some() && explicit.is_empty() {
        return Err("--nodes must contain at least one node id".into());
    }
    for id in &explicit {
        NodeId::new(id.clone()).map_err(|_| "invalid node id in group".to_owned())?;
    }
    if let Some(label) = label {
        parse_labels(label)
            .map_err(|_| "--label must be a single safe label".to_owned())?
            .first()
            .filter(|value| value.as_str() == label)
            .ok_or_else(|| "--label must be a single safe label".to_owned())?;
    }
    let selected = entries
        .iter()
        .filter(|entry| explicit_nodes.is_none() || explicit.iter().any(|id| id == &entry.id))
        .filter(|entry| {
            label.is_none()
                || entry
                    .labels
                    .iter()
                    .any(|value| Some(value.as_str()) == label)
        })
        .map(|entry| entry.id.clone())
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err("group selector matched no nodes".into());
    }
    Ok(selected)
}

fn labels_json(labels: &[String]) -> String {
    labels
        .iter()
        .map(|label| format!("\"{}\"", json_escape(label)))
        .collect::<Vec<_>>()
        .join(",")
}

fn write_groups(path: &Path, groups: &[(String, Vec<String>)]) -> Result<(), String> {
    let contents = groups
        .iter()
        .map(|(id, nodes)| {
            format!(
                "{}\t{}\n",
                id.replace('\t', " "),
                nodes
                    .iter()
                    .map(|node| node.replace([',', '\t', '\n'], " "))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect::<String>();
    fs::write(path, contents).map_err(|e| e.to_string())
}

fn append_audit(dir: &Path, event: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("audit.jsonl"))
        .map_err(|e| e.to_string())?;
    writeln!(file, "{event}").map_err(|e| e.to_string())?;
    restrict_file(&dir.join("audit.jsonl"));
    Ok(())
}

fn truncate(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT)]).into_owned()
}

fn persist_task(dir: &Path, record: &TaskRecord, stdout: &str, stderr: &str) -> Result<(), String> {
    let task_dir = dir.join("tasks");
    let stdout_path = task_dir.join(format!("{}.stdout", record.id));
    let stderr_path = task_dir.join(format!("{}.stderr", record.id));
    fs::write(&stdout_path, stdout).map_err(|e| e.to_string())?;
    fs::write(&stderr_path, stderr).map_err(|e| e.to_string())?;
    restrict_file(&stdout_path);
    restrict_file(&stderr_path);
    let command = record
        .command
        .iter()
        .map(|part| part.replace('\\', "\\\\").replace('\n', "\\n"))
        .collect::<Vec<_>>()
        .join(" ");
    let meta = format!(
        "id={}\nnode_id={}\nstate={}\ncommand={}\n",
        record.id,
        record.node_id.as_str(),
        state_name(&record.state),
        command
    );
    let meta_path = task_dir.join(format!("{}.meta", record.id));
    fs::write(&meta_path, meta).map_err(|e| e.to_string())?;
    restrict_file(&meta_path);
    Ok(())
}

fn print_task_meta(path: &Path) -> Result<(), String> {
    let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;
    print!("{{");
    for (index, line) in contents.lines().enumerate() {
        let (key, value) = line.split_once('=').ok_or("invalid task metadata")?;
        if index > 0 {
            print!(",");
        }
        print!("\"{}\":\"{}\"", key, json_escape(value));
    }
    println!("}}");
    Ok(())
}

fn state_name(state: &TaskState) -> &'static str {
    match state {
        TaskState::Pending => "Pending",
        TaskState::Approved => "Approved",
        TaskState::Running => "Running",
        TaskState::Succeeded => "Succeeded",
        TaskState::Failed => "Failed",
        TaskState::CancelRequested => "CancelRequested",
        TaskState::Cancelled => "Cancelled",
        TaskState::TimedOut => "TimedOut",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_endpoint_safe, parse_labels, read_response, scope_listing, select_group_nodes,
        validate_header_value, NodeEntry, MAX_HTTP_RESPONSE_BYTES,
    };
    use std::io::Cursor;

    #[test]
    fn labels_are_normalized_and_reject_unsafe_values() {
        assert_eq!(
            parse_labels(" gpu,lab,gpu ").unwrap(),
            vec!["gpu".to_owned(), "lab".to_owned()]
        );
        assert!(parse_labels("gpu/secret").is_err());
    }

    #[test]
    fn group_selector_intersects_explicit_nodes_and_labels() {
        let entries = vec![
            NodeEntry {
                id: "gpu-a".into(),
                name: "A".into(),
                online: true,
                labels: vec!["gpu".into(), "lab".into()],
            },
            NodeEntry {
                id: "cpu-a".into(),
                name: "B".into(),
                online: true,
                labels: vec!["cpu".into(), "lab".into()],
            },
        ];
        assert_eq!(
            select_group_nodes(&entries, None, Some("gpu")).unwrap(),
            vec!["gpu-a".to_owned()]
        );
        assert_eq!(
            select_group_nodes(&entries, Some("gpu-a,cpu-a"), Some("lab")).unwrap(),
            vec!["gpu-a".to_owned(), "cpu-a".to_owned()]
        );
        assert!(select_group_nodes(&entries, Some("gpu-a"), Some("cpu")).is_err());
    }

    #[test]
    fn remote_tokens_cannot_inject_http_headers() {
        assert!(validate_header_value("safe-token").is_ok());
        assert!(validate_header_value("bad\r\nX-Injected: yes").is_err());
    }

    #[test]
    fn scope_listing_returns_metadata_without_file_contents() {
        let root = std::env::temp_dir().join(format!("nodewe-scope-{}", super::now_id("test")));
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("secret.txt"), b"do-not-return").unwrap();
        let scope = super::Scope::new(&root).unwrap();
        let listing = scope_listing(&scope).unwrap();
        assert!(listing.contains("secret.txt"));
        assert!(listing.contains("\"size\":13"));
        assert!(!listing.contains("do-not-return"));
        assert!(listing.contains("nested"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn non_loopback_cli_transport_requires_tls() {
        assert!(ensure_endpoint_safe("control.example:443", true).is_ok());
        assert!(ensure_endpoint_safe("control.example:443", false).is_err());
    }

    #[test]
    fn response_reader_rejects_oversized_payloads() {
        let payload = vec![b'x'; MAX_HTTP_RESPONSE_BYTES + 1];
        assert!(read_response(&mut Cursor::new(payload)).is_err());
    }
}
