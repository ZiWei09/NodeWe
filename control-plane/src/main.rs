//! Minimal Control Plane for the first production candidate. Native TLS/mTLS
//! is available through environment-configured certificate files; a hardened
//! reverse proxy remains supported for deployments that centralize ingress.

use postgres::{Client, NoTls};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::digest::{digest as ring_digest, SHA1_FOR_LEGACY_USE_ONLY};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use rusqlite::{params, Connection};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde_json::Value;
use std::{
    env, fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
struct State {
    admin_token: String,
    grant_secret: String,
    store: Arc<Mutex<Store>>,
    require_approval_records: bool,
    policy: Policy,
    oidc: Option<OidcConfig>,
    active_connections: Arc<AtomicU64>,
    _store_lock: Option<Arc<StoreLock>>,
    backend: Arc<dyn StoreBackend>,
}

trait StoreBackend: Send + Sync {
    fn persist(&self, store: &Store) -> Result<(), String>;
}

struct SnapshotBackend {
    data_dir: Option<PathBuf>,
}

impl StoreBackend for SnapshotBackend {
    fn persist(&self, store: &Store) -> Result<(), String> {
        persist_snapshot(self.data_dir.as_deref(), store)
    }
}

/// Transactional SQLite backend. The canonical NodeWe snapshot remains the
/// payload so migrations keep the exact same data model while SQLite provides
/// atomic commit and crash recovery.
struct PostgresBackend {
    url: String,
}

impl StoreBackend for PostgresBackend {
    fn persist(&self, store: &Store) -> Result<(), String> {
        let mut client = Client::connect(&self.url, NoTls)
            .map_err(|e| format!("postgres connect failed: {e}"))?;
        client.batch_execute("CREATE TABLE IF NOT EXISTS nodewe_state (id SMALLINT PRIMARY KEY CHECK (id=1), snapshot BYTEA NOT NULL, updated_at BIGINT NOT NULL)").map_err(|e| format!("postgres schema failed: {e}"))?;
        let snapshot = encode_store_bytes(snapshot_text(store).as_bytes())?;
        let mut tx = client
            .transaction()
            .map_err(|e| format!("postgres transaction failed: {e}"))?;
        tx.execute("INSERT INTO nodewe_state (id,snapshot,updated_at) VALUES (1,$1,$2) ON CONFLICT (id) DO UPDATE SET snapshot=EXCLUDED.snapshot,updated_at=EXCLUDED.updated_at", &[&snapshot, &(now() as i64)]).map_err(|e| format!("postgres write failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("postgres commit failed: {e}"))?;
        Ok(())
    }
}

struct SqliteBackend {
    path: PathBuf,
}

impl StoreBackend for SqliteBackend {
    fn persist(&self, store: &Store) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create data directory: {e}"))?;
            restrict_directory(parent);
        }
        let connection =
            Connection::open(&self.path).map_err(|e| format!("sqlite open failed: {e}"))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS nodewe_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    snapshot BLOB NOT NULL,
                    updated_at INTEGER NOT NULL
                 );",
            )
            .map_err(|e| format!("sqlite schema failed: {e}"))?;
        let snapshot = snapshot_text(store);
        let encoded = encode_store_bytes(snapshot.as_bytes())?;
        let transaction = connection
            .unchecked_transaction()
            .map_err(|e| format!("sqlite transaction failed: {e}"))?;
        transaction
            .execute(
                "INSERT INTO nodewe_state (id, snapshot, updated_at) VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot, updated_at=excluded.updated_at",
                params![encoded, now() as i64],
            )
            .map_err(|e| format!("sqlite write failed: {e}"))?;
        transaction
            .commit()
            .map_err(|e| format!("sqlite commit failed: {e}"))?;
        restrict_file(&self.path);
        Ok(())
    }
}

const MAX_CONNECTIONS: u64 = 256;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

struct ConnectionGuard {
    active: Arc<AtomicU64>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct StoreLock {
    path: PathBuf,
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OidcConfig {
    issuer: String,
    audience: String,
    hmac_secret: Vec<u8>,
    admin_group: String,
    group_claim: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AuthContext {
    authorized: bool,
    admin: bool,
    node: bool,
    actor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Policy {
    allowed_abilities: Vec<String>,
    approval_required: Vec<String>,
    allowed_data_classes: Vec<String>,
    allowed_actors: Vec<String>,
    allowed_commands: Vec<String>,
    allowed_paths: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_abilities: SUPPORTED_ABILITIES
                .iter()
                .map(|ability| (*ability).to_owned())
                .collect(),
            approval_required: vec!["task.exec".into(), "file.write".into()],
            allowed_data_classes: Vec::new(),
            allowed_actors: Vec::new(),
            allowed_commands: Vec::new(),
            allowed_paths: Vec::new(),
        }
    }
}
#[derive(Clone, Default)]
struct Store {
    nodes: Vec<Node>,
    tasks: Vec<Task>,
    audit: Vec<Activity>,
    grants: Vec<Grant>,
    approvals: Vec<Approval>,
}
#[derive(Clone)]
struct Node {
    id: String,
    name: String,
    online: bool,
    revoked: bool,
    credential: String,
    abilities: String,
    platform: String,
    architecture: String,
    version: String,
    labels: String,
    region: String,
    data_class: String,
    capacity: String,
    last_seen: u64,
}
#[derive(Clone)]
struct Task {
    id: String,
    request_id: String,
    actor: String,
    node_id: String,
    ability: String,
    state: String,
    idempotency_key: String,
    program: String,
    argument: String,
    output: String,
    output_sha256: String,
    output_truncated: bool,
    output_limit: usize,
    exit_code: Option<i32>,
    lease_until: u64,
    /// Random fencing token for the current dispatch lease. A result must
    /// present the token issued for that dispatch, preventing a stale Agent
    /// from completing a task after it has been reclaimed by another Agent.
    lease_token: String,
    timeout_ms: u64,
}
#[derive(Clone)]
struct Activity {
    id: String,
    event: String,
    node_id: Option<String>,
    task_id: Option<String>,
    actor: Option<String>,
    timestamp: u64,
    prev_hash: String,
    hash: String,
}
#[derive(Clone)]
struct Grant {
    code: String,
    signature: String,
    expires_at: u64,
    used: bool,
    revoked: bool,
}
#[derive(Clone)]
struct Approval {
    id: String,
    node_id: String,
    ability: String,
    program: String,
    argument: String,
    actor: String,
    expires_at: u64,
    used: bool,
}

const PROTOCOL_VERSION: u16 = 1;
const SUPPORTED_ABILITIES: &[&str] = &["file.read", "file.write", "task.exec", "system.inspect"];
const DEFAULT_TASK_TIMEOUT_MS: u64 = 30_000;
const MAX_TASK_TIMEOUT_MS: u64 = 300_000;
const MAX_PERSISTED_OUTPUT_BYTES: usize = 4 * 1024;
const MAX_TASK_OUTPUT_LIMIT: usize = 1024 * 1024;
const NODE_ONLINE_TTL_MS: u64 = 30_000;
const MIN_NODE_ONLINE_TTL_MS: u64 = 1_000;
const MAX_NODE_ONLINE_TTL_MS: u64 = 300_000;

fn node_online_ttl_ms() -> u64 {
    env::var("NODEWE_NODE_ONLINE_TTL_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (MIN_NODE_ONLINE_TTL_MS..=MAX_NODE_ONLINE_TTL_MS).contains(value))
        .unwrap_or(NODE_ONLINE_TTL_MS)
}

fn validate_node_online_ttl() -> Result<(), String> {
    let Some(raw) = env::var("NODEWE_NODE_ONLINE_TTL_MS").ok() else {
        return Ok(());
    };
    let parsed = raw
        .parse::<u64>()
        .map_err(|_| "NODEWE_NODE_ONLINE_TTL_MS must be an integer".to_owned())?;
    if !(MIN_NODE_ONLINE_TTL_MS..=MAX_NODE_ONLINE_TTL_MS).contains(&parsed) {
        return Err(format!(
            "NODEWE_NODE_ONLINE_TTL_MS must be between {MIN_NODE_ONLINE_TTL_MS} and {MAX_NODE_ONLINE_TTL_MS}"
        ));
    }
    Ok(())
}

fn node_is_fresh(node: &Node) -> bool {
    node.online && !node.revoked && node.last_seen.saturating_add(node_online_ttl_ms()) >= now()
}

fn acquire_store_lock(dir: &Path) -> Result<Arc<StoreLock>, String> {
    fs::create_dir_all(dir).map_err(|error| format!("cannot create data directory: {error}"))?;
    restrict_directory(dir);
    let path = dir.join("store.lock");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                format!(
                    "NodeWe data directory is already locked: {}; use a shared transactional database for HA",
                    path.display()
                )
            } else {
                format!("cannot create store lock {}: {error}", path.display())
            }
        })?;
    file.write_all(format!("pid={}\nstarted_ms={}\n", std::process::id(), now()).as_bytes())
        .map_err(|error| format!("cannot write store lock: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync store lock: {error}"))?;
    restrict_file(&path);
    Ok(Arc::new(StoreLock { path }))
}

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|argument| argument == "--version" || argument == "-V")
    {
        println!("node-control-plane {VERSION}");
        return;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        println!("NodeWe Control Plane {VERSION}\n\nEnvironment: NODEWE_ADMIN_TOKEN, NODEWE_GRANT_SECRET, NODEWE_DATA_DIR, NODEWE_STORAGE_BACKEND(snapshot|sqlite), NODEWE_BIND\nOIDC: NODEWE_OIDC_REQUIRED, NODEWE_OIDC_ISSUER, NODEWE_OIDC_AUDIENCE, NODEWE_OIDC_HS256_SECRET_FILE\nTLS/mTLS: NODEWE_TLS_CERT, NODEWE_TLS_KEY, NODEWE_TLS_CLIENT_CA");
        return;
    }
    enforce_production_mode().expect("production configuration is incomplete");
    validate_node_online_ttl().expect("invalid NODEWE_NODE_ONLINE_TTL_MS");
    let bind = env::var("NODEWE_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    ensure_bind_safe(&bind)
        .expect("NODEWE_BIND must be loopback unless private bind is explicitly enabled");
    let token = load_secret_value("NODEWE_ADMIN_TOKEN", "NODEWE_ADMIN_TOKEN_FILE")
        .expect("invalid NODEWE_ADMIN_TOKEN_FILE")
        .expect("NODEWE_ADMIN_TOKEN or NODEWE_ADMIN_TOKEN_FILE must be set");
    let grant_secret = load_secret_value("NODEWE_GRANT_SECRET", "NODEWE_GRANT_SECRET_FILE")
        .expect("invalid NODEWE_GRANT_SECRET_FILE")
        .expect("NODEWE_GRANT_SECRET or NODEWE_GRANT_SECRET_FILE must be set");
    let configured_signing_key =
        configured_grant_signing_key().expect("invalid NODEWE_GRANT_SIGNING_KEY");
    let verification_keys =
        configured_grant_verification_keys().expect("invalid NODEWE_GRANT_SIGNING_KEY_PREVIOUS");
    for key_bytes in &verification_keys {
        grant_key_pair(key_bytes)
            .expect("configured grant signing key is not valid Ed25519 PKCS#8");
    }
    if configured_signing_key.is_none() && !verification_keys.is_empty() {
        panic!("NODEWE_GRANT_SIGNING_KEY is required when a previous signing key is configured");
    }
    if env::var("NODEWE_REQUIRE_SIGNED_GRANTS").as_deref() == Ok("1")
        && configured_signing_key.is_none()
    {
        panic!("NODEWE_GRANT_SIGNING_KEY is required when signed grants are enforced");
    }
    let data_dir = PathBuf::from(
        env::var("NODEWE_DATA_DIR").unwrap_or_else(|_| ".nodewe-control-plane".into()),
    );
    let sqlite_backend = match env::var("NODEWE_STORAGE_BACKEND").as_deref() {
        Ok("sqlite") => true,
        Ok("snapshot") | Err(_) => false,
        Ok("postgres") => false,
        Ok(value) => {
            panic!("NODEWE_STORAGE_BACKEND must be snapshot, sqlite, or postgres, got {value}")
        }
    };
    let store_lock = acquire_store_lock(&data_dir).expect("cannot acquire NodeWe store lock");
    let policy = load_policy().expect("invalid NODEWE_POLICY_FILE");
    let oidc = load_oidc_config().expect("invalid NODEWE_OIDC configuration");
    let sqlite_path = data_dir.join("nodewe.sqlite3");
    let postgres_backend = env::var("NODEWE_STORAGE_BACKEND").as_deref() == Ok("postgres");
    let postgres_url = if postgres_backend {
        Some(
            env::var("NODEWE_DATABASE_URL")
                .expect("NODEWE_DATABASE_URL is required for postgres backend"),
        )
    } else {
        None
    };
    if sqlite_backend {
        validate_sqlite_startup(&sqlite_path).expect("invalid or unavailable SQLite store");
    } else if !postgres_backend {
        validate_store_startup(&data_dir).expect("invalid or unavailable NodeWe store");
    }
    let store = if sqlite_backend {
        load_sqlite_store(&sqlite_path)
    } else if let Some(url) = postgres_url.as_deref() {
        load_postgres_store(url).expect("cannot load PostgreSQL store")
    } else {
        load_store(&data_dir)
    };
    let listener = TcpListener::bind(&bind).expect("NODEWE_BIND must be host:port");
    let tls = load_tls_config().expect("invalid NODEWE TLS configuration");
    let state = State {
        admin_token: token,
        grant_secret,
        store: Arc::new(Mutex::new(store)),
        require_approval_records: env::var("NODEWE_REQUIRE_APPROVAL_RECORDS").as_deref() == Ok("1"),
        policy,
        oidc,
        active_connections: Arc::new(AtomicU64::new(0)),
        _store_lock: Some(store_lock),
        backend: if sqlite_backend {
            Arc::new(SqliteBackend { path: sqlite_path })
        } else if let Some(url) = postgres_url {
            Arc::new(PostgresBackend { url })
        } else {
            Arc::new(SnapshotBackend {
                data_dir: Some(data_dir.clone()),
            })
        },
    };
    println!(
        "NodeWe Control Plane listening on {}://{bind}",
        if tls.is_some() { "https" } else { "http" }
    );
    for stream in listener.incoming().flatten() {
        if configure_connection(&stream).is_err() {
            continue;
        }
        let active = state.active_connections.fetch_add(1, Ordering::AcqRel) + 1;
        if active > MAX_CONNECTIONS {
            state.active_connections.fetch_sub(1, Ordering::AcqRel);
            drop(stream);
            continue;
        }
        let state = state.clone();
        if let Some(config) = tls.clone() {
            thread::spawn(move || {
                let _guard = ConnectionGuard {
                    active: state.active_connections.clone(),
                };
                let Ok(connection) = ServerConnection::new(config) else {
                    return;
                };
                let mut stream = StreamOwned::new(connection, stream);
                let _ = handle(&mut stream, &state);
                // Rustls clients must receive a close_notify before the
                // short-lived HTTP connection is dropped; otherwise a clean
                // response is reported as an unexpected EOF.
                stream.conn.send_close_notify();
                let _ = stream.flush();
            });
        } else {
            thread::spawn(move || {
                let _guard = ConnectionGuard {
                    active: state.active_connections.clone(),
                };
                let mut stream = stream;
                let _ = handle(&mut stream, &state);
            });
        }
    }
}

fn configure_connection(stream: &TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    Ok(())
}

fn load_tls_config() -> Result<Option<Arc<ServerConfig>>, String> {
    let certificate = env::var_os("NODEWE_TLS_CERT");
    let private_key = env::var_os("NODEWE_TLS_KEY");
    let client_ca = env::var_os("NODEWE_TLS_CLIENT_CA");
    if certificate.is_none() && private_key.is_none() && client_ca.is_none() {
        return Ok(None);
    }
    let certificate = certificate.ok_or("NODEWE_TLS_CERT is required when TLS is enabled")?;
    let private_key = private_key.ok_or("NODEWE_TLS_KEY is required when TLS is enabled")?;
    let client_ca = client_ca.ok_or("NODEWE_TLS_CLIENT_CA is required for mTLS")?;
    let certificates = CertificateDer::pem_file_iter(&certificate)
        .map_err(|error| format!("cannot read NODEWE_TLS_CERT: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot parse NODEWE_TLS_CERT: {error}"))?;
    if certificates.is_empty() {
        return Err("NODEWE_TLS_CERT contains no certificates".into());
    }
    let key = PrivateKeyDer::from_pem_file(&private_key)
        .map_err(|error| format!("cannot parse NODEWE_TLS_KEY: {error}"))?;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(&client_ca)
        .map_err(|error| format!("cannot read NODEWE_TLS_CLIENT_CA: {error}"))?
    {
        roots
            .add(
                certificate
                    .map_err(|error| format!("cannot parse NODEWE_TLS_CLIENT_CA: {error}"))?,
            )
            .map_err(|error| format!("invalid client CA certificate: {error}"))?;
    }
    if roots.is_empty() {
        return Err("NODEWE_TLS_CLIENT_CA contains no certificates".into());
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| format!("cannot build mTLS verifier: {error}"))?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)
        .map_err(|error| format!("cannot build TLS server config: {error}"))?;
    Ok(Some(Arc::new(config)))
}

fn load_policy() -> Result<Policy, String> {
    let Some(path) = env::var_os("NODEWE_POLICY_FILE") else {
        return Ok(Policy::default());
    };
    let path = PathBuf::from(path);
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read NODEWE_POLICY_FILE {}: {error}", path.display()))?;
    if contents.len() > 64 * 1024 {
        return Err("NODEWE_POLICY_FILE is larger than 64 KiB".into());
    }
    let mut policy = Policy::default();
    for (line_number, raw_line) in contents.lines().enumerate() {
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(value, _)| value)
            .trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid policy line {}", line_number + 1))?;
        let values = parse_policy_values(value)
            .ok_or_else(|| format!("empty policy value on line {}", line_number + 1))?;
        match key.trim() {
            "allowed_abilities" => {
                for ability in &values {
                    if !SUPPORTED_ABILITIES.contains(&ability.as_str()) {
                        return Err(format!("unsupported policy ability: {ability}"));
                    }
                }
                policy.allowed_abilities = values;
            }
            "approval_required" => {
                for ability in &values {
                    if !SUPPORTED_ABILITIES.contains(&ability.as_str()) {
                        return Err(format!("unsupported approval ability: {ability}"));
                    }
                }
                policy.approval_required = values;
            }
            "allowed_data_classes" => policy.allowed_data_classes = values,
            "allowed_actors" => policy.allowed_actors = values,
            "allowed_commands" => {
                if values.iter().any(|command| !valid_command_name(command)) {
                    return Err("allowed_commands contains an unsafe command name".into());
                }
                policy.allowed_commands = values;
            }
            "allowed_paths" => {
                if values.iter().any(|path| !valid_relative_path(path)) {
                    return Err("allowed_paths contains an unsafe relative path".into());
                }
                policy.allowed_paths = values;
            }
            other => return Err(format!("unknown policy key: {other}")),
        }
    }
    if policy.allowed_abilities.is_empty() {
        return Err("allowed_abilities cannot be empty".into());
    }
    Ok(policy)
}

fn parse_policy_values(value: &str) -> Option<Vec<String>> {
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    (!values.is_empty()).then_some(values)
}

/// Load the local OIDC verification profile. The control plane intentionally
/// does not fetch discovery metadata or keys at request time: deployments
/// provision a short-lived HS256 verification secret through their identity
/// gateway/secret manager and pin the issuer and audience here. This keeps
/// authorization deterministic and fail-closed when the IdP is unavailable.
fn load_oidc_config() -> Result<Option<OidcConfig>, String> {
    let issuer = env::var("NODEWE_OIDC_ISSUER").unwrap_or_default();
    let audience = env::var("NODEWE_OIDC_AUDIENCE").unwrap_or_default();
    let secret = load_secret_value("NODEWE_OIDC_HS256_SECRET", "NODEWE_OIDC_HS256_SECRET_FILE")?;
    let required = env::var("NODEWE_OIDC_REQUIRED").as_deref() == Ok("1");
    let any_config = !issuer.is_empty() || !audience.is_empty() || secret.is_some();
    if !any_config {
        if required {
            return Err(
                "NODEWE_OIDC_REQUIRED=1 needs NODEWE_OIDC_ISSUER, NODEWE_OIDC_AUDIENCE and NODEWE_OIDC_HS256_SECRET"
                    .into(),
            );
        }
        return Ok(None);
    }
    if issuer.is_empty() || audience.is_empty() {
        return Err("NODEWE_OIDC_ISSUER and NODEWE_OIDC_AUDIENCE are required together".into());
    }
    if !issuer.starts_with("https://") {
        return Err("NODEWE_OIDC_ISSUER must use https://".into());
    }
    let hmac_secret =
        secret.ok_or("NODEWE_OIDC_HS256_SECRET or NODEWE_OIDC_HS256_SECRET_FILE is required")?;
    if hmac_secret.len() < 32 {
        return Err("NODEWE_OIDC_HS256_SECRET must contain at least 32 bytes".into());
    }
    let admin_group = env::var("NODEWE_OIDC_ADMIN_GROUP").unwrap_or_else(|_| "nodewe-admin".into());
    let group_claim = env::var("NODEWE_OIDC_GROUP_CLAIM").unwrap_or_else(|_| "groups".into());
    if !valid_claim_name(&group_claim) || !valid_claim_name(&admin_group) {
        return Err(
            "NODEWE_OIDC_ADMIN_GROUP and NODEWE_OIDC_GROUP_CLAIM must be safe claim names".into(),
        );
    }
    Ok(Some(OidcConfig {
        issuer,
        audience,
        hmac_secret: hmac_secret.into_bytes(),
        admin_group,
        group_claim,
    }))
}

fn valid_claim_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_command_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with(['/', '\\'])
        && !value.contains('\0')
        && value
            .split(['/', '\\'])
            .all(|segment| !segment.is_empty() && segment != "..")
}

fn policy_allows_path(path: &str, allowed_paths: &[String]) -> bool {
    if allowed_paths.is_empty() {
        return true;
    }
    if !valid_relative_path(path) {
        return false;
    }
    let normalized = path.strip_prefix("./").unwrap_or(path);
    allowed_paths.iter().any(|allowed| {
        let allowed = allowed.strip_prefix("./").unwrap_or(allowed);
        normalized == allowed
            || normalized
                .strip_prefix(allowed)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn handle<S: Read + Write>(mut stream: &mut S, state: &State) -> std::io::Result<()> {
    const MAX_REQUEST_BYTES: usize = 64 * 1024;
    let mut request = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break None;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > MAX_REQUEST_BYTES {
            break Some(usize::MAX);
        }
        if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break Some(index);
        }
    };
    let Some(header_end) = header_end else {
        write_response(
            &mut stream,
            "400 Bad Request",
            "{\"code\":\"malformed_request\"}",
        )?;
        return Ok(());
    };
    if header_end == usize::MAX {
        write_response(
            &mut stream,
            "413 Payload Too Large",
            "{\"code\":\"request_too_large\"}",
        )?;
        return Ok(());
    }
    let header = match std::str::from_utf8(&request[..header_end]) {
        Ok(header) => header.to_owned(),
        Err(_) => {
            write_response(
                &mut stream,
                "400 Bad Request",
                "{\"code\":\"invalid_headers\"}",
            )?;
            return Ok(());
        }
    };
    let content_length = match request_content_length(&header) {
        Ok(content_length) => content_length,
        Err(code) => {
            write_response(
                &mut stream,
                "400 Bad Request",
                &format!("{{\"code\":\"{code}\"}}"),
            )?;
            return Ok(());
        }
    };
    let total = header_end + 4 + content_length;
    if total > MAX_REQUEST_BYTES {
        write_response(
            &mut stream,
            "413 Payload Too Large",
            "{\"code\":\"request_too_large\"}",
        )?;
        return Ok(());
    }
    while request.len() < total {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            write_response(
                &mut stream,
                "400 Bad Request",
                "{\"code\":\"truncated_request\"}",
            )?;
            return Ok(());
        }
        request.extend_from_slice(&chunk[..read]);
    }
    let request = String::from_utf8_lossy(&request[..total]);
    let mut parts = request.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    let presented = request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.trim().eq_ignore_ascii_case("authorization"))
                .then(|| value.trim().strip_prefix("Bearer ").map(str::trim))
                .flatten()
        })
        .unwrap_or("");
    let auth = authenticate_request(state, path, body, presented);
    if method == "GET"
        && websocket_path(path)
        && has_header(&header, "upgrade", "websocket")
        && has_header_token(&header, "connection", "upgrade")
    {
        // The persistent Agent channel is reserved for a Node Credential;
        // administrator bearer tokens must use the control-plane API routes.
        if !auth.node || auth.admin {
            write_response(
                &mut stream,
                "401 Unauthorized",
                "{\"code\":\"unauthenticated\"}",
            )?;
            return Ok(());
        }
        return handle_websocket(&mut stream, state, &header, path, presented);
    }
    let (status, response) = route_with_actor(
        method,
        path,
        body,
        auth.authorized,
        auth.admin,
        auth.actor.as_deref(),
        state,
    );
    write_response(&mut stream, status, &response)
}

fn request_content_length(header: &str) -> Result<usize, &'static str> {
    let mut content_length = None;
    for line in header.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or("malformed_header")?;
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err("malformed_header");
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("unsupported_transfer_encoding");
        }
        if name.eq_ignore_ascii_case("content-length") {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("invalid_content_length");
            }
            let parsed = value
                .parse::<usize>()
                .map_err(|_| "invalid_content_length")?;
            if content_length.is_some_and(|previous| previous != parsed) {
                return Err("conflicting_content_length");
            }
            content_length = Some(parsed);
        }
    }
    Ok(content_length.unwrap_or(0))
}

fn write_response<S: Write>(stream: &mut S, status: &str, response: &str) -> std::io::Result<()> {
    let content_type = if response.starts_with("<!doctype html>") {
        "text/html; charset=utf-8"
    } else {
        "application/json; charset=utf-8"
    };
    let header = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'\r\nConnection: close\r\n\r\n", response.len());
    stream.write_all(header.as_bytes())?;
    stream.write_all(response.as_bytes())
}

fn authenticate_request(state: &State, path: &str, body: &str, presented: &str) -> AuthContext {
    if constant_time_eq(presented, &state.admin_token) {
        return AuthContext {
            authorized: true,
            admin: true,
            node: false,
            actor: Some("admin".into()),
        };
    }
    if credential_authorized(&state.store, path, body, presented) {
        return AuthContext {
            authorized: true,
            admin: false,
            node: true,
            actor: None,
        };
    }
    let Some(config) = state.oidc.as_ref() else {
        return AuthContext::default();
    };
    let Some(claims) = validate_oidc_token(presented, config) else {
        return AuthContext::default();
    };
    AuthContext {
        authorized: true,
        admin: claims
            .groups
            .iter()
            .any(|group| group == &config.admin_group),
        node: false,
        actor: Some(claims.subject),
    }
}

struct OidcClaims {
    subject: String,
    groups: Vec<String>,
}

fn validate_oidc_token(token: &str, config: &OidcConfig) -> Option<OidcClaims> {
    let mut pieces = token.split('.');
    let (Some(header_part), Some(payload_part), Some(signature_part), None) =
        (pieces.next(), pieces.next(), pieces.next(), pieces.next())
    else {
        return None;
    };
    let header = String::from_utf8(base64url_decode(header_part)?).ok()?;
    if json_field(&header, "alg").as_deref() != Some("HS256") {
        return None;
    }
    if json_field(&header, "typ").as_deref() != Some("JWT") {
        return None;
    }
    let signature = base64url_decode(signature_part)?;
    if signature.len() != 32
        || !constant_time_eq_bytes(
            &signature,
            &hmac_sha256(
                &config.hmac_secret,
                format!("{header_part}.{payload_part}").as_bytes(),
            ),
        )
    {
        return None;
    }
    let payload = String::from_utf8(base64url_decode(payload_part)?).ok()?;
    if json_field(&payload, "iss").as_deref() != Some(config.issuer.as_str())
        || !jwt_audience_matches(&payload, &config.audience)
    {
        return None;
    }
    let now_seconds = now() / 1_000;
    let expires_at = json_number(&payload, "exp")?;
    if expires_at <= now_seconds {
        return None;
    }
    if let Some(not_before) = json_number(&payload, "nbf") {
        if not_before > now_seconds.saturating_add(30) {
            return None;
        }
    }
    let subject = json_field(&payload, "sub")?;
    if !valid_actor_id(&subject) {
        return None;
    }
    let groups = json_string_array(&payload, &config.group_claim);
    Some(OidcClaims { subject, groups })
}

fn valid_actor_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@' | b'|' | b'+')
        })
}

fn jwt_audience_matches(payload: &str, audience: &str) -> bool {
    if json_field(payload, "aud").as_deref() == Some(audience) {
        return true;
    }
    json_string_array(payload, "aud")
        .iter()
        .any(|value| value == audience)
}

fn json_string_array(body: &str, key: &str) -> Vec<String> {
    parse_json_object(body)
        .and_then(|object| object.get(key).cloned())
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect()
}

fn has_header(header: &str, name: &str, expected: &str) -> bool {
    header.lines().any(|line| {
        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        key.trim().eq_ignore_ascii_case(name) && value.trim().eq_ignore_ascii_case(expected)
    })
}

fn has_header_token(header: &str, name: &str, expected: &str) -> bool {
    header.lines().any(|line| {
        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        key.trim().eq_ignore_ascii_case(name)
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
    })
}

fn websocket_path(path: &str) -> bool {
    path.split_once('?')
        .map_or(path == "/v1/agent/ws", |(path, _)| path == "/v1/agent/ws")
}

fn header_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn handle_websocket<S: Read + Write>(
    stream: &mut S,
    state: &State,
    header: &str,
    path: &str,
    presented: &str,
) -> io::Result<()> {
    let Some(key) = header_value(header, "sec-websocket-key") else {
        write_response(
            stream,
            "400 Bad Request",
            "{\"code\":\"websocket_key_required\"}",
        )?;
        return Ok(());
    };
    if key.len() != 24 || !key.bytes().all(|byte| byte.is_ascii_graphic()) {
        write_response(
            stream,
            "400 Bad Request",
            "{\"code\":\"invalid_websocket_key\"}",
        )?;
        return Ok(());
    }
    let Some(node_id) = query_field(path, "node_id") else {
        write_response(stream, "400 Bad Request", "{\"code\":\"node_id_required\"}")?;
        return Ok(());
    };
    if !valid_node_id(&node_id) {
        write_response(stream, "400 Bad Request", "{\"code\":\"invalid_node\"}")?;
        return Ok(());
    }
    let accept = websocket_accept(key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    while let Some((opcode, payload)) = websocket_read_frame(stream)? {
        match opcode {
            0x1 => {
                let message = String::from_utf8(payload).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "websocket payload is not UTF-8")
                })?;
                let response = websocket_message(&message, &node_id, presented, state);
                websocket_write_frame(stream, 0x1, response.as_bytes())?;
            }
            0x8 => {
                websocket_write_frame(stream, 0x8, &[])?;
                break;
            }
            0x9 => websocket_write_frame(stream, 0xA, &payload)?,
            0xA => {}
            _ => {
                let close = 1002_u16.to_be_bytes();
                websocket_write_frame(stream, 0x8, &close)?;
                break;
            }
        }
    }
    Ok(())
}

fn websocket_message(message: &str, expected_node: &str, presented: &str, state: &State) -> String {
    let request_id = json_field(message, "request_id").unwrap_or_else(|| new_id("request"));
    let message_type = json_field(message, "type").unwrap_or_default();
    let node_id = json_field(message, "node_id").unwrap_or_default();
    if node_id != expected_node
        || !valid_node_id(&request_id)
        || !credential_authorized(&state.store, message, message, presented)
    {
        return websocket_envelope(
            &node_id,
            &request_id,
            "error",
            "{\"code\":\"unauthenticated\"}",
        );
    }
    let (status, payload, response_type) = match message_type.as_str() {
        "heartbeat" => {
            let (status, payload) = heartbeat(message, state);
            (status, payload, "heartbeat.ack")
        }
        "tasks.request" => {
            let (status, payload) =
                agent_tasks(&format!("/v1/agent/tasks?node_id={expected_node}"), state);
            (status, payload, "tasks.available")
        }
        "task.result" => {
            let Some(task_id) = json_field(message, "task_id") else {
                return websocket_envelope(
                    expected_node,
                    &request_id,
                    "error",
                    "{\"code\":\"task_id_required\"}",
                );
            };
            let (status, payload) =
                agent_result(&format!("/v1/agent/tasks/{task_id}/result"), message, state);
            (status, payload, "task.result.ack")
        }
        _ => {
            return websocket_envelope(
                expected_node,
                &request_id,
                "error",
                "{\"code\":\"unsupported_message_type\"}",
            );
        }
    };
    let payload = if status.starts_with('2') {
        payload
    } else {
        format!(
            "{{\"code\":\"websocket_request_failed\",\"http_status\":\"{}\",\"detail\":{payload}}}",
            status.replace(' ', "_")
        )
    };
    websocket_envelope(expected_node, &request_id, response_type, &payload)
}

fn websocket_envelope(
    node_id: &str,
    request_id: &str,
    message_type: &str,
    payload: &str,
) -> String {
    format!(
        "{{\"protocol_version\":1,\"agent_version\":\"{VERSION}\",\"node_id\":\"{}\",\"request_id\":\"{}\",\"type\":\"{}\",\"payload\":{}}}",
        esc(node_id),
        esc(request_id),
        esc(message_type),
        payload
    )
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

fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.contains('=') {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        accumulator = (accumulator << 6) | digit;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1_u32 << bits).saturating_sub(1);
        }
    }
    (bits < 6).then_some(output)
}

#[cfg(test)]
fn base64url_encode(bytes: &[u8]) -> String {
    base64_encode(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn websocket_read_frame<S: Read>(stream: &mut S) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut first = [0_u8; 1];
    if stream.read(&mut first)? == 0 {
        return Ok(None);
    }
    let mut second = [0_u8; 1];
    stream.read_exact(&mut second)?;
    if first[0] & 0x80 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fragmented websocket frames are not supported",
        ));
    }
    if first[0] & 0x70 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket extensions are not negotiated",
        ));
    }
    let opcode = first[0] & 0x0F;
    let masked = second[0] & 0x80 != 0;
    if !masked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client websocket frames must be masked",
        ));
    }
    let length_code = second[0] & 0x7F;
    let length = match length_code {
        0..=125 => length_code as u64,
        126 => {
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes)?;
            u16::from_be_bytes(bytes) as u64
        }
        127 => {
            let mut bytes = [0_u8; 8];
            stream.read_exact(&mut bytes)?;
            u64::from_be_bytes(bytes)
        }
        _ => unreachable!(),
    };
    if length > 1024 * 1024 || (opcode >= 8 && length > 125) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket frame too large",
        ));
    }
    let mut mask = [0_u8; 4];
    stream.read_exact(&mut mask)?;
    let mut payload = vec![0_u8; length as usize];
    stream.read_exact(&mut payload)?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    Ok(Some((opcode, payload)))
}

fn websocket_write_frame<S: Write>(stream: &mut S, opcode: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > 1024 * 1024 || (opcode >= 8 && payload.len() > 125) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket frame too large",
        ));
    }
    let mut header = vec![0x80 | (opcode & 0x0F)];
    match payload.len() {
        0..=125 => header.push(payload.len() as u8),
        126..=65_535 => {
            header.push(126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            header.push(127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()
}

const ADMIN_UI_HTML: &str = r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NodeWe Control Plane</title><style>body{font:16px system-ui;max-width:960px;margin:2rem auto;padding:0 1rem;background:#f6f7f9;color:#17202a}button{padding:.5rem 1rem}pre{background:white;padding:1rem;border-radius:8px;overflow:auto}</style></head><body><h1>NodeWe</h1><p>Control Plane 管理台</p><button onclick="load()">刷新节点</button><pre id="out">请输入 Bearer Token 后刷新</pre><script>async function load(){const token=prompt('Admin Bearer Token');if(!token)return;const r=await fetch('/v1/nodes',{headers:{Authorization:'Bearer '+token}});document.querySelector('#out').textContent=await r.text()}</script></body></html>"#;

#[cfg(test)]
fn route(
    method: &str,
    path: &str,
    body: &str,
    authorized: bool,
    admin_authorized: bool,
    state: &State,
) -> (&'static str, String) {
    route_with_actor(
        method,
        path,
        body,
        authorized,
        admin_authorized,
        None,
        state,
    )
}

fn route_with_actor(
    method: &str,
    path: &str,
    body: &str,
    authorized: bool,
    admin_authorized: bool,
    authenticated_actor: Option<&str>,
    state: &State,
) -> (&'static str, String) {
    if path == "/health" && method == "GET" {
        return (
            "200 OK",
            "{\"status\":\"ok\",\"protocol_version\":1,\"service\":\"nodewe-control-plane\"}"
                .into(),
        );
    }
    if path == "/" && method == "GET" {
        return ("200 OK", ADMIN_UI_HTML.into());
    }
    if method == "POST" && path == "/v1/grants/redeem" {
        return redeem_grant(body, state);
    }
    if !authorized {
        return ("401 Unauthorized", "{\"code\":\"unauthenticated\"}".into());
    }
    match (method, path) {
        ("GET", "/v1/nodes") if admin_authorized => {
            let store = state.store.lock().unwrap();
            (
                "200 OK",
                format!(
                    "[{}]",
                    store
                        .nodes
                        .iter()
                        .map(node_json)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            )
        }
        ("GET", "/v1/nodes") => ("403 Forbidden", "{\"code\":\"admin_required\"}".into()),
        ("POST", "/v1/nodes") if admin_authorized => {
            create_node_as(body, state, authenticated_actor)
        }
        ("POST", "/v1/nodes") => ("403 Forbidden", "{\"code\":\"admin_required\"}".into()),
        ("POST", "/v1/grants") if admin_authorized => create_grant_as(state, authenticated_actor),
        ("POST", "/v1/grants") => ("403 Forbidden", "{\"code\":\"admin_required\"}".into()),
        ("GET", "/v1/grants") if admin_authorized => list_grants(state),
        ("GET", "/v1/grants") => ("403 Forbidden", "{\"code\":\"admin_required\"}".into()),
        _ if method == "POST"
            && path.starts_with("/v1/grants/")
            && path.ends_with("/revoke")
            && admin_authorized =>
        {
            revoke_grant_as(path, state, authenticated_actor)
        }
        _ if method == "POST" && path.starts_with("/v1/grants/") && path.ends_with("/revoke") => {
            ("403 Forbidden", "{\"code\":\"admin_required\"}".into())
        }
        ("POST", "/v1/approvals") if admin_authorized => {
            create_approval_as(body, state, authenticated_actor)
        }
        ("GET", "/v1/approvals") if admin_authorized => {
            let store = state.store.lock().unwrap();
            (
                "200 OK",
                format!(
                    "[{}]",
                    store
                        .approvals
                        .iter()
                        .map(approval_json)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            )
        }
        ("GET", "/v1/tasks") if admin_authorized => {
            let store = state.store.lock().unwrap();
            (
                "200 OK",
                format!(
                    "[{}]",
                    store
                        .tasks
                        .iter()
                        .map(task_json)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            )
        }
        ("GET", "/v1/tasks") => ("403 Forbidden", "{\"code\":\"admin_required\"}".into()),
        _ if method == "GET" && path.starts_with("/v1/tasks/") && admin_authorized => {
            get_task(path, state)
        }
        _ if method == "GET" && path.starts_with("/v1/tasks/") => {
            ("403 Forbidden", "{\"code\":\"admin_required\"}".into())
        }
        ("POST", "/v1/tasks") if admin_authorized => {
            create_task_as(body, state, authenticated_actor)
        }
        ("POST", "/v1/tasks") => ("403 Forbidden", "{\"code\":\"admin_required\"}".into()),
        _ if method == "POST" && path.starts_with("/v1/tasks/") && path.ends_with("/cancel") => {
            if admin_authorized {
                cancel_task_as(path, state, None)
            } else if let Some(actor) = authenticated_actor {
                cancel_task_as(path, state, Some(actor))
            } else {
                ("403 Forbidden", "{\"code\":\"admin_required\"}".into())
            }
        }
        ("POST", "/v1/agent/heartbeat") => heartbeat(body, state),
        _ if method == "GET" && path.starts_with("/v1/agent/tasks") => agent_tasks(path, state),
        _ if method == "POST"
            && path.starts_with("/v1/agent/tasks/")
            && path.ends_with("/result") =>
        {
            agent_result(path, body, state)
        }
        ("GET", "/v1/audit") if admin_authorized => {
            let store = state.store.lock().unwrap();
            (
                "200 OK",
                format!(
                    "[{}]",
                    store
                        .audit
                        .iter()
                        .enumerate()
                        .map(|(index, _item)| sealed_activity_json(&store.audit, index))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            )
        }
        _ if method == "GET"
            && path.split_once('?').map_or(path, |(base, _)| base) == "/v1/audit/export"
            && admin_authorized =>
        {
            export_audit(path, state)
        }
        ("GET", "/v1/audit") => ("403 Forbidden", "{\"code\":\"admin_required\"}".into()),
        _ if method == "POST"
            && path.starts_with("/v1/nodes/")
            && path.ends_with("/revoke")
            && admin_authorized =>
        {
            let id = path
                .trim_start_matches("/v1/nodes/")
                .trim_end_matches("/revoke")
                .trim_end_matches('/');
            revoke_node_as(id, state, authenticated_actor)
        }
        _ if method == "POST" && path.starts_with("/v1/nodes/") && path.ends_with("/revoke") => {
            ("403 Forbidden", "{\"code\":\"admin_required\"}".into())
        }
        _ if method == "POST"
            && path.starts_with("/v1/nodes/")
            && path.ends_with("/rotate")
            && admin_authorized =>
        {
            let id = path
                .trim_start_matches("/v1/nodes/")
                .trim_end_matches("/rotate")
                .trim_end_matches('/');
            rotate_node_as(id, state, authenticated_actor)
        }
        _ if method == "POST" && path.starts_with("/v1/nodes/") && path.ends_with("/rotate") => {
            ("403 Forbidden", "{\"code\":\"admin_required\"}".into())
        }
        _ => ("404 Not Found", "{\"code\":\"not_found\"}".into()),
    }
}

#[cfg(test)]
fn create_node(body: &str, state: &State) -> (&'static str, String) {
    create_node_as(body, state, None)
}

fn create_node_as(
    body: &str,
    state: &State,
    authenticated_actor: Option<&str>,
) -> (&'static str, String) {
    if !json_types_valid(
        body,
        &[
            "node_id",
            "name",
            "platform",
            "architecture",
            "version",
            "labels",
            "region",
            "data_class",
            "capacity",
        ],
        &[],
        &[],
    ) {
        return ("400 Bad Request", "{\"code\":\"invalid_json_type\"}".into());
    }
    let id = json_field(body, "node_id").unwrap_or_default();
    let name = json_field(body, "name").unwrap_or_else(|| id.clone());
    let metadata = node_metadata(body);
    if !valid_node_id(&id) {
        return ("400 Bad Request", "{\"code\":\"invalid_node\"}".into());
    }
    if !valid_labels(&metadata.3) {
        return ("400 Bad Request", "{\"code\":\"invalid_labels\"}".into());
    }
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    if store.nodes.iter().any(|node| node.id == id) {
        return ("409 Conflict", "{\"code\":\"node_exists\"}".into());
    }
    let Ok(credential) = random_token() else {
        return (
            "500 Internal Server Error",
            "{\"code\":\"secure_random_unavailable\"}".into(),
        );
    };
    let node = Node {
        id: id.clone(),
        name,
        online: true,
        revoked: false,
        credential: credential.clone(),
        abilities: "file.read,file.write,task.exec,system.inspect".into(),
        platform: metadata.0,
        architecture: metadata.1,
        version: metadata.2,
        labels: metadata.3,
        region: metadata.4,
        data_class: metadata.5,
        capacity: metadata.6,
        last_seen: now(),
    };
    store.nodes.push(node.clone());
    store.audit.push(Activity::with_actor(
        "node.created",
        Some(id),
        None,
        Some(audit_actor(authenticated_actor)),
    ));
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    ("201 Created", node_with_credential_json(&node, &credential))
}

#[cfg(test)]
fn create_grant(state: &State) -> (&'static str, String) {
    create_grant_as(state, None)
}

fn create_grant_as(state: &State, authenticated_actor: Option<&str>) -> (&'static str, String) {
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    let Ok(code) = random_token() else {
        return (
            "500 Internal Server Error",
            "{\"code\":\"secure_random_unavailable\"}".into(),
        );
    };
    let grant = Grant {
        code,
        expires_at: now() + 300_000,
        used: false,
        revoked: false,
        signature: String::new(),
    };
    let mut grant = grant;
    let Ok(signature) = sign_grant(&grant.code, grant.expires_at, &state.grant_secret) else {
        return (
            "500 Internal Server Error",
            "{\"code\":\"grant_signing_unavailable\"}".into(),
        );
    };
    grant.signature = signature;
    let json = format!(
        "{{\"grant_code\":\"{}\",\"grant_signature\":\"{}\",\"expires_at\":{}}}",
        esc(&grant.code),
        esc(&grant.signature),
        grant.expires_at
    );
    store.audit.push(Activity::with_actor(
        "grant.created",
        None,
        None,
        Some(audit_actor(authenticated_actor)),
    ));
    store.grants.push(grant);
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    ("201 Created", json)
}

fn list_grants(state: &State) -> (&'static str, String) {
    let store = state.store.lock().unwrap();
    (
        "200 OK",
        format!(
            "[{}]",
            store
                .grants
                .iter()
                .map(|grant| {
                    format!(
                        "{{\"grant_code\":\"{}\",\"grant_signature\":\"{}\",\"expires_at\":{},\"used\":{},\"revoked\":{}}}",
                        esc(&grant.code),
                        esc(&grant.signature),
                        grant.expires_at,
                        grant.used,
                        grant.revoked
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        ),
    )
}

fn revoke_grant_as(
    path: &str,
    state: &State,
    authenticated_actor: Option<&str>,
) -> (&'static str, String) {
    let code = path
        .trim_start_matches("/v1/grants/")
        .trim_end_matches("/revoke")
        .trim_end_matches('/');
    if !valid_node_id(code) {
        return ("400 Bad Request", "{\"code\":\"invalid_grant\"}".into());
    }
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    let Some(grant) = store.grants.iter_mut().find(|grant| grant.code == code) else {
        return ("404 Not Found", "{\"code\":\"grant_not_found\"}".into());
    };
    grant.revoked = true;
    store.audit.push(Activity::with_actor(
        "grant.revoked",
        None,
        None,
        Some(audit_actor(authenticated_actor)),
    ));
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    (
        "200 OK",
        format!("{{\"grant_code\":\"{}\",\"revoked\":true}}", esc(code)),
    )
}

fn redeem_grant(body: &str, state: &State) -> (&'static str, String) {
    if !json_types_valid(
        body,
        &[
            "grant_code",
            "grant_signature",
            "node_id",
            "name",
            "platform",
            "architecture",
            "version",
            "labels",
            "region",
            "data_class",
            "capacity",
        ],
        &[],
        &[],
    ) {
        return ("400 Bad Request", "{\"code\":\"invalid_json_type\"}".into());
    }
    let code = json_field(body, "grant_code").unwrap_or_default();
    let signature = json_field(body, "grant_signature").unwrap_or_default();
    let id = json_field(body, "node_id").unwrap_or_default();
    let name = json_field(body, "name").unwrap_or_else(|| id.clone());
    let metadata = node_metadata(body);
    if code.is_empty() || signature.is_empty() || !valid_node_id(&id) {
        return ("400 Bad Request", "{\"code\":\"invalid_grant\"}".into());
    }
    if !valid_labels(&metadata.3) {
        return ("400 Bad Request", "{\"code\":\"invalid_labels\"}".into());
    }
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    if store.nodes.iter().any(|node| node.id == id) {
        return ("409 Conflict", "{\"code\":\"node_exists\"}".into());
    }
    let Some(grant) = store.grants.iter_mut().find(|grant| {
        grant.code == code
            && constant_time_eq(&grant.signature, &signature)
            && verify_grant(
                &grant.code,
                grant.expires_at,
                &grant.signature,
                &state.grant_secret,
            )
            && !grant.used
            && !grant.revoked
            && grant.expires_at > now()
    }) else {
        return (
            "403 Forbidden",
            "{\"code\":\"grant_invalid_or_expired\"}".into(),
        );
    };
    grant.used = true;
    let Ok(credential) = random_token() else {
        return (
            "500 Internal Server Error",
            "{\"code\":\"secure_random_unavailable\"}".into(),
        );
    };
    let node = Node {
        id: id.clone(),
        name,
        online: true,
        revoked: false,
        credential: credential.clone(),
        abilities: "file.read,file.write,task.exec,system.inspect".into(),
        platform: metadata.0,
        architecture: metadata.1,
        version: metadata.2,
        labels: metadata.3,
        region: metadata.4,
        data_class: metadata.5,
        capacity: metadata.6,
        last_seen: now(),
    };
    store.nodes.push(node.clone());
    store.audit.push(Activity::with_actor(
        "grant.redeemed",
        Some(id.clone()),
        None,
        Some(id),
    ));
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    (
        "201 Created",
        node_with_credential_json(&node, &credential).to_string(),
    )
}

#[cfg(test)]
fn revoke_node(id: &str, state: &State) -> (&'static str, String) {
    revoke_node_as(id, state, None)
}

fn revoke_node_as(
    id: &str,
    state: &State,
    authenticated_actor: Option<&str>,
) -> (&'static str, String) {
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    let Some(node) = store.nodes.iter_mut().find(|node| node.id == id) else {
        return ("404 Not Found", "{\"code\":\"node_not_found\"}".into());
    };
    node.revoked = true;
    node.online = false;
    let json = node_json(node);
    let cancelled = store
        .tasks
        .iter_mut()
        .filter(|task| task.node_id == id && matches!(task.state.as_str(), "queued" | "dispatched"))
        .map(|task| {
            task.state = "cancelled".into();
            task.lease_until = 0;
            task.id.clone()
        })
        .collect::<Vec<_>>();
    store.audit.push(Activity::with_actor(
        "node.revoked",
        Some(id.into()),
        None,
        Some(audit_actor(authenticated_actor)),
    ));
    for task_id in cancelled {
        store.audit.push(Activity::with_actor(
            "task.cancelled_by_node_revoke",
            Some(id.into()),
            Some(task_id),
            Some(audit_actor(authenticated_actor)),
        ));
    }
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    ("200 OK", json)
}

#[cfg(test)]
fn rotate_node(id: &str, state: &State) -> (&'static str, String) {
    rotate_node_as(id, state, None)
}

fn rotate_node_as(
    id: &str,
    state: &State,
    authenticated_actor: Option<&str>,
) -> (&'static str, String) {
    let Ok(credential) = random_token() else {
        return (
            "500 Internal Server Error",
            "{\"code\":\"secure_random_unavailable\"}".into(),
        );
    };
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    let Some(node) = store.nodes.iter_mut().find(|node| node.id == id) else {
        return ("404 Not Found", "{\"code\":\"node_not_found\"}".into());
    };
    if node.revoked {
        return ("403 Forbidden", "{\"code\":\"node_revoked\"}".into());
    }
    node.credential = credential.clone();
    let json = node_with_credential_json(node, &credential);
    store.audit.push(Activity::with_actor(
        "node.credential_rotated",
        Some(id.into()),
        None,
        Some(audit_actor(authenticated_actor)),
    ));
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    ("200 OK", json)
}

fn audit_actor(authenticated_actor: Option<&str>) -> String {
    authenticated_actor.unwrap_or("admin").to_owned()
}

fn resolve_actor(body: &str, authenticated_actor: Option<&str>) -> Option<String> {
    let requested = json_field(body, "actor");
    match (authenticated_actor, requested) {
        (Some(authenticated), Some(requested)) if authenticated != requested => None,
        (Some(authenticated), _) => Some(authenticated.to_owned()),
        (None, Some(requested)) => Some(requested),
        (None, None) => Some("admin".into()),
    }
}

#[cfg(test)]
fn create_approval(body: &str, state: &State) -> (&'static str, String) {
    create_approval_as(body, state, None)
}

fn create_approval_as(
    body: &str,
    state: &State,
    authenticated_actor: Option<&str>,
) -> (&'static str, String) {
    if !json_types_valid(
        body,
        &["node_id", "ability", "program", "argument", "actor"],
        &[],
        &[],
    ) {
        return ("400 Bad Request", "{\"code\":\"invalid_json_type\"}".into());
    }
    let node_id = json_field(body, "node_id").unwrap_or_default();
    let ability = json_field(body, "ability").unwrap_or_default();
    let program = json_field(body, "program").unwrap_or_else(|| "echo".into());
    let argument = json_field(body, "argument").unwrap_or_default();
    let Some(actor) = resolve_actor(body, authenticated_actor) else {
        return ("403 Forbidden", "{\"code\":\"actor_mismatch\"}".into());
    };
    if node_id.is_empty()
        || ability != "task.exec"
        || !valid_node_id(&node_id)
        || !valid_actor_id(&actor)
    {
        return ("400 Bad Request", "{\"code\":\"invalid_approval\"}".into());
    }
    let approval = Approval {
        id: new_id("approval"),
        node_id,
        ability,
        program,
        argument,
        actor,
        expires_at: now() + 300_000,
        used: false,
    };
    let json = approval_json(&approval);
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    store.audit.push(Activity::with_actor(
        "approval.created",
        Some(approval.node_id.clone()),
        Some(approval.id.clone()),
        Some(audit_actor(authenticated_actor)),
    ));
    store.approvals.push(approval);
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    ("201 Created", json)
}

#[cfg(test)]
fn create_task(body: &str, state: &State) -> (&'static str, String) {
    create_task_as(body, state, None)
}

fn create_task_as(
    body: &str,
    state: &State,
    authenticated_actor: Option<&str>,
) -> (&'static str, String) {
    if !json_types_valid(
        body,
        &[
            "node_id",
            "request_id",
            "actor",
            "ability",
            "idempotency_key",
            "program",
            "argument",
            "approval_id",
        ],
        &["timeout_ms", "output_limit"],
        &["approved"],
    ) {
        return ("400 Bad Request", "{\"code\":\"invalid_json_type\"}".into());
    }
    let node_id = json_field(body, "node_id").unwrap_or_default();
    let request_id = json_field(body, "request_id").unwrap_or_else(|| new_id("request"));
    let Some(actor) = resolve_actor(body, authenticated_actor) else {
        return ("403 Forbidden", "{\"code\":\"actor_mismatch\"}".into());
    };
    let ability = json_field(body, "ability").unwrap_or_default();
    let idempotency_key = json_field(body, "idempotency_key").unwrap_or_default();
    let program = json_field(body, "program").unwrap_or_else(|| "echo".into());
    let argument = json_field(body, "argument").unwrap_or_default();
    let approval_id = json_field(body, "approval_id");
    let timeout_ms = if json_key_present(body, "timeout_ms") {
        json_number(body, "timeout_ms").ok_or("invalid_timeout")
    } else {
        Ok(DEFAULT_TASK_TIMEOUT_MS)
    };
    let timeout_ms = match timeout_ms {
        Ok(value) => value,
        Err(_) => return ("400 Bad Request", "{\"code\":\"invalid_timeout\"}".into()),
    };
    let output_limit = if json_key_present(body, "output_limit") {
        json_number(body, "output_limit").ok_or("invalid_output_limit")
    } else {
        Ok(MAX_TASK_OUTPUT_LIMIT as u64)
    };
    let output_limit = match output_limit {
        Ok(value) if value > 0 && value <= MAX_TASK_OUTPUT_LIMIT as u64 => value as usize,
        _ => {
            return (
                "400 Bad Request",
                "{\"code\":\"invalid_output_limit\"}".into(),
            )
        }
    };
    if !valid_node_id(&request_id) {
        return (
            "400 Bad Request",
            "{\"code\":\"invalid_request_id\"}".into(),
        );
    }
    if !valid_node_id(&actor) {
        return ("400 Bad Request", "{\"code\":\"invalid_actor\"}".into());
    }
    if timeout_ms == 0 || timeout_ms > MAX_TASK_TIMEOUT_MS {
        return ("400 Bad Request", "{\"code\":\"invalid_timeout\"}".into());
    }
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    if !idempotency_key.is_empty() {
        if let Some(existing) = store
            .tasks
            .iter()
            .find(|task| task.idempotency_key == idempotency_key)
        {
            if existing.node_id == node_id
                && existing.actor == actor
                && existing.ability == ability
                && existing.program == program
                && existing.argument == argument
                && existing.timeout_ms == timeout_ms
            {
                return ("200 OK", task_json(existing));
            }
            return ("409 Conflict", "{\"code\":\"idempotency_conflict\"}".into());
        }
    }
    if !store
        .nodes
        .iter()
        .any(|node| node.id == node_id && node_is_fresh(node))
    {
        return ("409 Conflict", "{\"code\":\"node_unavailable\"}".into());
    }
    if !matches!(
        ability.as_str(),
        "file.read" | "file.write" | "task.exec" | "system.inspect"
    ) {
        return ("403 Forbidden", "{\"code\":\"forbidden\"}".into());
    }
    if !state
        .policy
        .allowed_abilities
        .iter()
        .any(|allowed| allowed == &ability)
    {
        return ("403 Forbidden", "{\"code\":\"policy_denied\"}".into());
    }
    if !state.policy.allowed_actors.is_empty()
        && !state
            .policy
            .allowed_actors
            .iter()
            .any(|allowed| allowed == &actor)
    {
        return ("403 Forbidden", "{\"code\":\"policy_denied\"}".into());
    }
    if ability == "task.exec"
        && !state.policy.allowed_commands.is_empty()
        && !state
            .policy
            .allowed_commands
            .iter()
            .any(|allowed| allowed == &program)
    {
        return ("403 Forbidden", "{\"code\":\"policy_denied\"}".into());
    }
    if matches!(ability.as_str(), "file.read" | "file.write")
        && !policy_allows_path(&program, &state.policy.allowed_paths)
    {
        return ("403 Forbidden", "{\"code\":\"policy_denied\"}".into());
    }
    if let Some(node) = store.nodes.iter().find(|node| node.id == node_id) {
        if !state.policy.allowed_data_classes.is_empty()
            && !state
                .policy
                .allowed_data_classes
                .iter()
                .any(|allowed| allowed == &node.data_class)
        {
            return ("403 Forbidden", "{\"code\":\"policy_denied\"}".into());
        }
    }
    if !store.nodes.iter().any(|node| {
        node.id == node_id
            && node
                .abilities
                .split(',')
                .any(|supported| supported == ability)
    }) {
        return ("403 Forbidden", "{\"code\":\"ability_unavailable\"}".into());
    }
    if ability == "task.exec"
        || state
            .policy
            .approval_required
            .iter()
            .any(|item| item == &ability)
    {
        if state.require_approval_records {
            let Some(approval_id) = approval_id else {
                return (
                    "428 Precondition Required",
                    "{\"code\":\"approval_required\"}".into(),
                );
            };
            {
                let Some(approval) = store.approvals.iter_mut().find(|approval| {
                    approval.id == approval_id
                        && approval.node_id == node_id
                        && approval.ability == ability
                        && approval.program == program
                        && approval.argument == argument
                        && approval.actor == actor
                        && !approval.used
                        && approval.expires_at > now()
                }) else {
                    return ("403 Forbidden", "{\"code\":\"approval_invalid\"}".into());
                };
                approval.used = true;
            }
            store.audit.push(Activity::with_actor(
                "approval.consumed",
                Some(node_id.clone()),
                Some(approval_id),
                Some(actor.clone()),
            ));
        } else if !json_true(body, "approved") {
            return (
                "428 Precondition Required",
                "{\"code\":\"approval_required\"}".into(),
            );
        }
    }
    let task = Task {
        id: new_id("task"),
        request_id,
        actor,
        node_id: node_id.clone(),
        ability,
        state: "queued".into(),
        idempotency_key,
        program,
        argument,
        output: String::new(),
        output_sha256: String::new(),
        output_truncated: false,
        output_limit,
        exit_code: None,
        lease_until: 0,
        lease_token: String::new(),
        timeout_ms,
    };
    let json = task_json(&task);
    store.audit.push(Activity::with_actor(
        "task.accepted",
        Some(node_id),
        Some(task.id.clone()),
        Some(task.actor.clone()),
    ));
    store.audit.push(Activity::with_actor(
        "policy.allowed",
        Some(task.node_id.clone()),
        Some(task.id.clone()),
        Some(task.actor.clone()),
    ));
    store.tasks.push(task);
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    ("202 Accepted", json)
}

fn get_task(path: &str, state: &State) -> (&'static str, String) {
    let task_id = path.trim_start_matches("/v1/tasks/").trim_end_matches('/');
    let store = state.store.lock().unwrap();
    let Some(task) = store.tasks.iter().find(|task| task.id == task_id) else {
        return ("404 Not Found", "{\"code\":\"task_not_found\"}".into());
    };
    ("200 OK", task_json(task))
}

#[cfg(test)]
fn cancel_task(path: &str, state: &State) -> (&'static str, String) {
    cancel_task_as(path, state, None)
}

fn cancel_task_as(
    path: &str,
    state: &State,
    authenticated_actor: Option<&str>,
) -> (&'static str, String) {
    let task_id = path
        .trim_start_matches("/v1/tasks/")
        .trim_end_matches("/cancel")
        .trim_end_matches('/');
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    let (json, node_id) = {
        let Some(task) = store.tasks.iter_mut().find(|task| task.id == task_id) else {
            return ("404 Not Found", "{\"code\":\"task_not_found\"}".into());
        };
        if let Some(actor) = authenticated_actor {
            if task.actor != actor {
                return ("403 Forbidden", "{\"code\":\"actor_forbidden\"}".into());
            }
        }
        if matches!(
            task.state.as_str(),
            "succeeded" | "failed" | "cancelled" | "timed_out"
        ) {
            return ("409 Conflict", "{\"code\":\"task_terminal\"}".into());
        }
        task.state = "cancelled".into();
        task.lease_until = 0;
        (task_json(task), task.node_id.clone())
    };
    store.audit.push(Activity::with_actor(
        "task.cancelled",
        Some(node_id),
        Some(task_id.into()),
        Some(audit_actor(authenticated_actor)),
    ));
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    ("200 OK", json)
}

fn heartbeat(body: &str, state: &State) -> (&'static str, String) {
    let Some(object) = parse_json_object(body) else {
        return ("400 Bad Request", "{\"code\":\"malformed_request\"}".into());
    };
    // Heartbeats are authenticated with a Node Credential, so every optional
    // field must have the expected JSON type. Silently ignoring a wrong type
    // would let an agent appear healthy while bypassing negotiation checks.
    if object
        .get("protocol_version")
        .is_some_and(|value| value.as_u64().is_none())
        || [
            "node_id",
            "abilities",
            "platform",
            "architecture",
            "version",
        ]
        .iter()
        .any(|key| object.get(*key).is_some_and(|value| !value.is_string()))
    {
        return ("400 Bad Request", "{\"code\":\"invalid_json_type\"}".into());
    }
    let node_id = json_field(body, "node_id").unwrap_or_default();
    if node_id.is_empty() {
        return ("400 Bad Request", "{\"code\":\"invalid_node\"}".into());
    }
    if let Some(protocol_version) = json_number(body, "protocol_version") {
        if protocol_version != PROTOCOL_VERSION as u64 {
            return (
                "426 Upgrade Required",
                "{\"code\":\"unsupported_protocol_version\",\"protocol_version\":1}".into(),
            );
        }
    }
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    let Some(node) = store.nodes.iter_mut().find(|node| node.id == node_id) else {
        return ("404 Not Found", "{\"code\":\"node_not_found\"}".into());
    };
    if node.revoked {
        return ("403 Forbidden", "{\"code\":\"node_revoked\"}".into());
    }
    // Scheduling metadata is administrator-owned. A Node Credential must not
    // be able to relabel itself into a privileged data class or group.
    if ["labels", "region", "data_class", "capacity"]
        .iter()
        .any(|key| object.get(*key).is_some())
    {
        return (
            "400 Bad Request",
            "{\"code\":\"immutable_node_metadata\"}".into(),
        );
    }
    node.online = true;
    node.last_seen = now();
    if let Some(abilities) = json_field(body, "abilities") {
        let Ok(negotiated) = normalize_abilities(&abilities) else {
            return (
                "422 Unprocessable Entity",
                "{\"code\":\"unsupported_ability\"}".into(),
            );
        };
        node.abilities = negotiated;
    }
    if let Some(value) = json_field(body, "platform") {
        node.platform = value;
    }
    if let Some(value) = json_field(body, "architecture") {
        node.architecture = value;
    }
    if let Some(value) = json_field(body, "version") {
        node.version = value;
    }
    let json = format!(
        "{{\"protocol_version\":{PROTOCOL_VERSION},\"negotiated_abilities\":[{}],\"node\":{}}}",
        abilities_json(&node.abilities),
        node_json(node)
    );
    store.audit.push(Activity::with_actor(
        "node.heartbeat",
        Some(node_id.clone()),
        None,
        Some(node_id),
    ));
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    ("200 OK", json)
}

impl Activity {
    fn with_actor(
        event: &str,
        node_id: Option<String>,
        task_id: Option<String>,
        actor: Option<String>,
    ) -> Self {
        Self {
            id: new_id("activity"),
            event: event.into(),
            node_id,
            task_id,
            actor,
            timestamp: now(),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }
}
fn json_field(body: &str, key: &str) -> Option<String> {
    parse_json_object(body).and_then(|object| {
        object
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn json_types_valid(body: &str, strings: &[&str], numbers: &[&str], booleans: &[&str]) -> bool {
    let Some(object) = parse_json_object(body) else {
        return false;
    };
    strings
        .iter()
        .all(|key| object.get(*key).is_none_or(Value::is_string))
        && numbers
            .iter()
            .all(|key| object.get(*key).is_none_or(Value::is_u64))
        && booleans
            .iter()
            .all(|key| object.get(*key).is_none_or(Value::is_boolean))
}

fn json_true(body: &str, key: &str) -> bool {
    parse_json_object(body)
        .and_then(|object| object.get(key).and_then(Value::as_bool))
        .unwrap_or(false)
}

fn parse_json_object(body: &str) -> Option<Value> {
    match serde_json::from_str::<Value>(body).ok()? {
        object @ Value::Object(_) => Some(object),
        _ => None,
    }
}
fn esc(value: &str) -> String {
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
fn node_json(node: &Node) -> String {
    format!(
        "{{\"node_id\":\"{}\",\"name\":\"{}\",\"online\":{},\"revoked\":{},\"abilities\":[{}],\"platform\":\"{}\",\"architecture\":\"{}\",\"version\":\"{}\",\"labels\":[{}],\"region\":\"{}\",\"data_class\":\"{}\",\"capacity\":\"{}\"}}",
        esc(&node.id),
        esc(&node.name),
        node_is_fresh(node),
        node.revoked,
        abilities_json(&node.abilities),
        esc(&node.platform),
        esc(&node.architecture),
        esc(&node.version),
        labels_json(&node.labels),
        esc(&node.region),
        esc(&node.data_class),
        esc(&node.capacity)
    )
}
fn task_json(task: &Task) -> String {
    format!(
        "{{\"task_id\":\"{}\",\"request_id\":\"{}\",\"actor\":\"{}\",\"node_id\":\"{}\",\"ability\":\"{}\",\"state\":\"{}\",\"idempotency_key\":\"{}\",\"program\":\"{}\",\"argument\":\"{}\",\"output\":\"{}\",\"output_sha256\":\"{}\",\"output_truncated\":{},\"output_limit\":{},\"exit_code\":{},\"lease_until\":{},\"lease_token\":\"{}\",\"timeout_ms\":{}}}",
        esc(&task.id),
        esc(&task.request_id),
        esc(&task.actor),
        esc(&task.node_id),
        esc(&task.ability),
        esc(&task.state),
        esc(&task.idempotency_key),
        esc(&task.program),
        esc(&task.argument),
        esc(&task.output),
        esc(&task.output_sha256),
        task.output_truncated,
        task.output_limit,
        task.exit_code.map(|code| code.to_string()).unwrap_or_else(|| "null".into()),
        task.lease_until,
        esc(&task.lease_token),
        task.timeout_ms
    )
}

fn approval_json(approval: &Approval) -> String {
    format!(
        "{{\"approval_id\":\"{}\",\"node_id\":\"{}\",\"ability\":\"{}\",\"program\":\"{}\",\"argument\":\"{}\",\"actor\":\"{}\",\"expires_at\":{},\"used\":{}}}",
        esc(&approval.id),
        esc(&approval.node_id),
        esc(&approval.ability),
        esc(&approval.program),
        esc(&approval.argument),
        esc(&approval.actor),
        approval.expires_at,
        approval.used
    )
}
fn activity_json_with_chain(item: &Activity, prev_hash: &str, hash: &str) -> String {
    format!("{{\"activity_id\":\"{}\",\"event\":\"{}\",\"node_id\":{},\"task_id\":{},\"actor\":{},\"timestamp\":{},\"prev_hash\":\"{}\",\"hash\":\"{}\"}}", esc(&item.id), esc(&item.event), item.node_id.as_deref().map(|v| format!("\"{}\"", esc(v))).unwrap_or_else(|| "null".into()), item.task_id.as_deref().map(|v| format!("\"{}\"", esc(v))).unwrap_or_else(|| "null".into()), item.actor.as_deref().map(|v| format!("\"{}\"", esc(v))).unwrap_or_else(|| "null".into()), item.timestamp, esc(prev_hash), esc(hash))
}

fn activity_hash(item: &Activity, prev_hash: &str) -> String {
    // Keep the legacy six-field canonical form for records created before the
    // actor field existed; new records bind the actor into the hash chain.
    let canonical = if let Some(actor) = item.actor.as_deref() {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            item.id,
            item.event,
            item.node_id.as_deref().unwrap_or(""),
            item.task_id.as_deref().unwrap_or(""),
            actor,
            item.timestamp,
            prev_hash
        )
    } else {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            item.id,
            item.event,
            item.node_id.as_deref().unwrap_or(""),
            item.task_id.as_deref().unwrap_or(""),
            item.timestamp,
            prev_hash
        )
    };
    hex_encode_bytes(&sha256(canonical.as_bytes()))
}

fn sealed_activity_json(audit: &[Activity], index: usize) -> String {
    let mut previous = "GENESIS".to_owned();
    for (current, item) in audit.iter().enumerate() {
        let hash = activity_hash(item, &previous);
        if current == index {
            return activity_json_with_chain(item, &previous, &hash);
        }
        previous = hash;
    }
    String::new()
}

fn audit_jsonl(audit: &[Activity]) -> String {
    audit
        .iter()
        .enumerate()
        .map(|(index, _item)| sealed_activity_json(audit, index))
        .collect::<Vec<_>>()
        .join("\n")
        + if audit.is_empty() { "" } else { "\n" }
}

fn export_audit(path: &str, state: &State) -> (&'static str, String) {
    let parse_query = |key: &str, default: usize| {
        query_field(path, key)
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(default)
    };
    let start = parse_query("from", 0);
    let limit = parse_query("limit", 1_000);
    if limit == 0 || limit > 10_000 {
        return (
            "400 Bad Request",
            "{\"code\":\"invalid_audit_limit\"}".into(),
        );
    }
    let store = state.store.lock().unwrap();
    if start > store.audit.len() {
        return (
            "416 Range Not Satisfiable",
            "{\"code\":\"invalid_audit_offset\"}".into(),
        );
    }
    let end = start.saturating_add(limit).min(store.audit.len());
    let records = (start..end)
        .map(|index| sealed_activity_json(&store.audit, index))
        .collect::<Vec<_>>();
    (
        "200 OK",
        format!(
            "{{\"protocol_version\":{PROTOCOL_VERSION},\"from\":{start},\"count\":{},\"next\":{},\"records\":[{}]}}",
            records.len(),
            if end < store.audit.len() { end.to_string() } else { "null".into() },
            records.join(",")
        ),
    )
}
fn new_id(prefix: &str) -> String {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!(
        "{prefix}_{:x}_{:x}_{:x}",
        now(),
        std::process::id(),
        sequence
    )
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn snapshot_text(store: &Store) -> String {
    let nodes = store
        .nodes
        .iter()
        .map(|node| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                clean(&node.id),
                clean(&node.name),
                if node.revoked {
                    "revoked"
                } else if node.online {
                    "online"
                } else {
                    "offline"
                },
                clean(&node.credential),
                clean(&node.abilities),
                hex_encode(&node.platform),
                hex_encode(&node.architecture),
                hex_encode(&node.version),
                hex_encode(&node.labels),
                hex_encode(&node.region),
                hex_encode(&node.data_class),
                hex_encode(&node.capacity),
                node.last_seen
            )
        })
        .collect::<String>();
    let tasks = store
        .tasks
        .iter()
        .map(|task| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                clean(&task.id),
                clean(&task.node_id),
                clean(&task.ability),
                clean(&task.state),
                clean(&task.idempotency_key),
                task.lease_until,
                hex_encode(&task.program),
                hex_encode(&task.argument),
                hex_encode(&task.output),
                clean(&task.output_sha256),
                if task.output_truncated {
                    "truncated"
                } else {
                    "complete"
                },
                task.exit_code
                    .map(|code| code.to_string())
                    .unwrap_or_default(),
                hex_encode(&task.request_id),
                hex_encode(&task.lease_token),
                hex_encode(&task.actor),
                task.timeout_ms,
                task.output_limit
            )
        })
        .collect::<String>();
    let grants = store
        .grants
        .iter()
        .map(|grant| {
            format!(
                "{}\t{}\t{}\t{}\t{}\n",
                clean(&grant.code),
                clean(&grant.signature),
                grant.expires_at,
                if grant.used { "used" } else { "unused" },
                if grant.revoked { "revoked" } else { "active" }
            )
        })
        .collect::<String>();
    let approvals = store
        .approvals
        .iter()
        .map(|approval| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                clean(&approval.id),
                clean(&approval.node_id),
                clean(&approval.ability),
                hex_encode(&approval.program),
                hex_encode(&approval.argument),
                clean(&approval.actor),
                approval.expires_at,
                if approval.used { "used" } else { "unused" }
            )
        })
        .collect::<String>();
    format!(
        "NODEWE-SNAPSHOT-V1\n[NODES]\n{nodes}[TASKS]\n{tasks}[GRANTS]\n{grants}[APPROVALS]\n{approvals}[AUDIT]\n{}",
        audit_jsonl(&store.audit)
    )
}

fn encode_store_bytes(contents: &[u8]) -> Result<Vec<u8>, String> {
    match store_key()? {
        Some(key) => encrypt_store(contents, &key),
        None => Ok(contents.to_vec()),
    }
}

fn decode_store_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.starts_with(STORE_MAGIC) {
        let key =
            store_key()?.ok_or_else(|| "encrypted store requires NODEWE_STORE_KEY".to_owned())?;
        decrypt_store(bytes, &key)
    } else {
        Ok(bytes.to_vec())
    }
}

fn persist_snapshot(data_dir: Option<&Path>, store: &Store) -> Result<(), String> {
    let Some(dir) = data_dir else { return Ok(()) };
    if fs::create_dir_all(dir).is_err() {
        return Err("cannot create data directory".into());
    }
    restrict_directory(dir);
    let nodes = store
        .nodes
        .iter()
        .map(|node| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                clean(&node.id),
                clean(&node.name),
                if node.revoked {
                    "revoked"
                } else if node.online {
                    "online"
                } else {
                    "offline"
                },
                clean(&node.credential),
                clean(&node.abilities),
                hex_encode(&node.platform),
                hex_encode(&node.architecture),
                hex_encode(&node.version),
                hex_encode(&node.labels),
                hex_encode(&node.region),
                hex_encode(&node.data_class),
                hex_encode(&node.capacity),
                node.last_seen
            )
        })
        .collect::<String>();
    let tasks = store
        .tasks
        .iter()
        .map(|task| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                clean(&task.id),
                clean(&task.node_id),
                clean(&task.ability),
                clean(&task.state),
                clean(&task.idempotency_key),
                task.lease_until,
                hex_encode(&task.program),
                hex_encode(&task.argument),
                hex_encode(&task.output),
                clean(&task.output_sha256),
                if task.output_truncated {
                    "truncated"
                } else {
                    "complete"
                },
                task.exit_code
                    .map(|code| code.to_string())
                    .unwrap_or_default(),
                hex_encode(&task.request_id),
                hex_encode(&task.lease_token),
                hex_encode(&task.actor),
                task.timeout_ms,
                task.output_limit,
            )
        })
        .collect::<String>();
    let audit = audit_jsonl(&store.audit);
    atomic_write(&dir.join("nodes.tsv"), &nodes)
        .map_err(|error| format!("nodes write failed: {error}"))?;
    atomic_write(&dir.join("tasks.tsv"), &tasks)
        .map_err(|error| format!("tasks write failed: {error}"))?;
    let grants = store
        .grants
        .iter()
        .map(|grant| {
            format!(
                "{}\t{}\t{}\t{}\t{}\n",
                clean(&grant.code),
                clean(&grant.signature),
                grant.expires_at,
                if grant.used { "used" } else { "unused" },
                if grant.revoked { "revoked" } else { "active" }
            )
        })
        .collect::<String>();
    let approvals = store
        .approvals
        .iter()
        .map(|approval| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                clean(&approval.id),
                clean(&approval.node_id),
                clean(&approval.ability),
                hex_encode(&approval.program),
                hex_encode(&approval.argument),
                clean(&approval.actor),
                approval.expires_at,
                if approval.used { "used" } else { "unused" }
            )
        })
        .collect::<String>();
    let snapshot = format!(
        "NODEWE-SNAPSHOT-V1\n[NODES]\n{nodes}[TASKS]\n{tasks}[GRANTS]\n{grants}[APPROVALS]\n{approvals}[AUDIT]\n{audit}"
    );
    atomic_write_with_backup(&dir.join("store.snapshot"), &snapshot)
        .map_err(|error| format!("store snapshot write failed: {error}"))?;
    atomic_write(&dir.join("grants.tsv"), &grants)
        .map_err(|error| format!("grants write failed: {error}"))?;
    atomic_write(&dir.join("approvals.tsv"), &approvals)
        .map_err(|error| format!("approvals write failed: {error}"))?;
    atomic_write(&dir.join("audit.jsonl"), &audit)
        .map_err(|error| format!("audit write failed: {error}"))?;
    Ok(())
}

fn persist_store(state: &State, store: &Store) -> Result<(), String> {
    state.backend.persist(store)
}

fn storage_unavailable() -> (&'static str, String) {
    (
        "503 Service Unavailable",
        "{\"code\":\"storage_unavailable\"}".into(),
    )
}

fn persist_or_rollback(
    state: &State,
    store: &mut Store,
    before: Store,
) -> Result<(), (&'static str, String)> {
    persist_store(state, store).map_err(|error| {
        eprintln!("NodeWe store persistence failed: {error}");
        *store = before;
        storage_unavailable()
    })
}

fn atomic_write(path: &Path, contents: &str) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let encoded = match store_key().map_err(std::io::Error::other)? {
        Some(key) => encrypt_store(contents.as_bytes(), &key).map_err(std::io::Error::other)?,
        None => contents.as_bytes().to_vec(),
    };
    let mut file = fs::File::create(&temporary)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    restrict_file(&temporary);
    fs::rename(temporary, path)?;
    sync_directory(path.parent());
    Ok(())
}

fn atomic_write_with_backup(path: &Path, contents: &str) -> std::io::Result<()> {
    if path.exists() {
        let backup = path.with_extension("snapshot.bak");
        let temporary = backup.with_extension(format!("bak.{}.tmp", std::process::id()));
        let existing = fs::read(path)?;
        let backup_contents = if let Some(key) = store_key().map_err(std::io::Error::other)? {
            if existing.starts_with(STORE_MAGIC) {
                existing
            } else {
                encrypt_store(&existing, &key).map_err(std::io::Error::other)?
            }
        } else {
            existing
        };
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&backup_contents)?;
        file.sync_all()?;
        restrict_file(&temporary);
        fs::rename(temporary, backup)?;
        sync_directory(path.parent());
    }
    atomic_write(path, contents)
}

#[cfg(unix)]
fn sync_directory(path: Option<&Path>) {
    if let Some(path) = path {
        if let Ok(directory) = fs::File::open(path) {
            let _ = directory.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn sync_directory(_path: Option<&Path>) {}

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

fn load_store(dir: &Path) -> Store {
    if let Ok(contents) = read_store_text(&dir.join("store.snapshot")) {
        if let Some(store) = parse_snapshot(&contents) {
            return store;
        }
    }
    load_legacy_store(dir)
}

fn load_sqlite_store(path: &Path) -> Store {
    let Ok(connection) = Connection::open(path) else {
        return Store::default();
    };
    let Ok(snapshot) = connection.query_row(
        "SELECT snapshot FROM nodewe_state WHERE id = 1",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    ) else {
        return Store::default();
    };
    decode_store_bytes(&snapshot)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| parse_snapshot(&text))
        .unwrap_or_default()
}

fn load_postgres_store(url: &str) -> Result<Store, String> {
    let mut client =
        Client::connect(url, NoTls).map_err(|e| format!("postgres connect failed: {e}"))?;
    client.batch_execute("CREATE TABLE IF NOT EXISTS nodewe_state (id SMALLINT PRIMARY KEY CHECK (id=1), snapshot BYTEA NOT NULL, updated_at BIGINT NOT NULL)").map_err(|e| format!("postgres schema failed: {e}"))?;
    let row = client
        .query_opt("SELECT snapshot FROM nodewe_state WHERE id=1", &[])
        .map_err(|e| format!("postgres read failed: {e}"))?;
    let Some(row) = row else {
        return Ok(Store::default());
    };
    let bytes: Vec<u8> = row.get(0);
    let text =
        decode_store_bytes(&bytes).map_err(|e| format!("postgres snapshot decode failed: {e}"))?;
    let text =
        String::from_utf8(text).map_err(|e| format!("postgres snapshot is not UTF-8: {e}"))?;
    parse_snapshot(&text).ok_or_else(|| "postgres snapshot is invalid".into())
}

fn parse_snapshot(contents: &str) -> Option<Store> {
    if !contents.starts_with("NODEWE-SNAPSHOT-V1\n") {
        return None;
    }
    let mut store = Store::default();
    let mut section = "";
    for line in contents.lines().skip(1) {
        if line.starts_with('[') && line.ends_with(']') {
            section = line;
            continue;
        }
        match section {
            "[NODES]" => parse_node_line(line, &mut store),
            "[TASKS]" => parse_task_line(line, &mut store),
            "[GRANTS]" => parse_grant_line(line, &mut store),
            "[APPROVALS]" => parse_approval_line(line, &mut store),
            "[AUDIT]" => parse_activity_line(line, &mut store),
            _ => {}
        }
    }
    if !audit_chain_valid(&store.audit) {
        return None;
    }
    Some(store)
}

fn audit_chain_valid(audit: &[Activity]) -> bool {
    let mut previous = "GENESIS".to_owned();
    for item in audit {
        let expected = activity_hash(item, &previous);
        if !item.hash.is_empty() && (item.prev_hash != previous || item.hash != expected) {
            return false;
        }
        previous = if item.hash.is_empty() {
            expected
        } else {
            item.hash.clone()
        };
    }
    true
}

fn parse_node_line(line: &str, store: &mut Store) {
    let mut fields = line.splitn(13, '\t');
    let (Some(id), Some(name), Some(status)) = (fields.next(), fields.next(), fields.next()) else {
        return;
    };
    let decode_or = |value: Option<&str>, default: &str| {
        value
            .and_then(hex_decode)
            .unwrap_or_else(|| default.to_owned())
    };
    store.nodes.push(Node {
        id: id.into(),
        name: name.into(),
        online: status == "online",
        revoked: status == "revoked",
        credential: fields.next().unwrap_or_default().into(),
        abilities: fields
            .next()
            .unwrap_or("file.read,file.write,task.exec,system.inspect")
            .into(),
        platform: decode_or(fields.next(), "unknown"),
        architecture: decode_or(fields.next(), "unknown"),
        version: decode_or(fields.next(), "unknown"),
        labels: decode_or(fields.next(), ""),
        region: decode_or(fields.next(), "unknown"),
        data_class: decode_or(fields.next(), "unclassified"),
        capacity: decode_or(fields.next(), ""),
        last_seen: fields
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(now),
    });
}

fn parse_task_line(line: &str, store: &mut Store) {
    let fields = line.split('\t').collect::<Vec<_>>();
    if fields.len() < 14 {
        return;
    }
    let id = fields[0];
    let node_id = fields[1];
    let ability = fields[2];
    let state = fields[3];
    let idempotency_key = fields[4].to_owned();
    let lease_until = fields[5].parse::<u64>().unwrap_or_default();
    let program = hex_decode(fields[6]).unwrap_or_else(|| "echo".into());
    let argument = hex_decode(fields[7]).unwrap_or_default();
    let output = hex_decode(fields[8]).unwrap_or_default();
    let has_output_metadata = fields.len() >= 16 && matches!(fields[10], "truncated" | "complete");
    let (output_sha256, output_truncated, exit_index) = if has_output_metadata {
        (fields[9].to_owned(), fields[10] == "truncated", 11)
    } else {
        (String::new(), false, 9)
    };
    let exit_code = fields.get(exit_index).and_then(|value| {
        if value.is_empty() {
            None
        } else {
            value.parse::<i32>().ok()
        }
    });
    let request_index = exit_index + 1;
    let request_id = fields
        .get(request_index)
        .and_then(|value| hex_decode(value))
        .unwrap_or_else(|| id.to_owned());
    let lease_token = fields
        .get(request_index + 1)
        .and_then(|value| hex_decode(value))
        .unwrap_or_default();
    let actor = fields
        .get(request_index + 2)
        .and_then(|value| hex_decode(value))
        .unwrap_or_else(|| "admin".into());
    let timeout_ms = fields
        .get(request_index + 3)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0 && *value <= MAX_TASK_TIMEOUT_MS)
        .unwrap_or(DEFAULT_TASK_TIMEOUT_MS);
    let output_limit = fields
        .get(request_index + 4)
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0 && *value <= MAX_TASK_OUTPUT_LIMIT)
        .unwrap_or(MAX_TASK_OUTPUT_LIMIT);
    store.tasks.push(Task {
        id: id.into(),
        request_id,
        actor,
        node_id: node_id.into(),
        ability: ability.into(),
        state: state.into(),
        idempotency_key,
        program,
        argument,
        output,
        output_sha256,
        output_truncated,
        exit_code,
        lease_until,
        lease_token,
        timeout_ms,
        output_limit,
    });
}

fn parse_grant_line(line: &str, store: &mut Store) {
    let mut fields = line.splitn(5, '\t');
    let (Some(code), Some(signature), Some(expires_at), Some(status)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return;
    };
    let Ok(expires_at) = expires_at.parse::<u64>() else {
        return;
    };
    store.grants.push(Grant {
        code: code.into(),
        signature: signature.into(),
        expires_at,
        used: status == "used",
        revoked: fields.next() == Some("revoked"),
    });
}

fn parse_approval_line(line: &str, store: &mut Store) {
    let mut fields = line.splitn(8, '\t');
    let (
        Some(id),
        Some(node_id),
        Some(ability),
        Some(program),
        Some(argument),
        Some(actor),
        Some(expires_at),
        Some(status),
    ) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    )
    else {
        return;
    };
    let (Some(program), Some(argument), Ok(expires_at)) = (
        hex_decode(program),
        hex_decode(argument),
        expires_at.parse::<u64>(),
    ) else {
        return;
    };
    store.approvals.push(Approval {
        id: id.into(),
        node_id: node_id.into(),
        ability: ability.into(),
        program,
        argument,
        actor: actor.into(),
        expires_at,
        used: status == "used",
    });
}

fn parse_activity_line(line: &str, store: &mut Store) {
    let (Some(id), Some(event), Some(timestamp)) = (
        json_field(line, "activity_id"),
        json_field(line, "event"),
        json_number(line, "timestamp"),
    ) else {
        return;
    };
    store.audit.push(Activity {
        id,
        event,
        node_id: json_field(line, "node_id"),
        task_id: json_field(line, "task_id"),
        actor: json_field(line, "actor"),
        timestamp,
        prev_hash: json_field(line, "prev_hash").unwrap_or_default(),
        hash: json_field(line, "hash").unwrap_or_default(),
    });
}

fn json_number(body: &str, key: &str) -> Option<u64> {
    parse_json_object(body)?.get(key)?.as_u64()
}

fn json_key_present(body: &str, key: &str) -> bool {
    parse_json_object(body)
        .and_then(|object| object.as_object().map(|map| map.contains_key(key)))
        .unwrap_or(false)
}

fn load_legacy_store(dir: &Path) -> Store {
    let mut store = Store::default();
    if let Ok(contents) = read_store_text(&dir.join("nodes.tsv")) {
        for line in contents.lines() {
            let mut f = line.splitn(15, '\t');
            let (Some(id), Some(name), Some(status)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            let decode_or = |value: Option<&str>, default: &str| {
                value
                    .and_then(hex_decode)
                    .unwrap_or_else(|| default.to_owned())
            };
            store.nodes.push(Node {
                id: id.into(),
                name: name.into(),
                online: status == "online",
                revoked: status == "revoked",
                credential: f.next().unwrap_or_default().into(),
                abilities: f
                    .next()
                    .unwrap_or("file.read,file.write,task.exec,system.inspect")
                    .into(),
                platform: decode_or(f.next(), "unknown"),
                architecture: decode_or(f.next(), "unknown"),
                version: decode_or(f.next(), "unknown"),
                labels: decode_or(f.next(), ""),
                region: decode_or(f.next(), "unknown"),
                data_class: decode_or(f.next(), "unclassified"),
                capacity: decode_or(f.next(), ""),
                last_seen: f
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(now),
            });
        }
    }
    if let Ok(contents) = read_store_text(&dir.join("tasks.tsv")) {
        for line in contents.lines() {
            let mut f = line.splitn(15, '\t');
            let (Some(id), Some(node_id), Some(ability), Some(state)) =
                (f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            let idempotency_key = f.next().unwrap_or_default().to_owned();
            let lease_until = f
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_default();
            let program = f
                .next()
                .and_then(hex_decode)
                .unwrap_or_else(|| "echo".into());
            let argument = f.next().and_then(hex_decode).unwrap_or_default();
            let output = f.next().and_then(hex_decode).unwrap_or_default();
            let exit_code = f.next().and_then(|value| {
                if value.is_empty() {
                    None
                } else {
                    value.parse::<i32>().ok()
                }
            });
            let request_id = f
                .next()
                .and_then(hex_decode)
                .unwrap_or_else(|| id.to_owned());
            let lease_token = f.next().and_then(hex_decode).unwrap_or_default();
            let actor = f
                .next()
                .and_then(hex_decode)
                .unwrap_or_else(|| "admin".into());
            let timeout_ms = f
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0 && *value <= MAX_TASK_TIMEOUT_MS)
                .unwrap_or(DEFAULT_TASK_TIMEOUT_MS);
            store.tasks.push(Task {
                id: id.into(),
                request_id,
                actor,
                node_id: node_id.into(),
                ability: ability.into(),
                state: state.into(),
                idempotency_key,
                program,
                argument,
                output,
                output_sha256: String::new(),
                output_truncated: false,
                exit_code,
                lease_until,
                lease_token,
                timeout_ms,
                output_limit: MAX_TASK_OUTPUT_LIMIT,
            });
        }
    }
    if let Ok(contents) = read_store_text(&dir.join("grants.tsv")) {
        for line in contents.lines() {
            let mut f = line.splitn(5, '\t');
            let (Some(code), Some(signature), Some(expires_at), Some(status)) =
                (f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            let Ok(expires_at) = expires_at.parse::<u64>() else {
                continue;
            };
            store.grants.push(Grant {
                code: code.into(),
                signature: signature.into(),
                expires_at,
                used: status == "used",
                revoked: f.next() == Some("revoked"),
            });
        }
    }
    if let Ok(contents) = read_store_text(&dir.join("approvals.tsv")) {
        for line in contents.lines() {
            parse_approval_line(line, &mut store);
        }
    }
    store
}

const STORE_MAGIC: &[u8] = b"NWENC1";

fn store_key() -> Result<Option<[u8; 32]>, String> {
    let Some(value) = load_secret_value("NODEWE_STORE_KEY", "NODEWE_STORE_KEY_FILE")? else {
        return Ok(None);
    };
    let value = value.trim();
    if value.len() != 64 {
        return Err("NODEWE_STORE_KEY must contain exactly 64 hex characters".into());
    }
    let mut key = [0_u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "NODEWE_STORE_KEY must contain only hexadecimal characters")?;
    }
    Ok(Some(key))
}

fn load_secret_value(env_name: &str, file_env_name: &str) -> Result<Option<String>, String> {
    if let Some(value) = env::var_os(env_name) {
        return value
            .into_string()
            .map(|value| Some(value.trim().to_owned()))
            .map_err(|_| format!("{env_name} must be UTF-8"));
    }
    let Some(path) = env::var_os(file_env_name) else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("cannot stat {file_env_name} {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "secret file {} must not be group/world readable",
                path.display()
            ));
        }
    }
    let value = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {file_env_name} {}: {error}", path.display()))?;
    if value.trim().is_empty() {
        return Err(format!("{file_env_name} must not be empty"));
    }
    Ok(Some(value.trim().to_owned()))
}

fn secure_random_bytes(output: &mut [u8]) -> std::io::Result<()> {
    let mut file = fs::File::open("/dev/urandom")?;
    file.read_exact(output)
}

fn encrypt_store(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| "invalid store key")?;
    let key = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    secure_random_bytes(&mut nonce_bytes).map_err(|_| "secure random source unavailable")?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut encrypted = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted)
        .map_err(|_| "store encryption failed")?;
    let mut output = STORE_MAGIC.to_vec();
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

fn decrypt_store(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let minimum = STORE_MAGIC.len() + NONCE_LEN;
    if ciphertext.len() < minimum || !ciphertext.starts_with(STORE_MAGIC) {
        return Err("invalid encrypted store header".into());
    }
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| "invalid store key")?;
    let key = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&ciphertext[STORE_MAGIC.len()..minimum]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut plaintext = ciphertext[minimum..].to_vec();
    let opened = key
        .open_in_place(nonce, Aad::empty(), &mut plaintext)
        .map_err(|_| "store authentication failed")?;
    Ok(opened.to_vec())
}

fn read_store_text(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let plaintext = if bytes.starts_with(STORE_MAGIC) {
        let key =
            store_key()?.ok_or_else(|| "encrypted store requires NODEWE_STORE_KEY".to_owned())?;
        decrypt_store(&bytes, &key)?
    } else {
        bytes
    };
    String::from_utf8(plaintext).map_err(|_| "store is not valid UTF-8".into())
}

fn validate_store_startup(dir: &Path) -> Result<(), String> {
    let key = store_key()?;
    let require_encrypted = env::var("NODEWE_REQUIRE_ENCRYPTED_STORE").as_deref() == Ok("1");
    if require_encrypted && key.is_none() {
        return Err("NODEWE_STORE_KEY is required when encrypted storage is enforced".into());
    }
    for name in [
        "store.snapshot",
        "store.snapshot.bak",
        "nodes.tsv",
        "tasks.tsv",
        "grants.tsv",
        "approvals.tsv",
        "audit.jsonl",
    ] {
        let path = dir.join(name);
        let Ok(bytes) = fs::read(&path) else { continue };
        if require_encrypted && !bytes.starts_with(STORE_MAGIC) {
            return Err(format!(
                "plaintext store file is not allowed: {}",
                path.display()
            ));
        }
        let plaintext = if bytes.starts_with(STORE_MAGIC) {
            let key = key.ok_or_else(|| {
                format!(
                    "encrypted store requires NODEWE_STORE_KEY: {}",
                    path.display()
                )
            })?;
            decrypt_store(&bytes, &key)?
        } else {
            bytes
        };
        if name == "store.snapshot" {
            let text = String::from_utf8(plaintext)
                .map_err(|_| format!("store snapshot is not UTF-8: {}", path.display()))?;
            if parse_snapshot(&text).is_none() {
                return Err(format!(
                    "store snapshot integrity check failed: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn validate_sqlite_startup(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let connection = Connection::open(path).map_err(|e| format!("sqlite open failed: {e}"))?;
    let snapshot: Vec<u8> = connection
        .query_row(
            "SELECT snapshot FROM nodewe_state WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("sqlite state read failed: {e}"))?;
    if env::var("NODEWE_REQUIRE_ENCRYPTED_STORE").as_deref() == Ok("1")
        && !snapshot.starts_with(STORE_MAGIC)
    {
        return Err("plaintext SQLite store is not allowed".into());
    }
    let bytes = decode_store_bytes(&snapshot)?;
    let text = String::from_utf8(bytes).map_err(|_| "sqlite snapshot is not UTF-8")?;
    if parse_snapshot(&text).is_none() {
        return Err("sqlite snapshot integrity check failed".into());
    }
    Ok(())
}

fn clean(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

fn hex_encode(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hex_decode(value: &str) -> Option<String> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    String::from_utf8(bytes).ok()
}

fn credential_authorized(
    store: &Arc<Mutex<Store>>,
    path: &str,
    body: &str,
    presented: &str,
) -> bool {
    let node_id = json_field(body, "node_id").or_else(|| query_field(path, "node_id"));
    let Some(node_id) = node_id else { return false };
    let store = store.lock().unwrap();
    store.nodes.iter().any(|node| {
        node.id == node_id && constant_time_eq(&node.credential, presented) && !node.revoked
    })
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= left.as_bytes().get(index).copied().unwrap_or(0) as usize
            ^ right.as_bytes().get(index).copied().unwrap_or(0) as usize;
    }
    difference == 0
}

fn constant_time_eq_bytes(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= left.get(index).copied().unwrap_or(0) as usize
            ^ right.get(index).copied().unwrap_or(0) as usize;
    }
    difference == 0
}

fn query_field(path: &str, key: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    query.split('&').find_map(|item| {
        let (name, value) = item.split_once('=')?;
        (name == key).then(|| value.to_owned())
    })
}

fn agent_tasks(path: &str, state: &State) -> (&'static str, String) {
    let Some(node_id) = query_field(path, "node_id") else {
        return ("400 Bad Request", "{\"code\":\"node_id_required\"}".into());
    };
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    if !store
        .nodes
        .iter()
        .any(|node| node.id == node_id && !node.revoked && node_is_fresh(node))
    {
        return ("403 Forbidden", "{\"code\":\"node_revoked\"}".into());
    }
    let mut queued = Vec::new();
    for task in store.tasks.iter_mut().filter(|task| {
        task.node_id == node_id
            && (task.state == "queued" || (task.state == "dispatched" && task.lease_until <= now()))
    }) {
        let Ok(lease_token) = random_token() else {
            return (
                "500 Internal Server Error",
                "{\"code\":\"secure_random_unavailable\"}".into(),
            );
        };
        task.state = "dispatched".into();
        task.lease_until = now() + task.timeout_ms.max(DEFAULT_TASK_TIMEOUT_MS) + 5_000;
        task.lease_token = lease_token;
        queued.push(task_json(task));
    }
    if !queued.is_empty() {
        store.audit.push(Activity::with_actor(
            "task.dispatched",
            Some(node_id.clone()),
            None,
            Some(node_id),
        ));
        if let Err(response) = persist_or_rollback(state, &mut store, before) {
            return response;
        }
    }
    ("200 OK", format!("[{}]", queued.join(",")))
}

fn agent_result(path: &str, body: &str, state: &State) -> (&'static str, String) {
    if !json_types_valid(
        body,
        &[
            "node_id",
            "request_id",
            "lease_token",
            "state",
            "output",
            "output_sha256",
            "exit_code",
        ],
        &[],
        &[],
    ) {
        return ("400 Bad Request", "{\"code\":\"invalid_json_type\"}".into());
    }
    let task_id = path
        .trim_start_matches("/v1/agent/tasks/")
        .trim_end_matches("/result")
        .trim_end_matches('/');
    let node_id = json_field(body, "node_id").unwrap_or_default();
    let request_id = json_field(body, "request_id");
    let lease_token = json_field(body, "lease_token").unwrap_or_default();
    if request_id
        .as_deref()
        .is_some_and(|value| !valid_node_id(value))
    {
        return (
            "400 Bad Request",
            "{\"code\":\"invalid_request_id\"}".into(),
        );
    }
    let new_state = json_field(body, "state").unwrap_or_else(|| "failed".into());
    let raw_output = json_field(body, "output").unwrap_or_default();
    let computed_output_sha256 = hex_encode_bytes(&sha256(raw_output.as_bytes()));
    let output_sha256 = match json_field(body, "output_sha256") {
        Some(value)
            if value.len() == 64
                && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                && constant_time_eq(&value.to_ascii_lowercase(), &computed_output_sha256) =>
        {
            computed_output_sha256.clone()
        }
        Some(_) => {
            return (
                "400 Bad Request",
                "{\"code\":\"output_hash_mismatch\"}".into(),
            )
        }
        None => computed_output_sha256,
    };
    let exit_code = json_field(body, "exit_code").and_then(|value| value.parse::<i32>().ok());
    let mut store = state.store.lock().unwrap();
    let before = store.clone();
    let Some(task) = store
        .tasks
        .iter_mut()
        .find(|task| task.id == task_id && task.node_id == node_id)
    else {
        return ("404 Not Found", "{\"code\":\"task_not_found\"}".into());
    };
    if request_id
        .as_deref()
        .is_some_and(|value| value != task.request_id)
    {
        return ("409 Conflict", "{\"code\":\"request_id_mismatch\"}".into());
    }
    if task.state != "dispatched" || task.lease_until < now() {
        return ("409 Conflict", "{\"code\":\"task_expired\"}".into());
    }
    if task.lease_token.is_empty() || !constant_time_eq(&task.lease_token, &lease_token) {
        return ("409 Conflict", "{\"code\":\"lease_token_mismatch\"}".into());
    }
    if !matches!(
        new_state.as_str(),
        "succeeded" | "failed" | "cancelled" | "timed_out"
    ) {
        return (
            "400 Bad Request",
            "{\"code\":\"invalid_task_state\"}".into(),
        );
    }
    let persisted_output_limit = task.output_limit.min(MAX_PERSISTED_OUTPUT_BYTES);
    let output_truncated = raw_output.len() > persisted_output_limit;
    let output = truncate_utf8(&raw_output, persisted_output_limit);
    task.state = new_state;
    task.output = output;
    task.output_sha256 = output_sha256;
    task.output_truncated = output_truncated;
    task.exit_code = exit_code;
    let json = task_json(task);
    store.audit.push(Activity::with_actor(
        "task.completed",
        Some(node_id.clone()),
        Some(task_id.into()),
        Some(node_id),
    ));
    if let Err(response) = persist_or_rollback(state, &mut store, before) {
        return response;
    }
    ("200 OK", json)
}

/// Keep persisted previews within their byte budget without splitting UTF-8.
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

fn node_with_credential_json(node: &Node, credential: &str) -> String {
    format!(
        "{{\"node_id\":\"{}\",\"name\":\"{}\",\"online\":{},\"revoked\":{},\"abilities\":[{}],\"platform\":\"{}\",\"architecture\":\"{}\",\"version\":\"{}\",\"labels\":[{}],\"region\":\"{}\",\"data_class\":\"{}\",\"capacity\":\"{}\",\"credential\":\"{}\"}}",
        esc(&node.id),
        esc(&node.name),
        node_is_fresh(node),
        node.revoked,
        abilities_json(&node.abilities),
        esc(&node.platform),
        esc(&node.architecture),
        esc(&node.version),
        labels_json(&node.labels),
        esc(&node.region),
        esc(&node.data_class),
        esc(&node.capacity),
        esc(credential)
    )
}

fn abilities_json(abilities: &str) -> String {
    abilities
        .split(',')
        .filter(|ability| !ability.is_empty())
        .map(|ability| format!("\"{}\"", esc(ability)))
        .collect::<Vec<_>>()
        .join(",")
}

fn normalize_abilities(abilities: &str) -> Result<String, ()> {
    let mut normalized = Vec::new();
    for ability in abilities
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !SUPPORTED_ABILITIES.contains(&ability) {
            return Err(());
        }
        if !normalized.iter().any(|existing| existing == &ability) {
            normalized.push(ability);
        }
    }
    if normalized.is_empty() {
        return Err(());
    }
    Ok(normalized.join(","))
}

fn labels_json(labels: &str) -> String {
    labels
        .split(',')
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .map(|label| format!("\"{}\"", esc(label)))
        .collect::<Vec<_>>()
        .join(",")
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

fn node_metadata(body: &str) -> (String, String, String, String, String, String, String) {
    (
        json_field(body, "platform").unwrap_or_else(|| "unknown".into()),
        json_field(body, "architecture").unwrap_or_else(|| "unknown".into()),
        json_field(body, "version").unwrap_or_else(|| "unknown".into()),
        json_field(body, "labels").unwrap_or_default(),
        json_field(body, "region").unwrap_or_else(|| "unknown".into()),
        json_field(body, "data_class").unwrap_or_else(|| "unclassified".into()),
        json_field(body, "capacity").unwrap_or_default(),
    )
}

fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_graphic()
                && !matches!(byte, b'/' | b'\\' | b'?' | b'&' | b'=' | b'#' | b'%')
        })
}

fn ensure_bind_safe(bind: &str) -> Result<(), &'static str> {
    let host = bind.rsplit_once(':').map(|(host, _)| host).unwrap_or(bind);
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]");
    if loopback || env::var("NODEWE_ALLOW_PRIVATE_BIND").as_deref() == Ok("1") {
        Ok(())
    } else {
        Err("non-loopback bind requires NODEWE_ALLOW_PRIVATE_BIND=1")
    }
}

/// Prevent an operator from accidentally starting the development security
/// profile under a production service name. The deployment preflight checks
/// the same settings, but the binary must remain fail-closed when launched
/// directly or by a misconfigured supervisor.
fn enforce_production_mode() -> Result<(), String> {
    if env::var("NODEWE_ENV").as_deref() != Ok("production") {
        return Ok(());
    }
    for name in [
        "NODEWE_REQUIRE_ENCRYPTED_STORE",
        "NODEWE_REQUIRE_SIGNED_GRANTS",
        "NODEWE_REQUIRE_APPROVAL_RECORDS",
        "NODEWE_OIDC_REQUIRED",
    ] {
        if env::var(name).as_deref() != Ok("1") {
            return Err(format!("NODEWE_ENV=production requires {name}=1"));
        }
    }
    let data_dir = env::var("NODEWE_DATA_DIR")
        .map_err(|_| "NODEWE_ENV=production requires an explicit NODEWE_DATA_DIR".to_owned())?;
    if data_dir.trim().is_empty() || data_dir == ".nodewe-control-plane" {
        return Err("NODEWE_ENV=production requires a non-default NODEWE_DATA_DIR".into());
    }
    let native_tls = ["NODEWE_TLS_CERT", "NODEWE_TLS_KEY", "NODEWE_TLS_CLIENT_CA"]
        .iter()
        .all(|name| env::var_os(name).is_some());
    if !native_tls && env::var("NODEWE_TLS_PROXY_APPROVED").as_deref() != Ok("1") {
        return Err(
            "NODEWE_ENV=production requires native TLS/mTLS or NODEWE_TLS_PROXY_APPROVED=1".into(),
        );
    }
    Ok(())
}

fn random_token() -> Result<String, &'static str> {
    let mut bytes = [0_u8; 24];
    if let Ok(mut file) = fs::File::open("/dev/urandom") {
        use std::io::Read as _;
        if file.read_exact(&mut bytes).is_ok() {
            return Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect());
        }
    }
    Err("secure random source unavailable")
}

fn sign_grant(code: &str, expires_at: u64, secret: &str) -> Result<String, &'static str> {
    let payload = format!("{code}:{expires_at}");
    let configured_key = configured_grant_signing_key().map_err(|_| "invalid grant signing key")?;
    if let Some(key_bytes) = configured_key {
        let key_pair = grant_key_pair(&key_bytes).map_err(|_| "invalid grant signing key")?;
        return Ok(hex_encode_bytes(key_pair.sign(payload.as_bytes()).as_ref()));
    }
    if !configured_grant_verification_keys()
        .map_err(|_| "invalid grant signing key")?
        .is_empty()
    {
        return Err("active grant signing key is required for signing");
    }
    let digest = hmac_sha256(secret.as_bytes(), payload.as_bytes());
    Ok(hex_encode_bytes(&digest))
}

fn verify_grant(code: &str, expires_at: u64, signature: &str, secret: &str) -> bool {
    let payload = format!("{code}:{expires_at}");
    let Ok(configured_keys) = configured_grant_verification_keys() else {
        return false;
    };
    if !configured_keys.is_empty() {
        let Some(signature) = hex_decode_bytes(signature) else {
            return false;
        };
        return configured_keys.iter().any(|key_bytes| {
            let Ok(key_pair) = grant_key_pair(key_bytes) else {
                return false;
            };
            UnparsedPublicKey::new(&ED25519, key_pair.public_key().as_ref())
                .verify(payload.as_bytes(), &signature)
                .is_ok()
        });
    }
    let digest = hmac_sha256(secret.as_bytes(), payload.as_bytes());
    constant_time_eq(signature, &hex_encode_bytes(&digest))
}

fn configured_grant_signing_key() -> Result<Option<Vec<u8>>, String> {
    configured_signing_key_value("NODEWE_GRANT_SIGNING_KEY", "NODEWE_GRANT_SIGNING_KEY_FILE")
}

fn configured_grant_verification_keys() -> Result<Vec<Vec<u8>>, String> {
    let mut keys = Vec::new();
    if let Some(active) = configured_grant_signing_key()? {
        keys.push(active);
    }
    if let Some(previous) = configured_signing_key_value(
        "NODEWE_GRANT_SIGNING_KEY_PREVIOUS",
        "NODEWE_GRANT_SIGNING_KEY_PREVIOUS_FILE",
    )? {
        keys.push(previous);
    }
    Ok(keys)
}

fn configured_signing_key_value(
    env_name: &str,
    file_env_name: &str,
) -> Result<Option<Vec<u8>>, String> {
    let Some(value) = load_secret_value(env_name, file_env_name)? else {
        return Ok(None);
    };
    Ok(Some(hex_decode_bytes(&value).ok_or_else(|| {
        format!("{env_name} must be hexadecimal PKCS#8 bytes")
    })?))
}

fn grant_key_pair(key_bytes: &[u8]) -> Result<Ed25519KeyPair, ring::error::KeyRejected> {
    Ed25519KeyPair::from_pkcs8(key_bytes)
        .or_else(|_| Ed25519KeyPair::from_pkcs8_maybe_unchecked(key_bytes))
}

fn hex_encode_bytes(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode_bytes(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0_u8; 64];
    let mut outer = [0_u8; 64];
    for index in 0..64 {
        inner[index] = block[index] ^ 0x36;
        outer[index] = block[index] ^ 0x5c;
    }
    let mut inner_message = inner.to_vec();
    inner_message.extend_from_slice(message);
    let inner_digest = sha256(&inner_message);
    let mut outer_message = outer.to_vec();
    outer_message.extend_from_slice(&inner_digest);
    sha256(&outer_message)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut message = data.to_vec();
    let bit_len = (message.len() as u64) * 8;
    message.push(0x80);
    while !(message.len() + 8).is_multiple_of(64) {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    let mut hash: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    for chunk in message.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for index in 0..16 {
            words[index] = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        );
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            (h, g, f, e, d, c, b, a) = (
                g,
                f,
                e,
                d.wrapping_add(temp1),
                c,
                b,
                a,
                temp1.wrapping_add(temp2),
            );
        }
        for index in 0..8 {
            hash[index] = hash[index].wrapping_add([a, b, c, d, e, f, g, h][index]);
        }
    }
    let mut output = [0_u8; 32];
    for index in 0..8 {
        output[index * 4..index * 4 + 4].copy_from_slice(&hash[index].to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingBackend;

    impl StoreBackend for FailingBackend {
        fn persist(&self, _store: &Store) -> Result<(), String> {
            Err("injected persistence failure".into())
        }
    }

    fn first_array_field(body: &str, key: &str) -> Option<String> {
        let value = serde_json::from_str::<Value>(body).ok()?;
        value
            .as_array()?
            .first()?
            .get(key)?
            .as_str()
            .map(ToOwned::to_owned)
    }

    fn state() -> State {
        State {
            admin_token: "secret".into(),
            grant_secret: "test-grant-secret".into(),
            store: Arc::new(Mutex::new(Store::default())),
            require_approval_records: false,
            policy: Policy::default(),
            oidc: None,
            active_connections: Arc::new(AtomicU64::new(0)),
            _store_lock: None,
            backend: Arc::new(SnapshotBackend { data_dir: None }),
        }
    }

    fn failing_state() -> State {
        let mut state = state();
        state.backend = Arc::new(FailingBackend);
        state
    }

    #[test]
    fn persistence_failure_returns_service_unavailable_and_rolls_back() {
        let state = failing_state();
        let (status, _) = create_node("{\"node_id\":\"storage-failure\"}", &state);
        assert_eq!(status, "503 Service Unavailable");
        assert!(state.store.lock().unwrap().nodes.is_empty());
    }

    #[test]
    fn agent_result_rejects_mismatched_output_hash() {
        let state = state();
        create_node("{\"node_id\":\"hash-node\"}", &state);
        let (_, task_json) = create_task(
            "{\"node_id\":\"hash-node\",\"ability\":\"file.read\"}",
            &state,
        );
        let task_id = json_field(&task_json, "task_id").unwrap();
        let (_, dispatched) = agent_tasks("/v1/agent/tasks?node_id=hash-node", &state);
        let lease = first_array_field(&dispatched, "lease_token").unwrap();
        let status = agent_result(
            &format!("/v1/agent/tasks/{task_id}/result"),
            &format!("{{\"node_id\":\"hash-node\",\"lease_token\":\"{lease}\",\"state\":\"succeeded\",\"output\":\"hello\",\"output_sha256\":\"{}\"}}", "0".repeat(64)),
            &state,
        )
        .0;
        assert_eq!(status, "400 Bad Request");
        assert_eq!(state.store.lock().unwrap().tasks[0].state, "dispatched");
    }

    #[test]
    fn sqlite_backend_commits_and_round_trips_snapshot() {
        let path = std::env::temp_dir().join(format!("nodewe-sqlite-test-{}.db", now()));
        let state = State {
            backend: Arc::new(SqliteBackend { path: path.clone() }),
            ..state()
        };
        assert_eq!(
            create_node("{\"node_id\":\"sqlite-node\"}", &state).0,
            "201 Created"
        );
        let loaded = load_sqlite_store(&path);
        assert_eq!(
            loaded.nodes.first().map(|node| node.id.as_str()),
            Some("sqlite-node")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn health_is_public_but_api_requires_auth() {
        let state = state();
        assert_eq!(
            route("GET", "/health", "", false, false, &state).0,
            "200 OK"
        );
        assert_eq!(
            route("GET", "/v1/nodes", "", false, false, &state).0,
            "401 Unauthorized"
        );
        assert_eq!(
            route(
                "POST",
                "/v1/tasks",
                "{\"node_id\":\"a\"}",
                true,
                false,
                &state
            )
            .0,
            "403 Forbidden"
        );
        assert_eq!(
            route(
                "POST",
                "/v1/nodes",
                "{\"node_id\":\"a\"}",
                true,
                false,
                &state
            )
            .0,
            "403 Forbidden"
        );
    }

    #[test]
    fn request_content_length_is_strict_and_rejects_smuggling_inputs() {
        assert_eq!(
            request_content_length("POST /v1/tasks HTTP/1.1\r\nHost: nodewe\r\n\r\n"),
            Ok(0)
        );
        assert_eq!(
            request_content_length(
                "POST /v1/tasks HTTP/1.1\r\nContent-Length: 12\r\nContent-Length: 12\r\n\r\n"
            ),
            Ok(12)
        );
        assert_eq!(
            request_content_length(
                "POST /v1/tasks HTTP/1.1\r\nContent-Length: 12\r\nContent-Length: 13\r\n\r\n"
            ),
            Err("conflicting_content_length")
        );
        assert_eq!(
            request_content_length("POST /v1/tasks HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err("unsupported_transfer_encoding")
        );
        assert_eq!(
            request_content_length("POST /v1/tasks HTTP/1.1\r\nContent-Length: nope\r\n\r\n"),
            Err("invalid_content_length")
        );
        assert_eq!(
            request_content_length("POST /v1/tasks HTTP/1.1\r\nContent-Length: +12\r\n\r\n"),
            Err("invalid_content_length")
        );
    }

    #[test]
    fn json_helpers_reject_malformed_or_wrongly_typed_payloads() {
        assert_eq!(json_field("{\"node_id\":", "node_id"), None);
        assert_eq!(json_field("{\"node_id\":123}", "node_id"), None);
        assert_eq!(
            json_number("{\"timeout_ms\":\"30000\"}", "timeout_ms"),
            None
        );
        assert!(!json_true("{\"approved\":\"true\"}", "approved"));
        assert!(json_field("[{\"task_id\":\"task-1\"}]", "task_id").is_none());
        assert_eq!(
            first_array_field("[{\"task_id\":\"task-1\"}]", "task_id").as_deref(),
            Some("task-1")
        );
    }

    #[test]
    fn node_labels_are_restricted_to_safe_values() {
        assert!(valid_labels("gpu,lab-1,arm64+cuda"));
        assert!(valid_labels("gpu, lab"));
        assert!(!valid_labels("gpu/secret"));
        assert!(!valid_labels("gpu\nX-Injected: yes"));
    }

    #[test]
    fn heartbeat_cannot_change_admin_owned_node_metadata() {
        let state = state();
        assert_eq!(
            create_node(
                "{\"node_id\":\"metadata-node\",\"labels\":\"gpu\",\"region\":\"cn-east\",\"data_class\":\"restricted\",\"capacity\":\"gpu=1\"}"
            , &state)
            .0,
            "201 Created"
        );
        let response = heartbeat(
            "{\"node_id\":\"metadata-node\",\"labels\":\"public\",\"data_class\":\"public\"}",
            &state,
        );
        assert_eq!(response.0, "400 Bad Request");
        let store = state.store.lock().unwrap();
        let node = store
            .nodes
            .iter()
            .find(|node| node.id == "metadata-node")
            .expect("node remains registered");
        assert_eq!(node.labels, "gpu");
        assert_eq!(node.region, "cn-east");
        assert_eq!(node.data_class, "restricted");
        assert_eq!(node.capacity, "gpu=1");
    }

    #[test]
    fn heartbeat_rejects_malformed_or_wrongly_typed_fields() {
        let state = state();
        assert_eq!(
            create_node("{\"node_id\":\"typed-node\"}", &state).0,
            "201 Created"
        );
        assert_eq!(
            heartbeat(
                "{\"node_id\":\"typed-node\",\"protocol_version\":\"1\"}",
                &state
            )
            .0,
            "400 Bad Request"
        );
        assert_eq!(
            heartbeat(
                "{\"node_id\":\"typed-node\",\"abilities\":[\"file.read\"]}",
                &state
            )
            .0,
            "400 Bad Request"
        );
        assert_eq!(
            heartbeat(
                "{\"node_id\":\"typed-node\",\"labels\":[\"public\"]}",
                &state
            )
            .0,
            "400 Bad Request"
        );
        assert_eq!(heartbeat("{\"node_id\":", &state).0, "400 Bad Request");
    }

    #[test]
    fn non_loopback_bind_is_rejected_by_default() {
        assert!(ensure_bind_safe("0.0.0.0:8787").is_err());
        assert!(ensure_bind_safe("127.0.0.1:8787").is_ok());
    }

    #[test]
    fn websocket_accept_matches_rfc6455_example() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert!(websocket_path("/v1/agent/ws?node_id=lab-a"));
        assert!(!websocket_path("/v1/agent/ws-extra?node_id=lab-a"));
    }

    #[test]
    fn revoked_node_cannot_accept_task() {
        let state = state();
        assert_eq!(
            create_node("{\"node_id\":\"a\",\"name\":\"A\"}", &state).0,
            "201 Created"
        );
        assert_eq!(revoke_node("a", &state).0, "200 OK");
        assert_eq!(
            create_task("{\"node_id\":\"a\",\"ability\":\"file.read\"}", &state).0,
            "409 Conflict"
        );
    }

    #[test]
    fn node_ids_follow_agent_identifier_rules() {
        let state = state();
        assert_eq!(
            create_node("{\"node_id\":\"bad/id\"}", &state).0,
            "400 Bad Request"
        );
        assert_eq!(
            create_node("{\"node_id\":\"bad?node=other\"}", &state).0,
            "400 Bad Request"
        );
        assert_eq!(
            create_node(&format!("{{\"node_id\":\"{}\"}}", "x".repeat(129)), &state).0,
            "400 Bad Request"
        );
    }

    #[test]
    fn store_round_trips_nodes_and_tasks() {
        let dir = std::env::temp_dir().join(format!("nodewe-cp-test-{}", now()));
        let state = State {
            admin_token: "secret".into(),
            grant_secret: "test-grant-secret".into(),
            store: Arc::new(Mutex::new(Store::default())),
            require_approval_records: false,
            policy: Policy::default(),
            oidc: None,
            active_connections: Arc::new(AtomicU64::new(0)),
            _store_lock: None,
            backend: Arc::new(SnapshotBackend {
                data_dir: Some(dir.clone()),
            }),
        };
        assert_eq!(
            create_node("{\"node_id\":\"persisted\",\"name\":\"P\",\"platform\":\"linux\",\"architecture\":\"aarch64\",\"version\":\"0.1.0\",\"labels\":\"gpu,lab\",\"region\":\"cn-east\",\"data_class\":\"research\",\"capacity\":\"gpu=1;ram_gb=64\"}", &state).0,
            "201 Created"
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"persisted\",\"ability\":\"file.read\"}",
                &state
            )
            .0,
            "202 Accepted"
        );
        let loaded = load_store(&dir);
        assert_eq!(loaded.nodes.len(), 1);
        assert_eq!(loaded.nodes[0].platform, "linux");
        assert_eq!(loaded.nodes[0].labels, "gpu,lab");
        assert_eq!(loaded.nodes[0].data_class, "research");
        assert_eq!(loaded.tasks.len(), 1);
        assert!(loaded.audit.iter().any(|item| item.event == "node.created"));
        assert!(dir.join("store.snapshot").is_file());
        assert!(dir.join("store.snapshot.bak").is_file());
        let audit_response = route("GET", "/v1/audit", "", true, true, &state).1;
        assert!(audit_response.contains("\"prev_hash\":\"GENESIS\""));
        assert!(audit_response.contains("\"hash\":\""));
        let snapshot = read_store_text(&dir.join("store.snapshot")).unwrap();
        let tampered = snapshot.replace("node.created", "node.tampered");
        assert!(parse_snapshot(&tampered).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn revoked_node_rejects_heartbeat() {
        let state = state();
        assert_eq!(create_node("{\"node_id\":\"hb\"}", &state).0, "201 Created");
        assert_eq!(revoke_node("hb", &state).0, "200 OK");
        assert_eq!(heartbeat("{\"node_id\":\"hb\"}", &state).0, "403 Forbidden");
    }

    #[test]
    fn heartbeat_negotiates_known_capabilities_and_rejects_unknown_protocol_or_ability() {
        let state = state();
        assert_eq!(
            create_node("{\"node_id\":\"negotiation\"}", &state).0,
            "201 Created"
        );
        let response = heartbeat(
            "{\"protocol_version\":1,\"node_id\":\"negotiation\",\"abilities\":\"task.exec,file.read,task.exec\"}",
            &state,
        );
        assert_eq!(response.0, "200 OK");
        assert!(response.1.contains("\"protocol_version\":1"));
        assert!(response
            .1
            .contains("\"negotiated_abilities\":[\"task.exec\",\"file.read\"]"));
        assert_eq!(
            heartbeat(
                "{\"protocol_version\":2,\"node_id\":\"negotiation\",\"abilities\":\"file.read\"}",
                &state,
            )
            .0,
            "426 Upgrade Required"
        );
        assert_eq!(
            heartbeat(
                "{\"protocol_version\":1,\"node_id\":\"negotiation\",\"abilities\":\"desktop.control\"}",
                &state,
            )
            .0,
            "422 Unprocessable Entity"
        );
    }

    #[test]
    fn revoking_node_cancels_queued_tasks_and_audits_each_task() {
        let state = state();
        assert_eq!(
            create_node("{\"node_id\":\"revoke-tasks\"}", &state).0,
            "201 Created"
        );
        let (_, task_json) = create_task(
            "{\"node_id\":\"revoke-tasks\",\"ability\":\"file.read\"}",
            &state,
        );
        let task_id = json_field(&task_json, "task_id").unwrap();
        assert_eq!(revoke_node("revoke-tasks", &state).0, "200 OK");
        let store = state.store.lock().unwrap();
        assert_eq!(store.tasks[0].state, "cancelled");
        assert_eq!(store.tasks[0].lease_until, 0);
        assert!(store.audit.iter().any(|item| {
            item.event == "task.cancelled_by_node_revoke"
                && item.task_id.as_deref() == Some(task_id.as_str())
        }));
    }

    #[test]
    fn credential_rotation_invalidates_old_credential() {
        let state = state();
        let (_, node_json) = create_node("{\"node_id\":\"rotate\"}", &state);
        let old_credential = json_field(&node_json, "credential").unwrap();
        let (_, rotated_json) = rotate_node("rotate", &state);
        let new_credential = json_field(&rotated_json, "credential").unwrap();
        assert_ne!(old_credential, new_credential);
        assert!(!credential_authorized(
            &state.store,
            "/v1/agent/heartbeat",
            "{\"node_id\":\"rotate\"}",
            &old_credential,
        ));
        assert!(credential_authorized(
            &state.store,
            "/v1/agent/heartbeat",
            "{\"node_id\":\"rotate\"}",
            &new_credential,
        ));
        assert!(state
            .store
            .lock()
            .unwrap()
            .audit
            .iter()
            .any(|item| item.event == "node.credential_rotated"));
    }

    #[test]
    fn idempotency_key_does_not_duplicate_task() {
        let state = state();
        assert_eq!(
            create_node("{\"node_id\":\"idem\"}", &state).0,
            "201 Created"
        );
        let body = "{\"node_id\":\"idem\",\"ability\":\"file.read\",\"idempotency_key\":\"k1\"}";
        let first = create_task(body, &state);
        let second = create_task(body, &state);
        assert_eq!(first.0, "202 Accepted");
        assert_eq!(second.0, "200 OK");
        assert_eq!(state.store.lock().unwrap().tasks.len(), 1);
    }

    #[test]
    fn idempotency_key_cannot_change_task_target_or_payload() {
        let state = state();
        create_node("{\"node_id\":\"idem-a\"}", &state);
        create_node("{\"node_id\":\"idem-b\"}", &state);
        assert_eq!(
            create_task(
                "{\"node_id\":\"idem-a\",\"ability\":\"file.read\",\"idempotency_key\":\"same\"}",
                &state,
            )
            .0,
            "202 Accepted"
        );
        let (_, conflict) = create_task(
            "{\"node_id\":\"idem-b\",\"ability\":\"file.read\",\"idempotency_key\":\"same\"}",
            &state,
        );
        assert!(conflict.contains("idempotency_conflict"));
    }

    #[test]
    fn idempotency_key_cannot_change_actor_or_timeout() {
        let state = state();
        create_node("{\"node_id\":\"idem-actor\"}", &state);
        assert_eq!(
            create_task(
                "{\"node_id\":\"idem-actor\",\"ability\":\"file.read\",\"idempotency_key\":\"same-actor\",\"actor\":\"operator\",\"timeout_ms\":30000}",
                &state,
            )
            .0,
            "202 Accepted"
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"idem-actor\",\"ability\":\"file.read\",\"idempotency_key\":\"same-actor\",\"actor\":\"automation\",\"timeout_ms\":30000}",
                &state,
            )
            .0,
            "409 Conflict"
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"idem-actor\",\"ability\":\"file.read\",\"idempotency_key\":\"same-actor\",\"actor\":\"operator\",\"timeout_ms\":60000}",
                &state,
            )
            .0,
            "409 Conflict"
        );
    }

    #[test]
    fn pairing_grant_is_single_use_and_credential_authenticates_heartbeat() {
        let state = state();
        let (_, grant_json) = create_grant(&state);
        let code = json_field(&grant_json, "grant_code").unwrap();
        let signature = json_field(&grant_json, "grant_signature").unwrap();
        let (_, node_json) = redeem_grant(
            &format!("{{\"grant_code\":\"{code}\",\"grant_signature\":\"{signature}\",\"node_id\":\"paired\"}}"),
            &state,
        );
        assert!(node_json.contains("credential"));
        let credential = json_field(&node_json, "credential").unwrap();
        assert_eq!(heartbeat("{\"node_id\":\"paired\"}", &state).0, "200 OK");
        let (_, second) = redeem_grant(
            &format!("{{\"grant_code\":\"{code}\",\"grant_signature\":\"{signature}\",\"node_id\":\"paired-2\"}}"),
            &state,
        );
        assert!(second.contains("grant_invalid_or_expired") || second.contains("node_exists"));
        assert!(credential_authorized(
            &state.store,
            "/v1/agent/heartbeat",
            "{\"node_id\":\"paired\"}",
            &credential
        ));
    }

    #[test]
    fn grant_list_and_revoke_are_persistent_and_block_redeem() {
        let state = state();
        let (_, grant_json) = create_grant(&state);
        let code = json_field(&grant_json, "grant_code").unwrap();
        let signature = json_field(&grant_json, "grant_signature").unwrap();
        let (status, listed) = route("GET", "/v1/grants", "", true, true, &state);
        assert_eq!(status, "200 OK");
        assert!(listed.contains(&code));
        assert_eq!(
            route(
                "POST",
                &format!("/v1/grants/{code}/revoke"),
                "",
                true,
                true,
                &state,
            )
            .0,
            "200 OK"
        );
        assert_eq!(
            redeem_grant(
                &format!(
                    "{{\"grant_code\":\"{code}\",\"grant_signature\":\"{signature}\",\"node_id\":\"revoked-grant\"}}"
                ),
                &state,
            )
            .0,
            "403 Forbidden"
        );
        let (_, listed) = route("GET", "/v1/grants", "", true, true, &state);
        assert!(listed.contains("\"revoked\":true"));
    }

    #[test]
    fn used_grant_stays_used_after_reload() {
        let dir = std::env::temp_dir().join(format!("nodewe-grant-test-{}", now()));
        let state = State {
            admin_token: "secret".into(),
            grant_secret: "test-grant-secret".into(),
            store: Arc::new(Mutex::new(Store::default())),
            require_approval_records: false,
            policy: Policy::default(),
            oidc: None,
            active_connections: Arc::new(AtomicU64::new(0)),
            _store_lock: None,
            backend: Arc::new(SnapshotBackend {
                data_dir: Some(dir.clone()),
            }),
        };
        let (_, grant_json) = create_grant(&state);
        let code = json_field(&grant_json, "grant_code").unwrap();
        let signature = json_field(&grant_json, "grant_signature").unwrap();
        assert_eq!(
            redeem_grant(
                &format!("{{\"grant_code\":\"{code}\",\"grant_signature\":\"{signature}\",\"node_id\":\"one\"}}"),
                &state
            )
            .0,
            "201 Created"
        );
        let loaded = load_store(&dir);
        assert!(loaded
            .grants
            .iter()
            .any(|grant| grant.code == code && grant.used));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn task_ability_is_allowlisted_and_high_risk_needs_approval() {
        let state = state();
        assert_eq!(
            create_node("{\"node_id\":\"policy\"}", &state).0,
            "201 Created"
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"policy\",\"ability\":\"desktop.control\"}",
                &state
            )
            .0,
            "403 Forbidden"
        );
        assert_eq!(
            create_task("{\"node_id\":\"policy\",\"ability\":\"task.exec\"}", &state).0,
            "428 Precondition Required"
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"policy\",\"ability\":\"task.exec\",\"approved\":true}",
                &state
            )
            .0,
            "202 Accepted"
        );
    }

    #[test]
    fn policy_file_shape_and_data_class_gate_are_fail_closed() {
        let mut state = state();
        state.policy.allowed_abilities = vec!["file.read".into()];
        state.policy.allowed_data_classes = vec!["restricted".into()];
        create_node(
            "{\"node_id\":\"policy-gated\",\"data_class\":\"research\"}",
            &state,
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"policy-gated\",\"ability\":\"file.read\"}",
                &state
            )
            .0,
            "403 Forbidden"
        );
        state.policy.allowed_data_classes = vec!["research".into()];
        assert_eq!(
            create_task(
                "{\"node_id\":\"policy-gated\",\"ability\":\"task.exec\",\"approved\":true}",
                &state
            )
            .0,
            "403 Forbidden"
        );
        state.policy.allowed_abilities = vec!["file.read".into(), "task.exec".into()];
        state.policy.allowed_paths = vec!["safe".into()];
        state.policy.allowed_commands = vec!["echo".into()];
        assert_eq!(
            create_task(
                "{\"node_id\":\"policy-gated\",\"ability\":\"file.read\",\"program\":\"outside/input\"}",
                &state
            )
            .0,
            "403 Forbidden"
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"policy-gated\",\"ability\":\"task.exec\",\"program\":\"pwd\",\"approved\":true}",
                &state
            )
            .0,
            "403 Forbidden"
        );
        assert!(state
            .store
            .lock()
            .unwrap()
            .audit
            .iter()
            .all(|item| item.event != "policy.allowed"));
    }

    #[test]
    fn task_timeout_is_bounded_and_persisted() {
        let state = state();
        create_node("{\"node_id\":\"timeout\"}", &state);
        assert_eq!(
            create_task(
                "{\"node_id\":\"timeout\",\"ability\":\"file.read\",\"timeout_ms\":0}",
                &state,
            )
            .0,
            "400 Bad Request"
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"timeout\",\"ability\":\"file.read\",\"timeout_ms\":300001}",
                &state,
            )
            .0,
            "400 Bad Request"
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"timeout\",\"ability\":\"file.read\",\"timeout_ms\":\"30000\"}",
                &state,
            )
            .0,
            "400 Bad Request"
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"timeout\",\"ability\":\"file.read\",\"idempotency_key\":123}",
                &state,
            )
            .0,
            "400 Bad Request"
        );
        let (status, task) = create_task(
            "{\"node_id\":\"timeout\",\"ability\":\"file.read\",\"timeout_ms\":45000}",
            &state,
        );
        assert_eq!(status, "202 Accepted");
        assert!(task.contains("\"timeout_ms\":45000"));
    }

    #[test]
    fn audit_export_is_paginated_and_keeps_chain_fields() {
        let state = state();
        create_node("{\"node_id\":\"audit-export\"}", &state);
        create_task(
            "{\"node_id\":\"audit-export\",\"ability\":\"file.read\"}",
            &state,
        );
        let (status, page) = route(
            "GET",
            "/v1/audit/export?from=0&limit=1",
            "",
            true,
            true,
            &state,
        );
        assert_eq!(status, "200 OK");
        assert!(page.contains("\"count\":1"));
        assert!(page.contains("\"next\":1"));
        assert!(page.contains("\"prev_hash\":\"GENESIS\""));
        assert!(page.contains("\"hash\":\""));
        assert_eq!(
            route("GET", "/v1/audit/export?limit=0", "", true, true, &state,).0,
            "400 Bad Request"
        );
        assert_eq!(
            route("GET", "/v1/audit/export?from=999", "", true, true, &state,).0,
            "416 Range Not Satisfiable"
        );
    }

    #[test]
    fn audit_records_bind_authenticated_actor_and_chain_covers_it() {
        let state = state();
        create_node("{\"node_id\":\"actor-audit\"}", &state);
        assert_eq!(
            create_task_as(
                "{\"node_id\":\"actor-audit\",\"ability\":\"file.read\"}",
                &state,
                Some("auth0|alice@example.com"),
            )
            .0,
            "202 Accepted"
        );
        let store = state.store.lock().unwrap();
        let accepted = store
            .audit
            .iter()
            .find(|item| item.event == "task.accepted")
            .expect("accepted activity");
        assert_eq!(accepted.actor.as_deref(), Some("auth0|alice@example.com"));
        assert!(
            sealed_activity_json(&store.audit, 1).contains("\"actor\":\"auth0|alice@example.com\"")
        );
        assert!(audit_chain_valid(&store.audit));
    }

    #[test]
    fn durable_approval_records_gate_high_risk_tasks_and_are_single_use() {
        let mut state = state();
        state.require_approval_records = true;
        create_node("{\"node_id\":\"approval-node\"}", &state);
        assert_eq!(
            create_task(
                "{\"node_id\":\"approval-node\",\"ability\":\"task.exec\",\"program\":\"echo\",\"argument\":\"ok\"}",
                &state,
            )
            .0,
            "428 Precondition Required"
        );
        let (_, approval_json) = create_approval(
            "{\"node_id\":\"approval-node\",\"ability\":\"task.exec\",\"program\":\"echo\",\"argument\":\"ok\",\"actor\":\"operator\"}",
            &state,
        );
        let approval_id = json_field(&approval_json, "approval_id").unwrap();
        let task_body = format!(
            "{{\"node_id\":\"approval-node\",\"ability\":\"task.exec\",\"program\":\"echo\",\"argument\":\"ok\",\"actor\":\"operator\",\"approval_id\":\"{approval_id}\"}}"
        );
        assert_eq!(create_task(&task_body, &state).0, "202 Accepted");
        assert_eq!(create_task(&task_body, &state).0, "403 Forbidden");
        assert!(state
            .store
            .lock()
            .unwrap()
            .approvals
            .iter()
            .any(|approval| approval.id == approval_id && approval.used));
    }

    #[test]
    fn approval_records_cannot_be_consumed_by_another_actor() {
        let mut state = state();
        state.require_approval_records = true;
        create_node("{\"node_id\":\"approval-actor\"}", &state);
        let (_, approval_json) = create_approval(
            "{\"node_id\":\"approval-actor\",\"ability\":\"task.exec\",\"program\":\"echo\",\"argument\":\"ok\",\"actor\":\"alice\"}",
            &state,
        );
        let approval_id = json_field(&approval_json, "approval_id").unwrap();
        let task_body = format!(
            "{{\"node_id\":\"approval-actor\",\"ability\":\"task.exec\",\"program\":\"echo\",\"argument\":\"ok\",\"actor\":\"bob\",\"approval_id\":\"{approval_id}\"}}"
        );
        assert_eq!(create_task(&task_body, &state).0, "403 Forbidden");
        assert!(!state
            .store
            .lock()
            .unwrap()
            .approvals
            .iter()
            .any(|approval| approval.id == approval_id && approval.used));
    }

    #[test]
    fn task_requires_declared_node_ability() {
        let state = state();
        assert_eq!(
            create_node("{\"node_id\":\"cap\"}", &state).0,
            "201 Created"
        );
        state.store.lock().unwrap().nodes[0].abilities = "file.read".into();
        assert_eq!(
            create_task(
                "{\"node_id\":\"cap\",\"ability\":\"system.inspect\"}",
                &state
            )
            .0,
            "403 Forbidden"
        );
    }

    #[test]
    fn sha256_matches_standard_abc_vector() {
        let digest = sha256(b"abc");
        let encoded: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            encoded,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_vector() {
        let key = [0x0b_u8; 20];
        let digest = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex_encode_bytes(&digest),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn encrypted_store_round_trips_and_rejects_tampering() {
        let key = [7_u8; 32];
        let encrypted = encrypt_store(b"nodewe-secret-state", &key).unwrap();
        assert!(encrypted.starts_with(STORE_MAGIC));
        assert_eq!(
            decrypt_store(&encrypted, &key).unwrap(),
            b"nodewe-secret-state"
        );
        let mut tampered = encrypted.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decrypt_store(&tampered, &key).is_err());
    }

    #[test]
    fn expired_dispatch_lease_can_be_reclaimed() {
        let state = state();
        assert_eq!(
            create_node("{\"node_id\":\"lease\"}", &state).0,
            "201 Created"
        );
        assert_eq!(
            create_task("{\"node_id\":\"lease\",\"ability\":\"file.read\"}", &state).0,
            "202 Accepted"
        );
        let first_dispatch = agent_tasks("/v1/agent/tasks?node_id=lease", &state).1;
        let first_token = first_array_field(&first_dispatch, "lease_token").unwrap();
        state.store.lock().unwrap().tasks[0].lease_until = 1;
        let second_dispatch = agent_tasks("/v1/agent/tasks?node_id=lease", &state).1;
        let second_token = first_array_field(&second_dispatch, "lease_token").unwrap();
        assert_ne!(first_token, second_token);
        let task_id = first_array_field(&second_dispatch, "task_id").unwrap();
        assert_eq!(
            agent_result(
                &format!("/v1/agent/tasks/{task_id}/result"),
                &format!("{{\"node_id\":\"lease\",\"lease_token\":\"{first_token}\",\"state\":\"succeeded\"}}"),
                &state,
            )
            .0,
            "409 Conflict"
        );
    }

    #[test]
    fn queued_task_can_be_cancelled_and_is_audited() {
        let state = state();
        assert_eq!(
            create_node("{\"node_id\":\"cancel\"}", &state).0,
            "201 Created"
        );
        let (_, task) = create_task("{\"node_id\":\"cancel\",\"ability\":\"file.read\"}", &state);
        let task_id = json_field(&task, "task_id").unwrap();
        assert_eq!(
            cancel_task(&format!("/v1/tasks/{task_id}/cancel"), &state).0,
            "200 OK"
        );
        assert_eq!(state.store.lock().unwrap().tasks[0].state, "cancelled");
        assert!(state
            .store
            .lock()
            .unwrap()
            .audit
            .iter()
            .any(|item| item.event == "task.cancelled"));
    }

    #[test]
    fn task_can_be_fetched_by_id_for_background_cli_operations() {
        let state = state();
        create_node("{\"node_id\":\"fetch\"}", &state);
        let (_, task) = create_task("{\"node_id\":\"fetch\",\"ability\":\"file.read\"}", &state);
        let task_id = json_field(&task, "task_id").unwrap();
        let (status, fetched) = get_task(&format!("/v1/tasks/{task_id}"), &state);
        assert_eq!(status, "200 OK");
        assert!(fetched.contains(&task_id));
        assert_eq!(
            get_task("/v1/tasks/does-not-exist", &state).0,
            "404 Not Found"
        );
    }

    #[test]
    fn task_execution_fields_survive_reload() {
        let dir = std::env::temp_dir().join(format!("nodewe-task-fields-{}", now()));
        let state = State {
            admin_token: "secret".into(),
            grant_secret: "test-grant-secret".into(),
            store: Arc::new(Mutex::new(Store::default())),
            require_approval_records: false,
            policy: Policy::default(),
            oidc: None,
            active_connections: Arc::new(AtomicU64::new(0)),
            _store_lock: None,
            backend: Arc::new(SnapshotBackend {
                data_dir: Some(dir.clone()),
            }),
        };
        create_node("{\"node_id\":\"fields\"}", &state);
        let (_, task_json) = create_task(
            "{\"node_id\":\"fields\",\"ability\":\"task.exec\",\"approved\":true,\"program\":\"printf\",\"argument\":\"hello\\nworld\",\"timeout_ms\":45000,\"output_limit\":1024}",
            &state,
        );
        let task_id = json_field(&task_json, "task_id").unwrap();
        assert_eq!(
            create_task(
                "{\"node_id\":\"fields\",\"ability\":\"task.exec\",\"approved\":true,\"output_limit\":0}",
                &state,
            )
            .0,
            "400 Bad Request"
        );
        assert_eq!(
            create_task(
                "{\"node_id\":\"fields\",\"ability\":\"task.exec\",\"approved\":true,\"output_limit\":1048577}",
                &state,
            )
            .0,
            "400 Bad Request"
        );
        let (_, dispatched) = agent_tasks("/v1/agent/tasks?node_id=fields", &state);
        let lease_token = first_array_field(&dispatched, "lease_token").unwrap();
        agent_result(
            &format!("/v1/agent/tasks/{task_id}/result"),
            &format!("{{\"node_id\":\"fields\",\"lease_token\":\"{lease_token}\",\"state\":\"succeeded\",\"output\":\"ok\\nvalue\",\"exit_code\":\"0\"}}"),
            &state,
        );
        let loaded = load_store(&dir);
        let task = &loaded.tasks[0];
        assert_eq!(task.program, "printf");
        assert_eq!(task.argument, "hello\nworld");
        assert_eq!(task.output, "ok\nvalue");
        assert_eq!(task.output_sha256, hex_encode_bytes(&sha256(b"ok\nvalue")));
        assert!(!task.output_truncated);
        assert_eq!(task.output_limit, 1024);
        assert_eq!(task.exit_code, Some(0));
        assert_eq!(task.timeout_ms, 45_000);

        let (_, large_task_json) = create_task(
            "{\"node_id\":\"fields\",\"ability\":\"task.exec\",\"approved\":true}",
            &state,
        );
        let large_task_id = json_field(&large_task_json, "task_id").unwrap();
        let (_, dispatched) = agent_tasks("/v1/agent/tasks?node_id=fields", &state);
        let large_lease_token = dispatched
            .split('{')
            .filter_map(|object| {
                object
                    .split_once('}')
                    .map(|(body, _)| format!("{{{body}}}"))
            })
            .find_map(|object| {
                (json_field(&object, "task_id").as_deref() == Some(large_task_id.as_str()))
                    .then(|| json_field(&object, "lease_token"))
                    .flatten()
            })
            .expect("large task lease");
        let large_output = "你".repeat((MAX_PERSISTED_OUTPUT_BYTES / 3) + 1);
        let large_body = format!(
            "{{\"node_id\":\"fields\",\"lease_token\":\"{large_lease_token}\",\"state\":\"succeeded\",\"output\":\"{large_output}\"}}"
        );
        assert_eq!(
            agent_result(
                &format!("/v1/agent/tasks/{large_task_id}/result"),
                &large_body,
                &state,
            )
            .0,
            "200 OK"
        );
        let loaded = load_store(&dir);
        let large_task = loaded
            .tasks
            .iter()
            .find(|task| task.id == large_task_id)
            .expect("large task persisted");
        assert_eq!(large_task.output.len(), MAX_PERSISTED_OUTPUT_BYTES - 1);
        assert!(large_task.output_truncated);
        assert_eq!(
            large_task.output_sha256,
            hex_encode_bytes(&sha256(large_output.as_bytes()))
        );
        let _ = fs::remove_dir_all(dir);
    }

    fn test_oidc_token(config: &OidcConfig, subject: &str, groups: &str, exp: u64) -> String {
        let header = base64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64url_encode(
            format!(
                "{{\"iss\":\"{}\",\"aud\":\"{}\",\"sub\":\"{}\",\"groups\":[{}],\"exp\":{}}}",
                esc(&config.issuer),
                esc(&config.audience),
                esc(subject),
                groups,
                exp
            )
            .as_bytes(),
        );
        let signing_input = format!("{header}.{payload}");
        let signature =
            base64url_encode(&hmac_sha256(&config.hmac_secret, signing_input.as_bytes()));
        format!("{signing_input}.{signature}")
    }

    #[test]
    fn oidc_hs256_claims_are_verified_and_bind_actor() {
        let config = OidcConfig {
            issuer: "https://issuer.example".into(),
            audience: "nodewe-cli".into(),
            hmac_secret: b"01234567890123456789012345678901".to_vec(),
            admin_group: "nodewe-admin".into(),
            group_claim: "groups".into(),
        };
        let token = test_oidc_token(
            &config,
            "auth0|alice@example.com",
            "\"nodewe-admin\",\"research\"",
            now() / 1_000 + 60,
        );
        let claims = validate_oidc_token(&token, &config).expect("valid OIDC token");
        assert_eq!(claims.subject, "auth0|alice@example.com");
        assert!(claims.groups.iter().any(|group| group == "nodewe-admin"));
        let mut state = state();
        state.oidc = Some(config);
        let context = authenticate_request(&state, "/v1/tasks", "", &token);
        assert!(context.authorized);
        assert!(context.admin);
        assert_eq!(context.actor.as_deref(), Some("auth0|alice@example.com"));
        create_node("{\"node_id\":\"oidc-node\"}", &state);
        let (status, task) = route_with_actor(
            "POST",
            "/v1/tasks",
            "{\"node_id\":\"oidc-node\",\"ability\":\"file.read\"}",
            context.authorized,
            context.admin,
            context.actor.as_deref(),
            &state,
        );
        assert_eq!(status, "202 Accepted");
        assert_eq!(
            json_field(&task, "actor").as_deref(),
            Some("auth0|alice@example.com")
        );
        let task_id = json_field(&task, "task_id").expect("task id");
        assert_eq!(
            route_with_actor(
                "POST",
                &format!("/v1/tasks/{task_id}/cancel"),
                "",
                true,
                false,
                Some("bob"),
                &state,
            )
            .0,
            "403 Forbidden"
        );
        assert_eq!(
            route_with_actor(
                "POST",
                &format!("/v1/tasks/{task_id}/cancel"),
                "",
                true,
                false,
                Some("auth0|alice@example.com"),
                &state,
            )
            .0,
            "200 OK"
        );
        assert_eq!(
            route_with_actor(
                "POST",
                "/v1/tasks",
                "{\"node_id\":\"oidc-node\",\"ability\":\"file.read\",\"actor\":\"bob\"}",
                true,
                true,
                Some("alice"),
                &state,
            )
            .0,
            "403 Forbidden"
        );
    }

    #[test]
    fn oidc_rejects_bad_signature_issuer_and_expiry() {
        let config = OidcConfig {
            issuer: "https://issuer.example".into(),
            audience: "nodewe-cli".into(),
            hmac_secret: b"01234567890123456789012345678901".to_vec(),
            admin_group: "nodewe-admin".into(),
            group_claim: "groups".into(),
        };
        let valid = test_oidc_token(&config, "alice", "\"nodewe-admin\"", now() / 1_000 + 60);
        let mut pieces = valid.split('.').map(str::to_owned).collect::<Vec<_>>();
        let replacement = if pieces[2].starts_with('A') { "B" } else { "A" };
        pieces[2].replace_range(0..1, replacement);
        assert!(validate_oidc_token(&pieces.join("."), &config).is_none());
        let wrong_issuer = OidcConfig {
            issuer: "https://other.example".into(),
            ..config.clone()
        };
        assert!(validate_oidc_token(&valid, &wrong_issuer).is_none());
        let expired = test_oidc_token(&config, "alice", "\"nodewe-admin\"", now() / 1_000 - 1);
        assert!(validate_oidc_token(&expired, &config).is_none());
    }

    #[test]
    fn stale_nodes_are_not_available_for_new_tasks() {
        let state = state();
        assert_eq!(
            create_node(r#"{"node_id":"stale-node"}"#, &state).0,
            "201 Created"
        );
        state.store.lock().unwrap().nodes[0].last_seen = 1;
        let (status, body) = create_task(
            r#"{"node_id":"stale-node","ability":"file.read","program":"x"}"#,
            &state,
        );
        assert_eq!(status, "409 Conflict");
        assert!(body.contains("node_unavailable"));
    }

    #[test]
    fn store_lock_prevents_concurrent_snapshot_writers() {
        let dir = std::env::temp_dir().join(format!("nodewe-store-lock-{}", now()));
        let first = acquire_store_lock(&dir).expect("first writer acquires lock");
        assert!(acquire_store_lock(&dir).is_err());
        drop(first);
        let second = acquire_store_lock(&dir).expect("lock is released on shutdown");
        drop(second);
        let _ = fs::remove_dir_all(dir);
    }
}
