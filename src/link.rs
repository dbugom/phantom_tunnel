//! Shareable connect links.
//!
//! A connect link carries everything a client needs to reach a server, in one
//! line that can be pasted into a chat or a terminal:
//!
//! ```text
//! phantom://SERVER_KEY@host:port?backup=[KEY@]host:port&key=CLIENT_KEY#label
//! ```
//!
//! - `SERVER_KEY` — the server's public key (required).
//! - `backup` — zero or more fallback servers, tried in order. A backup without
//!   its own `KEY@` uses the primary server's key.
//! - `key` — optional. The **client's private key**. A link with a key is a
//!   credential: whoever has it can use the tunnel as that client. A link
//!   without one is not secret; the importing client generates its own key and
//!   the admin then adds that public key to `allowed_clients`.
//! - `label` — optional name for the person or device, for display only.
//!
//! Keys are base64url without padding (43 characters). The parser also accepts
//! standard base64, with or without padding. Unknown query parameters are
//! ignored so that later versions can add fields.

use crate::config::{BackupServer, ClientConfig};
use crate::crypto::{KeyPair, PrivateKey, PublicKey, KEY_LEN};
use base64::Engine;
use std::fmt;

/// URI scheme of a connect link.
pub const SCHEME: &str = "phantom";

/// Most backup servers a link may list.
pub const MAX_BACKUPS: usize = 16;

/// Longest label kept, in characters.
const MAX_LABEL_CHARS: usize = 64;

/// Errors from parsing a connect link.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("not a phantom:// link")]
    WrongScheme,
    #[error("link has no server key (expected phantom://KEY@host:port)")]
    MissingServerKey,
    #[error("invalid {what} key: {why}")]
    BadKey { what: &'static str, why: String },
    #[error("invalid {what} address '{addr}': {why}")]
    BadAddress {
        what: &'static str,
        addr: String,
        why: &'static str,
    },
    #[error("link lists more than {MAX_BACKUPS} backup servers")]
    TooManyBackups,
    #[error("link contains more than one client key")]
    DuplicateKey,
    #[error("parameter '{0}' has an empty value")]
    EmptyValue(String),
    #[error("bad percent-encoding in link")]
    BadEncoding,
}

/// A server reachable through a link: address plus, for backups, an optional
/// key of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkServer {
    /// `host:port` (IPv6 hosts in brackets).
    pub address: String,
    /// Server public key; `None` on a backup means "same as the primary".
    pub public_key: Option<PublicKey>,
}

/// A parsed connect link.
#[derive(Debug, Clone)]
pub struct ConnectLink {
    /// Primary server address, `host:port`.
    pub server: String,
    /// Primary server public key.
    pub server_public_key: PublicKey,
    /// Fallback servers, in the order to try them.
    pub backups: Vec<LinkServer>,
    /// The client's private key, when the admin issued one.
    pub client_private_key: Option<PrivateKey>,
    /// Display label (person or device).
    pub label: Option<String>,
}

/// Where the client key in an imported config came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// The link carried a key issued by the admin.
    FromLink,
    /// The existing config's key was kept (identity unchanged).
    Kept,
    /// A new key pair was generated; its public key must be authorised.
    Generated,
}

impl ConnectLink {
    /// Parse a link. Surrounding whitespace, quotes and `<...>` are ignored.
    pub fn parse(input: &str) -> Result<Self, LinkError> {
        let s = strip_wrapping(input.trim());

        let rest = s
            .split_once("://")
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case(SCHEME))
            .map(|(_, rest)| rest)
            .ok_or(LinkError::WrongScheme)?;

        let (rest, fragment) = match rest.split_once('#') {
            Some((r, f)) => (r, Some(f)),
            None => (rest, None),
        };
        let (authority, query) = match rest.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (rest, None),
        };
        // Tolerate a trailing slash (some apps add one when linkifying).
        let authority = authority.trim_end_matches('/');

        let (key_part, addr_part) = authority
            .split_once('@')
            .ok_or(LinkError::MissingServerKey)?;
        if key_part.is_empty() {
            return Err(LinkError::MissingServerKey);
        }
        let server_public_key = PublicKey(decode_key(&percent_decode(key_part)?, "server")?);
        let server = percent_decode(addr_part)?;
        validate_address(&server, "server")?;

        let mut backups = Vec::new();
        let mut client_private_key = None;
        for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            match name {
                "backup" => {
                    if value.is_empty() {
                        return Err(LinkError::EmptyValue(name.into()));
                    }
                    if backups.len() == MAX_BACKUPS {
                        return Err(LinkError::TooManyBackups);
                    }
                    backups.push(parse_backup(&percent_decode(value)?)?);
                }
                "key" => {
                    if value.is_empty() {
                        return Err(LinkError::EmptyValue(name.into()));
                    }
                    if client_private_key.is_some() {
                        return Err(LinkError::DuplicateKey);
                    }
                    let bytes = decode_key(&percent_decode(value)?, "client")?;
                    client_private_key = Some(PrivateKey(bytes));
                }
                // Forward compatibility: ignore parameters we don't know.
                _ => {}
            }
        }

        let label = match fragment {
            Some(f) => clean_label(&percent_decode(f)?),
            None => None,
        };

        Ok(Self {
            server,
            server_public_key,
            backups,
            client_private_key,
            label,
        })
    }

    /// Build a link from a client config. The client's private key is included
    /// only when `include_client_key` is true.
    pub fn from_client_config(
        cfg: &ClientConfig,
        include_client_key: bool,
    ) -> Result<Self, crate::Error> {
        let bad = |what: &str, e: crate::crypto::CryptoError| {
            crate::Error::Config(format!("{}: {}", what, e))
        };
        let server_public_key = PublicKey::from_base64(&cfg.server_public_key)
            .map_err(|e| bad("server_public_key", e))?;
        let mut backups = Vec::new();
        for b in &cfg.backup_servers {
            let public_key = if b.public_key.is_empty() {
                None
            } else {
                Some(
                    PublicKey::from_base64(&b.public_key)
                        .map_err(|e| bad(&format!("backup server {}", b.address), e))?,
                )
            };
            backups.push(LinkServer {
                address: b.address.clone(),
                public_key,
            });
        }
        let client_private_key = if include_client_key && !cfg.private_key.is_empty() {
            Some(PrivateKey::from_base64(&cfg.private_key).map_err(|e| bad("private_key", e))?)
        } else {
            None
        };
        Ok(Self {
            server: cfg.server.clone(),
            server_public_key,
            backups,
            client_private_key,
            label: None,
        })
    }

    /// True when the link carries a client private key (and is therefore a
    /// credential that must be shared privately).
    pub fn has_client_key(&self) -> bool {
        self.client_private_key.is_some()
    }

    /// The client public key that must be in the server's `allowed_clients`,
    /// when the link carries a client key.
    pub fn client_public_key(&self) -> Option<PublicKey> {
        self.client_private_key.as_ref().map(PrivateKey::public_key)
    }

    /// Produce the client config for this link.
    ///
    /// `existing` is the config already on disk, if any. Its local settings
    /// (proxy listen addresses) are kept, and so is its key pair unless the
    /// link brings a key of its own — re-importing an updated link (say, with a
    /// new backup server) must not change the device's identity.
    pub fn to_client_config(
        &self,
        existing: Option<&ClientConfig>,
    ) -> Result<(ClientConfig, KeySource), crate::Error> {
        let mut cfg = existing.cloned().unwrap_or_default();
        cfg.server = self.server.clone();
        cfg.server_public_key = self.server_public_key.to_base64();
        cfg.backup_servers = self
            .backups
            .iter()
            .map(|b| BackupServer {
                address: b.address.clone(),
                public_key: b
                    .public_key
                    .as_ref()
                    .map(PublicKey::to_base64)
                    .unwrap_or_default(),
            })
            .collect();

        let existing_pair = existing
            .filter(|c| !c.private_key.is_empty())
            .and_then(|c| PrivateKey::from_base64(&c.private_key).ok())
            .map(KeyPair::from_private);

        let (pair, source) = match (&self.client_private_key, existing_pair) {
            (Some(k), _) => (KeyPair::from_private(k.clone()), KeySource::FromLink),
            (None, Some(p)) => (p, KeySource::Kept),
            (None, None) => (KeyPair::generate()?, KeySource::Generated),
        };
        cfg.private_key = pair.private.to_base64();
        cfg.public_key = pair.public.to_base64();
        Ok((cfg, source))
    }
}

impl fmt::Display for ConnectLink {
    /// The link text. Includes the client private key if the link has one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}@{}",
            SCHEME,
            encode_key(self.server_public_key.as_bytes()),
            // Brackets around an IPv6 host are legal in the authority.
            percent_encode_with(&self.server, b"[]")
        )?;
        let mut sep = '?';
        for b in &self.backups {
            let value = match &b.public_key {
                Some(k) => format!("{}@{}", encode_key(k.as_bytes()), b.address),
                None => b.address.clone(),
            };
            write!(f, "{}backup={}", sep, percent_encode(&value))?;
            sep = '&';
        }
        if let Some(k) = &self.client_private_key {
            write!(f, "{}key={}", sep, encode_key(k.as_bytes()))?;
        }
        if let Some(label) = &self.label {
            write!(f, "#{}", percent_encode(label))?;
        }
        Ok(())
    }
}

/// Parse a `host:port` or `KEY@host:port` backup entry (already decoded).
/// The same syntax is used by `phantom-server link --backup`.
pub fn parse_backup(value: &str) -> Result<LinkServer, LinkError> {
    let (key, address) = match value.split_once('@') {
        Some((k, a)) => (Some(k), a),
        None => (None, value),
    };
    validate_address(address, "backup")?;
    let public_key = match key {
        Some(k) => Some(PublicKey(decode_key(k, "backup server")?)),
        None => None,
    };
    Ok(LinkServer {
        address: address.to_string(),
        public_key,
    })
}

/// Check that `addr` is `host:port`, with IPv6 hosts in brackets.
pub fn validate_address(addr: &str, what: &'static str) -> Result<(), LinkError> {
    let bad = |why| LinkError::BadAddress {
        what,
        addr: addr.to_string(),
        why,
    };
    let (host, port) = if let Some(rest) = addr.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(|| bad("missing ']'"))?;
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| bad("missing :port"))?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(bad("not an IPv6 address inside [...]"));
        }
        (host, port)
    } else {
        let (host, port) = addr.rsplit_once(':').ok_or_else(|| bad("missing :port"))?;
        if host.contains(':') {
            return Err(bad(
                "put IPv6 addresses in brackets, e.g. [2001:db8::1]:8444",
            ));
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(bad("empty host"));
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || "/?#@\\\"'<>".contains(c))
    {
        return Err(bad(
            "host contains characters that cannot appear in a hostname",
        ));
    }
    match port.parse::<u16>() {
        Ok(p) if p != 0 => Ok(()),
        _ => Err(bad("port must be 1-65535")),
    }
}

/// base64url, no padding: the form used inside links.
fn encode_key(bytes: &[u8; KEY_LEN]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a key written in base64url or standard base64, padded or not.
fn decode_key(s: &str, what: &'static str) -> Result<[u8; KEY_LEN], LinkError> {
    let normalised: String = s
        .trim()
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(normalised.as_bytes())
        .map_err(|e| LinkError::BadKey {
            what,
            why: e.to_string(),
        })?;
    bytes.try_into().map_err(|b: Vec<u8>| LinkError::BadKey {
        what,
        why: format!("expected {} bytes, got {}", KEY_LEN, b.len()),
    })
}

/// Percent-encode everything except RFC 3986 unreserved characters and the
/// `:` / `@` separators used inside addresses (both are legal in a query).
fn percent_encode(s: &str) -> String {
    percent_encode_with(s, b"")
}

/// [`percent_encode`], also leaving the bytes in `extra` as they are.
fn percent_encode_with(s: &str, extra: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:@".contains(&b) || extra.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Decode `%XX` escapes. `+` is left alone (it can be a base64 character).
fn percent_decode(s: &str) -> Result<String, LinkError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or(LinkError::BadEncoding)?;
            let hex = std::str::from_utf8(hex).map_err(|_| LinkError::BadEncoding)?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| LinkError::BadEncoding)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| LinkError::BadEncoding)
}

/// Strip one layer of quotes or angle brackets that chat apps and docs add.
fn strip_wrapping(s: &str) -> &str {
    for (open, close) in [('"', '"'), ('\'', '\''), ('<', '>'), ('`', '`')] {
        if let Some(inner) = s.strip_prefix(open).and_then(|r| r.strip_suffix(close)) {
            return inner.trim();
        }
    }
    s
}

/// Keep a label printable and short; empty labels become `None`.
fn clean_label(s: &str) -> Option<String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_LABEL_CHARS)
        .collect();
    let cleaned = cleaned.trim().to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> PublicKey {
        KeyPair::generate().unwrap().public
    }

    #[test]
    fn minimal_link_roundtrips() {
        let pk = key();
        let link = ConnectLink {
            server: "examroom.dbug.om:8444".into(),
            server_public_key: pk.clone(),
            backups: vec![],
            client_private_key: None,
            label: None,
        };
        let text = link.to_string();
        assert!(text.starts_with("phantom://"));
        assert!(!text.contains('?') && !text.contains('#'));
        let back = ConnectLink::parse(&text).unwrap();
        assert_eq!(back.server, "examroom.dbug.om:8444");
        assert_eq!(back.server_public_key, pk);
        assert!(back.backups.is_empty() && !back.has_client_key() && back.label.is_none());
    }

    #[test]
    fn full_link_roundtrips() {
        let pk = key();
        let backup_pk = key();
        let client = KeyPair::generate().unwrap();
        let link = ConnectLink {
            server: "examroom.dbug.om:8444".into(),
            server_public_key: pk.clone(),
            backups: vec![
                LinkServer {
                    address: "46.225.110.152:8444".into(),
                    public_key: None,
                },
                LinkServer {
                    address: "[2001:db8::7]:443".into(),
                    public_key: Some(backup_pk.clone()),
                },
            ],
            client_private_key: Some(client.private.clone()),
            label: Some("Office laptop #2 (Sam's)".into()),
        };
        let text = link.to_string();
        // Keys are base64url without padding: nothing that needs escaping.
        assert_eq!(encode_key(pk.as_bytes()).len(), 43);
        let after_scheme = text.strip_prefix("phantom://").unwrap();
        assert!(
            !after_scheme.contains(['+', '/']) && !text.contains("=&"),
            "{}",
            text
        );
        let back = ConnectLink::parse(&text).unwrap();
        assert_eq!(back.server, link.server);
        assert_eq!(back.server_public_key, pk);
        assert_eq!(back.backups, link.backups);
        assert_eq!(back.client_public_key(), Some(client.public));
        assert_eq!(back.label.as_deref(), Some("Office laptop #2 (Sam's)"));
        // Formatting is stable.
        assert_eq!(back.to_string(), text);

        // An IPv6 primary keeps its brackets readable.
        let v6 = ConnectLink {
            server: "[2001:db8::9]:8444".into(),
            ..back
        };
        let text = v6.to_string();
        assert!(text.contains("@[2001:db8::9]:8444"), "{}", text);
        assert_eq!(
            ConnectLink::parse(&text).unwrap().server,
            "[2001:db8::9]:8444"
        );
    }

    #[test]
    fn accepts_standard_base64_and_wrapping() {
        let pk = key();
        let text = format!("  <phantom://{}@1.2.3.4:8444/>  ", pk.to_base64());
        let back = ConnectLink::parse(&text).unwrap();
        assert_eq!(back.server_public_key, pk);
        assert_eq!(back.server, "1.2.3.4:8444");

        let text = format!("\"PHANTOM://{}@h:1?future=1&backup=h2:2\"", pk.to_base64());
        let back = ConnectLink::parse(&text).unwrap();
        assert_eq!(back.backups.len(), 1, "unknown params are ignored");
    }

    #[test]
    fn rejects_bad_links() {
        let pk = encode_key(key().as_bytes());
        let cases: Vec<(String, LinkError)> = vec![
            ("https://example.com".into(), LinkError::WrongScheme),
            (
                "phantom://example.com:8444".into(),
                LinkError::MissingServerKey,
            ),
            (
                "phantom://@example.com:8444".into(),
                LinkError::MissingServerKey,
            ),
            (
                format!("phantom://{}@example.com", pk),
                LinkError::BadAddress {
                    what: "server",
                    addr: "example.com".into(),
                    why: "missing :port",
                },
            ),
            (
                format!("phantom://{}@example.com:0", pk),
                LinkError::BadAddress {
                    what: "server",
                    addr: "example.com:0".into(),
                    why: "port must be 1-65535",
                },
            ),
            (
                format!("phantom://{}@h:1?key=", pk),
                LinkError::EmptyValue("key".into()),
            ),
            (
                format!("phantom://{}@h:1?key={}&key={}", pk, pk, pk),
                LinkError::DuplicateKey,
            ),
            (
                format!("phantom://{}@h:1?backup=%ZZ", pk),
                LinkError::BadEncoding,
            ),
        ];
        for (text, want) in cases {
            assert_eq!(ConnectLink::parse(&text).unwrap_err(), want, "{}", text);
        }
        // Short key.
        assert!(matches!(
            ConnectLink::parse("phantom://AAAA@h:1"),
            Err(LinkError::BadKey { what: "server", .. })
        ));
        // Bare IPv6 is ambiguous.
        assert!(matches!(
            ConnectLink::parse(&format!("phantom://{}@2001:db8::1:8444", pk)),
            Err(LinkError::BadAddress { .. })
        ));
        // Too many backups.
        let many: String = (0..=MAX_BACKUPS)
            .map(|i| format!("&backup=h{}:1", i))
            .collect();
        assert_eq!(
            ConnectLink::parse(&format!("phantom://{}@h:1?{}", pk, &many[1..])).unwrap_err(),
            LinkError::TooManyBackups
        );
    }

    #[test]
    fn label_is_sanitised() {
        let pk = encode_key(key().as_bytes());
        let l = ConnectLink::parse(&format!("phantom://{}@h:1#a%0Ab%07c", pk)).unwrap();
        assert_eq!(l.label.as_deref(), Some("abc"));
        let l = ConnectLink::parse(&format!("phantom://{}@h:1#%20", pk)).unwrap();
        assert_eq!(l.label, None);
    }

    #[test]
    fn debug_output_never_shows_client_key() {
        let client = KeyPair::generate().unwrap();
        let link = ConnectLink {
            server: "h:1".into(),
            server_public_key: key(),
            backups: vec![],
            client_private_key: Some(client.private.clone()),
            label: None,
        };
        let dbg = format!("{:?}", link);
        assert!(!dbg.contains(&encode_key(client.private.as_bytes())));
        assert!(!dbg.contains(&client.private.to_base64()));
    }

    #[test]
    fn import_keeps_identity_and_local_settings() {
        let server = key();
        let mine = KeyPair::generate().unwrap();
        let existing = ClientConfig {
            server: "old:1".into(),
            server_public_key: server.to_base64(),
            private_key: mine.private.to_base64(),
            // A stale/wrong public key in the old file gets corrected.
            public_key: key().to_base64(),
            http_listen: Some("127.0.0.1:18080".into()),
            ..ClientConfig::default()
        };
        let link = ConnectLink::parse(&format!(
            "phantom://{}@new:8444?backup=1.2.3.4:8444",
            encode_key(server.as_bytes())
        ))
        .unwrap();

        let (cfg, src) = link.to_client_config(Some(&existing)).unwrap();
        assert_eq!(src, KeySource::Kept);
        assert_eq!(cfg.server, "new:8444");
        assert_eq!(cfg.private_key, mine.private.to_base64());
        assert_eq!(cfg.public_key, mine.public.to_base64());
        assert_eq!(cfg.http_listen.as_deref(), Some("127.0.0.1:18080"));
        assert_eq!(
            cfg.backup_servers,
            vec![BackupServer {
                address: "1.2.3.4:8444".into(),
                public_key: String::new()
            }]
        );

        // No existing config: a fresh key pair is generated.
        let (cfg, src) = link.to_client_config(None).unwrap();
        assert_eq!(src, KeySource::Generated);
        let sk = PrivateKey::from_base64(&cfg.private_key).unwrap();
        assert_eq!(sk.public_key().to_base64(), cfg.public_key);

        // A key in the link wins over the existing one.
        let issued = KeyPair::generate().unwrap();
        let with_key = ConnectLink {
            client_private_key: Some(issued.private.clone()),
            ..link
        };
        let (cfg, src) = with_key.to_client_config(Some(&existing)).unwrap();
        assert_eq!(src, KeySource::FromLink);
        assert_eq!(cfg.public_key, issued.public.to_base64());
    }

    #[test]
    fn link_from_config_includes_key_only_on_request() {
        let server = key();
        let mine = KeyPair::generate().unwrap();
        let cfg = ClientConfig {
            server: "h:1".into(),
            server_public_key: server.to_base64(),
            private_key: mine.private.to_base64(),
            backup_servers: vec![BackupServer {
                address: "b:2".into(),
                public_key: String::new(),
            }],
            ..ClientConfig::default()
        };
        let public = ConnectLink::from_client_config(&cfg, false).unwrap();
        assert!(!public.has_client_key());
        assert!(!public
            .to_string()
            .contains(&encode_key(mine.private.as_bytes())));
        assert_eq!(public.backups.len(), 1);
        let private = ConnectLink::from_client_config(&cfg, true).unwrap();
        assert_eq!(private.client_public_key(), Some(mine.public));
    }
}
