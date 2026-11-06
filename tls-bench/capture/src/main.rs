//! Records one TLS 1.3 session with a public HTTPS API, as a witness would
//! see it, plus the client's ephemeral X25519 secret, and writes it as a
//! [`tlsv::Capture`].
//!
//! The request carries no credentials, so the server answers with an error;
//! the handshake and the record layer are the same as for an authenticated
//! call.
//!
//! Usage: `capture <host> <path> <model> <out.bin>`

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex},
};

use der::{Decode, Encode};
use rand_core::{OsRng, RngCore};
use rustls::{
    crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    pki_types::ServerName,
    ClientConfig, ClientConnection, Error, NamedGroup, RootCertStore, StreamOwned,
};

/// The X25519 secret of the session in progress.
static SECRET: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// X25519 that remembers its ephemeral secret.
#[derive(Debug)]
struct RecordingX25519;

static RECORDING_X25519: RecordingX25519 = RecordingX25519;

struct Active {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl SupportedKxGroup for RecordingX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        *SECRET.lock().unwrap() = Some(sk);
        let secret = x25519_dalek::StaticSecret::from(sk);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Box::new(Active { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer.try_into().map_err(|_| Error::General("bad X25519 share".into()))?;
        let shared = self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        Ok(SharedSecret::from(&shared.to_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// A TCP stream that keeps a copy of every byte in each direction.
struct Tee {
    inner: TcpStream,
    sent: Arc<Mutex<Vec<u8>>>,
    received: Arc<Mutex<Vec<u8>>>,
}

impl Read for Tee {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.received.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl Write for Tee {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sent.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// DER of a SEQUENCE around `content`.
fn sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: capture <host> <path> <model> <out.bin>");
        std::process::exit(2);
    }
    let (host, path, model, out) = (&args[1], &args[2], &args[3], &args[4]);

    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![&RECORDING_X25519];
    let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let sent = Arc::new(Mutex::new(Vec::new()));
    let received = Arc::new(Mutex::new(Vec::new()));
    let tcp = TcpStream::connect((host.as_str(), 443)).expect("connect");
    let tee = Tee { inner: tcp, sent: sent.clone(), received: received.clone() };
    let conn = ClientConnection::new(Arc::new(config), ServerName::try_from(host.clone()).expect("name"))
        .expect("client connection");
    let mut tls = StreamOwned::new(conn, tee);

    let body = format!(
        "{{\"model\":\"{model}\",\"max_tokens\":16,\"messages\":[{{\"role\":\"user\",\"content\":\"Say hi.\"}}]}}"
    );
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nAnthropic-Version: 2023-06-01\r\nUser-Agent: tls-bench\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(request.as_bytes()).expect("send request");
    tls.flush().expect("flush");
    let mut response = Vec::new();
    if let Err(e) = tls.read_to_end(&mut response) {
        eprintln!("read ended with: {e}");
    }
    let status = String::from_utf8_lossy(response.split(|&b| b == b'\n').next().unwrap_or_default()).to_string();

    let chain: Vec<Vec<u8>> =
        tls.conn.peer_certificates().expect("peer certificates").iter().map(|c| c.as_ref().to_vec()).collect();
    let mut found = None;
    'outer: for (i, der) in chain.iter().enumerate() {
        let cert = x509_cert::Certificate::from_der(der).expect("certificate");
        let issuer = cert.tbs_certificate.issuer.to_der().expect("issuer");
        for anchor in webpki_roots::TLS_SERVER_ROOTS {
            if sequence(anchor.subject.as_ref()) == issuer {
                found = Some((i + 1, issuer, sequence(anchor.subject_public_key_info.as_ref())));
                break 'outer;
            }
        }
    }
    let (chain_len, anchor_subject, anchor_spki) = found.expect("no certificate is issued by a known root");

    let offset = body_offset(&request, "\"model\"");
    let first = (offset / 16) as u32;
    let last = ((offset + 8 + model.len() + 2) / 16) as u32;
    let capture = tlsv::Capture {
        server_name: host.clone(),
        client_secret: SECRET.lock().unwrap().expect("key exchange ran"),
        c2s: sent.lock().unwrap().clone(),
        s2c: received.lock().unwrap().clone(),
        chain_len: chain_len as u32,
        anchor_subject,
        anchor_spki,
        selective_blocks: (first..=last).collect(),
    };

    let summary = tlsv::check(&capture, &mut tlsv::NoTrack).expect("native check");
    std::fs::write(out, bincode::serialize(&capture).expect("serialize")).expect("write capture");

    if chain_len >= 2 {
        let intermediate = x509_cert::Certificate::from_der(&chain[1]).expect("intermediate");
        let pinned = tlsv::Capture {
            chain_len: 1,
            anchor_subject: intermediate.tbs_certificate.subject.to_der().expect("subject"),
            anchor_spki: intermediate.tbs_certificate.subject_public_key_info.to_der().expect("spki"),
            ..capture.clone()
        };
        tlsv::check(&pinned, &mut tlsv::NoTrack).expect("native check, intermediate pinned");
        let pinned_out = out.replace(".bin", "-pinned.bin");
        std::fs::write(&pinned_out, bincode::serialize(&pinned).expect("serialize")).expect("write pinned capture");
        println!("  also wrote {pinned_out} (intermediate pinned as the anchor)");
    }
    println!("{host}: {status}");
    println!("  chain sent {} certs, {} to the anchor ({} bytes)", chain.len(), chain_len, summary.cert_bytes);
    for c in &summary.chain {
        println!("  {c}");
    }
    println!("  CertificateVerify scheme {:#06x}", summary.cert_verify_scheme);
    println!(
        "  handshake records {} B, request {} B, response {} B",
        summary.hs_record_bytes, summary.request_bytes, summary.response_bytes
    );
    println!("  selective blocks {:?}: {:?}", capture.selective_blocks, String::from_utf8_lossy(&summary.selective_plaintext));
}

/// Byte offset of `needle` in the HTTP request.
fn body_offset(request: &str, needle: &str) -> usize {
    request.find(needle).expect("needle in request")
}
