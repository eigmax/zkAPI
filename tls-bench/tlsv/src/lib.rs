//! Verification of a recorded TLS 1.3 session (`TLS_AES_128_GCM_SHA256`,
//! X25519), as a witness would see it: the raw bytes each way, plus the
//! client's ephemeral X25519 secret.
//!
//! From those it recomputes the whole key schedule, opens every handshake
//! record, checks the server's certificate chain up to a pinned trust anchor,
//! the server's `CertificateVerify` signature over the transcript and its
//! `Finished` MAC, then opens the application records. A caller-supplied
//! [`Tracker`] brackets each phase so a zkVM guest can attribute cycles.

use aes::cipher::{BlockEncrypt, KeyInit as _};
use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Nonce, Tag};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use x509_cert::{
    ext::pkix::{name::GeneralName, BasicConstraints, SubjectAltName},
    spki::SubjectPublicKeyInfoOwned,
    Certificate,
};

/// A recorded session.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Capture {
    /// The name the client asked for (SNI), matched against the leaf's SAN.
    pub server_name: String,
    /// The client's ephemeral X25519 secret.
    pub client_secret: [u8; 32],
    /// Every byte the client sent.
    pub c2s: Vec<u8>,
    /// Every byte the server sent.
    pub s2c: Vec<u8>,
    /// How many certificates, from the leaf, lead to the trust anchor.
    pub chain_len: u32,
    /// DER `Name` of the pinned trust anchor that issued the last certificate.
    pub anchor_subject: Vec<u8>,
    /// DER `SubjectPublicKeyInfo` of the pinned trust anchor.
    pub anchor_spki: Vec<u8>,
    /// AES blocks of the first client application record to open without its tag.
    pub selective_blocks: Vec<u32>,
}

/// What the check established.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Summary {
    pub server_name: String,
    pub chain: Vec<String>,
    pub cert_verify_scheme: u16,
    pub cert_bytes: u32,
    pub hs_record_bytes: u32,
    pub request_bytes: u32,
    pub response_bytes: u32,
    pub transcript_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub response_hash: [u8; 32],
    pub selective_plaintext: Vec<u8>,
}

/// Brackets a phase of the check.
pub trait Tracker {
    fn start(&mut self, phase: &str);
    fn end(&mut self, phase: &str);
}

/// A tracker that records nothing.
pub struct NoTrack;

impl Tracker for NoTrack {
    fn start(&mut self, _: &str) {}
    fn end(&mut self, _: &str) {}
}

pub type Result<T> = core::result::Result<T, String>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(msg.into())
}

/// Runs `f` as phase `name`.
fn phase<T>(t: &mut dyn Tracker, name: &str, f: impl FnOnce() -> T) -> T {
    t.start(name);
    let out = f();
    t.end(name);
    out
}

/// A TLS record: content type, the 5-byte header (the AEAD's additional data)
/// and the body.
struct Record<'a> {
    content_type: u8,
    header: [u8; 5],
    body: &'a [u8],
}

fn records(mut buf: &[u8]) -> Result<Vec<Record<'_>>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 5 {
            return err("truncated record header");
        }
        let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() < 5 + len {
            return err("truncated record");
        }
        let mut header = [0u8; 5];
        header.copy_from_slice(&buf[..5]);
        out.push(Record { content_type: buf[0], header, body: &buf[5..5 + len] });
        buf = &buf[5 + len..];
    }
    Ok(out)
}

/// A byte cursor over a handshake structure.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return err("truncated field");
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Result<usize> {
        let b = self.take(3)?;
        Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
    }
    fn vec8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn vec24(&mut self) -> Result<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }
}

/// Splits complete handshake messages (header included) off the front of `buf`.
fn take_messages(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        if buf.len() < 4 {
            break;
        }
        let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
        if buf.len() < 4 + len {
            break;
        }
        out.push(buf.drain(..4 + len).collect());
    }
    out
}

/// The key share for `group` in a ClientHello or ServerHello extension block.
fn key_share(mut ext: Cursor<'_>, server: bool) -> Result<Vec<u8>> {
    while !ext.0.is_empty() {
        let typ = ext.u16()?;
        let mut body = Cursor(ext.vec16()?);
        if typ != 51 {
            continue;
        }
        if server {
            if body.u16()? != 0x001d {
                return err("server key share is not X25519");
            }
            return Ok(body.vec16()?.to_vec());
        }
        let mut shares = Cursor(body.vec16()?);
        while !shares.0.is_empty() {
            let group = shares.u16()?;
            let key = shares.vec16()?;
            if group == 0x001d {
                return Ok(key.to_vec());
            }
        }
    }
    err("no X25519 key share")
}

const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

fn client_hello_share(msg: &[u8]) -> Result<Vec<u8>> {
    let mut c = Cursor(&msg[4..]);
    c.take(2 + 32)?;
    c.vec8()?;
    let suites = c.vec16()?;
    if !suites.chunks(2).any(|s| s == [0x13, 0x01]) {
        return err("client did not offer TLS_AES_128_GCM_SHA256");
    }
    c.vec8()?;
    key_share(Cursor(c.vec16()?), false)
}

fn server_hello_share(msg: &[u8]) -> Result<Vec<u8>> {
    if msg[0] != 2 {
        return err("expected ServerHello");
    }
    let mut c = Cursor(&msg[4..]);
    c.take(2)?;
    if c.take(32)? == HRR_RANDOM {
        return err("HelloRetryRequest is not supported");
    }
    c.vec8()?;
    if c.u16()? != 0x1301 {
        return err("server chose a suite other than TLS_AES_128_GCM_SHA256");
    }
    c.u8()?;
    key_share(Cursor(c.vec16()?), true)
}

/// `HKDF-Expand-Label` of RFC 8446 §7.1.
fn expand_label(secret: &[u8; 32], label: &str, context: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("PRK is one hash long");
    let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hk.expand(&info, out).expect("output fits HKDF");
}

/// `Derive-Secret(secret, label, transcript)` with the transcript already hashed.
fn derive_secret(secret: &[u8; 32], label: &str, transcript_hash: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    expand_label(secret, label, transcript_hash, &mut out);
    out
}

fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// One direction of a protected connection: its AEAD, IV and next sequence number.
struct Direction {
    aead: Aes128Gcm,
    key: [u8; 16],
    iv: [u8; 12],
    seq: u64,
}

impl Direction {
    fn new(traffic_secret: &[u8; 32]) -> Self {
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        expand_label(traffic_secret, "key", &[], &mut key);
        expand_label(traffic_secret, "iv", &[], &mut iv);
        Self { aead: Aes128Gcm::new(&key.into()), key, iv, seq: 0 }
    }

    fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in seq.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        n
    }

    /// Opens the next record and returns its inner content type and content.
    fn open(&mut self, rec: &Record<'_>) -> Result<(u8, Vec<u8>)> {
        if rec.content_type != 23 || rec.body.len() < 17 {
            return err("expected a protected record");
        }
        let (ct, tag) = rec.body.split_at(rec.body.len() - 16);
        let mut buf = ct.to_vec();
        let nonce = self.nonce(self.seq);
        self.aead
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), &rec.header, &mut buf, Tag::from_slice(tag))
            .map_err(|_| "record authentication failed".to_string())?;
        self.seq += 1;
        while buf.last() == Some(&0) {
            buf.pop();
        }
        let inner = buf.pop().ok_or("empty record")?;
        Ok((inner, buf))
    }

    /// Decrypts the given 16-byte blocks of the record with sequence number
    /// `seq`, by AES-CTR from the GCM counter, without checking its tag.
    fn open_blocks(&self, seq: u64, rec: &Record<'_>, blocks: &[u32]) -> Result<Vec<u8>> {
        let cipher = aes::Aes128::new(&self.key.into());
        let nonce = self.nonce(seq);
        let ct = &rec.body[..rec.body.len() - 16];
        let mut out = Vec::with_capacity(blocks.len() * 16);
        for &b in blocks {
            let start = b as usize * 16;
            if start >= ct.len() {
                return err("selected block past the record");
            }
            let mut counter = [0u8; 16];
            counter[..12].copy_from_slice(&nonce);
            counter[12..].copy_from_slice(&(b + 2).to_be_bytes());
            let mut ks = counter.into();
            cipher.encrypt_block(&mut ks);
            let end = (start + 16).min(ct.len());
            out.extend(ct[start..end].iter().zip(ks.iter()).map(|(c, k)| c ^ k));
        }
        Ok(out)
    }
}

const OID_EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_SAN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// The kind of public key in an SPKI.
enum Key {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

impl Key {
    fn from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<Self> {
        let bits = spki.subject_public_key.raw_bytes();
        if spki.algorithm.oid == OID_RSA {
            use rsa::pkcs1::DecodeRsaPublicKey;
            return rsa::RsaPublicKey::from_pkcs1_der(bits).map(Key::Rsa).map_err(|e| e.to_string());
        }
        if spki.algorithm.oid != OID_EC {
            return err("unsupported key algorithm");
        }
        let curve: ObjectIdentifier = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or("EC key without curve")?
            .decode_as()
            .map_err(|e| e.to_string())?;
        if curve == OID_P256 {
            p256::ecdsa::VerifyingKey::from_sec1_bytes(bits).map(Key::P256).map_err(|e| e.to_string())
        } else if curve == OID_P384 {
            p384::ecdsa::VerifyingKey::from_sec1_bytes(bits).map(Key::P384).map_err(|e| e.to_string())
        } else {
            err("unsupported curve")
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Key::P256(_) => "P-256",
            Key::P384(_) => "P-384",
            Key::Rsa(k) => {
                use rsa::traits::PublicKeyParts;
                if k.size() == 256 {
                    "RSA-2048"
                } else if k.size() == 512 {
                    "RSA-4096"
                } else {
                    "RSA"
                }
            }
        }
    }
}

/// Hash used by a signature.
#[derive(Clone, Copy)]
enum Hash {
    Sha256,
    Sha384,
}

/// Checks an ECDSA (DER) or RSA PKCS#1 v1.5 signature, or with `pss` an
/// RSA-PSS signature, over `msg`.
fn verify(key: &Key, hash: Hash, pss: bool, msg: &[u8], sig: &[u8]) -> Result<()> {
    use p256::ecdsa::signature::{hazmat::PrehashVerifier, Verifier};
    let bad = |e: &dyn core::fmt::Display| e.to_string();
    match (key, hash) {
        (Key::P256(k), Hash::Sha256) => {
            k.verify(msg, &p256::ecdsa::Signature::from_der(sig).map_err(|e| bad(&e))?).map_err(|e| bad(&e))
        }
        (Key::P256(k), Hash::Sha384) => k
            .verify_prehash(&Sha384::digest(msg), &p256::ecdsa::Signature::from_der(sig).map_err(|e| bad(&e))?)
            .map_err(|e| bad(&e)),
        (Key::P384(k), Hash::Sha384) => {
            k.verify(msg, &p384::ecdsa::Signature::from_der(sig).map_err(|e| bad(&e))?).map_err(|e| bad(&e))
        }
        (Key::P384(k), Hash::Sha256) => k
            .verify_prehash(&Sha256::digest(msg), &p384::ecdsa::Signature::from_der(sig).map_err(|e| bad(&e))?)
            .map_err(|e| bad(&e)),
        (Key::Rsa(k), h) => {
            if pss {
                let s = rsa::pss::Signature::try_from(sig).map_err(|e| bad(&e))?;
                match h {
                    Hash::Sha256 => rsa::pss::VerifyingKey::<Sha256>::new(k.clone()).verify(msg, &s),
                    Hash::Sha384 => rsa::pss::VerifyingKey::<Sha384>::new(k.clone()).verify(msg, &s),
                }
                .map_err(|e| bad(&e))
            } else {
                let s = rsa::pkcs1v15::Signature::try_from(sig).map_err(|e| bad(&e))?;
                match h {
                    Hash::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(k.clone()).verify(msg, &s),
                    Hash::Sha384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(k.clone()).verify(msg, &s),
                }
                .map_err(|e| bad(&e))
            }
        }
    }
}

/// The raw DER of a certificate's `tbsCertificate`, the bytes its issuer signed.
fn tbs_bytes(cert: &[u8]) -> Result<&[u8]> {
    fn header(b: &[u8]) -> Result<(usize, usize)> {
        if b.len() < 2 {
            return err("short DER");
        }
        let l = b[1] as usize;
        if l < 0x80 {
            return Ok((2, l));
        }
        let n = l & 0x7f;
        if n == 0 || n > 4 || b.len() < 2 + n {
            return err("bad DER length");
        }
        Ok((2 + n, b[2..2 + n].iter().fold(0usize, |a, &x| (a << 8) | x as usize)))
    }
    let (h, _) = header(cert)?;
    let inner = &cert[h..];
    let (h2, l2) = header(inner)?;
    inner.get(..h2 + l2).ok_or_else(|| "truncated tbsCertificate".to_string())
}

fn dns_matches(pattern: &str, name: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("*.") {
        match name.split_once('.') {
            Some((label, tail)) => !label.is_empty() && tail.eq_ignore_ascii_case(rest),
            None => false,
        }
    } else {
        pattern.eq_ignore_ascii_case(name)
    }
}

/// Checks `c` and returns what it established.
pub fn check(c: &Capture, t: &mut dyn Tracker) -> Result<Summary> {
    let mut summary = Summary { server_name: c.server_name.clone(), ..Default::default() };

    let (crecs, srecs) = phase(t, "records", || Ok::<_, String>((records(&c.c2s)?, records(&c.s2c)?)))?;

    let client_hello = {
        let r = crecs.first().ok_or("no client records")?;
        if r.content_type != 22 {
            return err("first client record is not a handshake");
        }
        let mut buf = r.body.to_vec();
        take_messages(&mut buf).into_iter().next().ok_or("no ClientHello")?
    };
    let server_hello = {
        let r = srecs.first().ok_or("no server records")?;
        if r.content_type != 22 {
            return err("first server record is not a handshake");
        }
        let mut buf = r.body.to_vec();
        take_messages(&mut buf).into_iter().next().ok_or("no ServerHello")?
    };
    let client_share = client_hello_share(&client_hello)?;
    let server_share: [u8; 32] =
        server_hello_share(&server_hello)?.try_into().map_err(|_| "bad server share length")?;

    let shared = phase(t, "x25519", || {
        let secret = x25519_dalek::StaticSecret::from(c.client_secret);
        if x25519_dalek::PublicKey::from(&secret).as_bytes() != client_share.as_slice() {
            return err("client secret does not match the ClientHello key share");
        }
        Ok(secret.diffie_hellman(&x25519_dalek::PublicKey::from(server_share)).to_bytes())
    })?;

    let mut transcript = Sha256::new();
    phase(t, "transcript_hash", || {
        transcript.update(&client_hello);
        transcript.update(&server_hello);
    });
    let th_hello = transcript.clone().finalize();

    let (handshake_secret, s_hs, c_hs) = phase(t, "key_schedule", || {
        let empty = Sha256::digest([]);
        let early = extract(&[0u8; 32], &[0u8; 32]);
        let hs = extract(&derive_secret(&early, "derived", &empty), &shared);
        (hs, derive_secret(&hs, "s hs traffic", &th_hello), derive_secret(&hs, "c hs traffic", &th_hello))
    });
    let mut server_dir = phase(t, "key_schedule", || Direction::new(&s_hs));

    let mut hs_buf = Vec::new();
    let mut messages: Vec<Vec<u8>> = Vec::new();
    let mut srest = srecs.iter().skip(1).filter(|r| r.content_type != 20).peekable();
    while !messages.iter().any(|m| m[0] == 20) {
        let rec = srest.next().ok_or("server handshake ended before Finished")?;
        summary.hs_record_bytes += rec.body.len() as u32;
        let (inner, body) = phase(t, "hs_decrypt", || server_dir.open(rec))?;
        if inner != 22 {
            return err("expected handshake content");
        }
        hs_buf.extend_from_slice(&body);
        messages.extend(take_messages(&mut hs_buf));
    }
    let kinds: Vec<u8> = messages.iter().map(|m| m[0]).collect();
    if kinds != [8, 11, 15, 20] {
        return err(format!("unexpected server flight {kinds:?}"));
    }

    phase(t, "transcript_hash", || {
        transcript.update(&messages[0]);
        transcript.update(&messages[1]);
    });
    let th_cert = transcript.clone().finalize();

    let ders: Vec<Vec<u8>> = {
        let mut m = Cursor(&messages[1][4..]);
        m.vec8()?;
        let mut list = Cursor(m.vec24()?);
        let mut out = Vec::new();
        while !list.0.is_empty() {
            out.push(list.vec24()?.to_vec());
            list.vec16()?;
        }
        out
    };
    summary.cert_bytes = ders.iter().map(|d| d.len() as u32).sum();
    if c.chain_len == 0 || c.chain_len as usize > ders.len() {
        return err("chain length out of range");
    }
    let ders = &ders[..c.chain_len as usize];

    let (certs, anchor_spki) = phase(t, "x509_parse", || {
        let certs = ders.iter().map(|d| Certificate::from_der(d).map_err(|e| e.to_string())).collect::<Result<Vec<_>>>()?;
        let anchor = SubjectPublicKeyInfoOwned::from_der(&c.anchor_spki).map_err(|e| e.to_string())?;
        Ok::<_, String>((certs, anchor))
    })?;
    if certs.is_empty() {
        return err("empty certificate chain");
    }

    phase(t, "chain_names", || {
        for i in 0..certs.len() {
            let issuer = certs[i].tbs_certificate.issuer.to_der().map_err(|e| e.to_string())?;
            let expected = if i + 1 < certs.len() {
                certs[i + 1].tbs_certificate.subject.to_der().map_err(|e| e.to_string())?
            } else {
                c.anchor_subject.clone()
            };
            if issuer != expected {
                return err(format!("certificate {i} is not issued by the next one"));
            }
            if certs[i].signature_algorithm != certs[i].tbs_certificate.signature {
                return err("inner and outer signature algorithms differ");
            }
            if i > 0 {
                let ca = certs[i]
                    .tbs_certificate
                    .extensions
                    .iter()
                    .flatten()
                    .find(|e| e.extn_id == OID_BASIC_CONSTRAINTS)
                    .and_then(|e| BasicConstraints::from_der(e.extn_value.as_bytes()).ok())
                    .map(|b| b.ca)
                    .unwrap_or(false);
                if !ca {
                    return err(format!("certificate {i} is not a CA"));
                }
            }
        }
        let san = certs[0]
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id == OID_SAN)
            .ok_or("leaf has no SAN")?;
        let san = SubjectAltName::from_der(san.extn_value.as_bytes()).map_err(|e| e.to_string())?;
        if !san.0.iter().any(|g| matches!(g, GeneralName::DnsName(d) if dns_matches(d.as_str(), &c.server_name))) {
            return err("leaf SAN does not cover the server name");
        }
        Ok(())
    })?;

    for i in 0..certs.len() {
        let issuer_spki = if i + 1 < certs.len() { &certs[i + 1].tbs_certificate.subject_public_key_info } else { &anchor_spki };
        let name = format!("chain_sig_{i}");
        let label = phase(t, &name, || {
            let key = Key::from_spki(issuer_spki)?;
            let alg = certs[i].signature_algorithm.oid;
            let (hash, alg_name) = if alg == OID_ECDSA_SHA256 || alg == OID_RSA_SHA256 {
                (Hash::Sha256, "SHA-256")
            } else if alg == OID_ECDSA_SHA384 || alg == OID_RSA_SHA384 {
                (Hash::Sha384, "SHA-384")
            } else {
                return err("unsupported certificate signature algorithm");
            };
            let tbs = tbs_bytes(&ders[i])?;
            let sig = certs[i].signature.raw_bytes();
            verify(&key, hash, false, tbs, sig)?;
            Ok::<_, String>(format!("cert {i} signed by {} / {alg_name}", key.name()))
        })?;
        summary.chain.push(label);
    }

    let mut cv = Cursor(&messages[2][4..]);
    let scheme = cv.u16()?;
    let cv_sig = cv.vec16()?.to_vec();
    summary.cert_verify_scheme = scheme;
    phase(t, "cert_verify", || {
        let leaf = Key::from_spki(&certs[0].tbs_certificate.subject_public_key_info)?;
        let mut msg = vec![0x20u8; 64];
        msg.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
        msg.extend_from_slice(&th_cert);
        let (hash, pss) = match scheme {
            0x0403 => (Hash::Sha256, false),
            0x0503 => (Hash::Sha384, false),
            0x0804 => (Hash::Sha256, true),
            0x0805 => (Hash::Sha384, true),
            _ => return err(format!("unsupported CertificateVerify scheme {scheme:#06x}")),
        };
        verify(&leaf, hash, pss, &msg, &cv_sig)
    })?;

    phase(t, "transcript_hash", || transcript.update(&messages[2]));
    let th_cv = transcript.clone().finalize();
    phase(t, "finished", || {
        let mut finished_key = [0u8; 32];
        expand_label(&s_hs, "finished", &[], &mut finished_key);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&finished_key).expect("any key length");
        mac.update(&th_cv);
        mac.verify_slice(&messages[3][4..]).map_err(|_| "server Finished does not verify".to_string())
    })?;
    phase(t, "transcript_hash", || transcript.update(&messages[3]));
    let th_fin = transcript.clone().finalize();
    summary.transcript_hash = th_fin.into();

    let (mut client_hs_dir, mut client_app, mut server_app) = phase(t, "key_schedule", || {
        let empty = Sha256::digest([]);
        let master = extract(&derive_secret(&handshake_secret, "derived", &empty), &[0u8; 32]);
        (
            Direction::new(&c_hs),
            Direction::new(&derive_secret(&master, "c ap traffic", &th_fin)),
            Direction::new(&derive_secret(&master, "s ap traffic", &th_fin)),
        )
    });

    let mut cprot = crecs.iter().skip(1).filter(|r| r.content_type != 20);
    let cfin = cprot.next().ok_or("no client Finished")?;
    let (inner, body) = phase(t, "hs_decrypt", || client_hs_dir.open(cfin))?;
    if inner != 22 || body.first() != Some(&20) {
        return err("client Finished record is not a Finished message");
    }

    let creqs: Vec<&Record<'_>> = cprot.collect();
    let first_req = *creqs.first().ok_or("no client application data")?;
    let mut request = Vec::new();
    phase(t, "app_decrypt_request", || {
        for r in &creqs {
            let (inner, body) = client_app.open(r)?;
            if inner == 23 {
                request.extend_from_slice(&body);
            }
        }
        Ok::<_, String>(())
    })?;
    summary.request_bytes = request.len() as u32;

    let mut response = Vec::new();
    phase(t, "app_decrypt_response", || {
        for r in srest {
            if r.content_type == 21 {
                break;
            }
            let (inner, body) = server_app.open(r)?;
            if inner == 23 {
                response.extend_from_slice(&body);
            }
        }
        Ok::<_, String>(())
    })?;
    summary.response_bytes = response.len() as u32;

    phase(t, "app_hash", || {
        summary.request_hash = Sha256::digest(&request).into();
        summary.response_hash = Sha256::digest(&response).into();
    });

    summary.selective_plaintext = phase(t, "selective_decrypt", || client_app.open_blocks(0, first_req, &c.selective_blocks))?;

    Ok(summary)
}
