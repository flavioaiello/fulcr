use std::collections::BTreeSet;

use object::{Object, ObjectSection, ObjectSymbol};

use crate::models::{
    BinaryAnalysis, FindingSeverity, ScanFinding, ScannedCryptoMaterial, VulnerabilityAssessment,
};

const MAX_BINARY_STRINGS: usize = 48;
const MAX_BINARY_SYMBOLS: usize = 96;
const MAX_BINARY_SECTIONS: usize = 64;

pub struct BinaryScanOutput {
    pub analysis: BinaryAnalysis,
    pub findings: Vec<ScanFinding>,
    pub crypto: Vec<ScannedCryptoMaterial>,
    pub vulnerability_assessments: Vec<VulnerabilityAssessment>,
}

pub fn analyze_binary(evidence: &str, bytes: &[u8]) -> Option<BinaryScanOutput> {
    if !is_object_magic(bytes) && !looks_binary(bytes) {
        return None;
    }

    let mut analysis = BinaryAnalysis {
        path: evidence.to_string(),
        format: "opaque-binary".to_string(),
        architecture: None,
        digest: crate::digest::digest_bytes(bytes),
        size: bytes.len() as u64,
        entrypoint: None,
        sections: Vec::new(),
        imported_libraries: Vec::new(),
        symbols: Vec::new(),
        interesting_strings: extract_interesting_strings(bytes),
    };

    if let Ok(file) = object::File::parse(bytes) {
        analysis.format = format!("{:?}", file.format()).to_ascii_lowercase();
        analysis.architecture = Some(format!("{:?}", file.architecture()));
        analysis.entrypoint = (file.entry() != 0).then_some(file.entry());
        analysis.sections = file
            .sections()
            .filter_map(|section| section.name().ok().map(str::to_string))
            .take(MAX_BINARY_SECTIONS)
            .collect();

        let mut symbols = BTreeSet::new();
        for symbol in file.dynamic_symbols() {
            if let Ok(name) = symbol.name()
                && (symbol.is_undefined() || is_interesting_symbol(name))
            {
                symbols.insert(name.to_string());
            }
        }
        for symbol in file.symbols() {
            if symbols.len() >= MAX_BINARY_SYMBOLS {
                break;
            }
            if let Ok(name) = symbol.name()
                && is_interesting_symbol(name)
            {
                symbols.insert(name.to_string());
            }
        }

        let mut libraries = BTreeSet::new();
        for symbol in &symbols {
            if let Some(library) = inferred_library(symbol) {
                libraries.insert(library.to_string());
            }
        }

        analysis.symbols = symbols.into_iter().take(MAX_BINARY_SYMBOLS).collect();
        analysis.imported_libraries = libraries.into_iter().collect();
    }

    let mut findings = Vec::new();
    let mut crypto = Vec::new();
    let vulnerability_assessments = Vec::new();

    let joined = analysis
        .symbols
        .iter()
        .chain(analysis.imported_libraries.iter())
        .chain(analysis.interesting_strings.iter())
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();

    for (needle, library) in [
        ("openssl", "OpenSSL"),
        ("libssl", "OpenSSL"),
        ("libcrypto", "OpenSSL libcrypto"),
        ("rustls", "rustls"),
        ("ring", "ring"),
        ("boringssl", "BoringSSL"),
        ("schannel", "Schannel"),
        ("secur32", "Windows Secur32"),
    ] {
        if joined.contains(needle) {
            crypto.push(ScannedCryptoMaterial {
                name: library.to_string(),
                kind: "linked-crypto-library".to_string(),
                algorithm: None,
                purpose: Some("observed-in-binary-imports-or-symbols".to_string()),
                evidence: evidence.to_string(),
            });
        }
    }

    for (needle, algorithm, severity) in [
        ("tlsv1.0", "TLS 1.0", FindingSeverity::High),
        ("tlsv1_0", "TLS 1.0", FindingSeverity::High),
        ("tlsv1.1", "TLS 1.1", FindingSeverity::Medium),
        ("ssl3", "SSL 3.0", FindingSeverity::High),
        ("rc4", "RC4", FindingSeverity::High),
        ("3des", "3DES", FindingSeverity::Medium),
        ("md5", "MD5", FindingSeverity::Medium),
        ("sha1", "SHA-1", FindingSeverity::Low),
    ] {
        if joined.contains(needle) {
            let severity = if matches!(severity, FindingSeverity::High | FindingSeverity::Critical)
            {
                FindingSeverity::Medium
            } else {
                severity
            };
            crypto.push(ScannedCryptoMaterial {
                name: algorithm.to_string(),
                kind: "binary-crypto-primitive".to_string(),
                algorithm: Some(algorithm.to_string()),
                purpose: Some("observed-in-binary".to_string()),
                evidence: evidence.to_string(),
            });
            findings.push(ScanFinding {
                severity,
                category: "binary-crypto-policy-drift".to_string(),
                message: format!(
                    "legacy or sensitive crypto primitive observed in binary: {algorithm}"
                ),
                evidence: evidence.to_string(),
            });
        }
    }

    if contains_network_indicator(&joined) {
        findings.push(ScanFinding {
            severity: FindingSeverity::Medium,
            category: "binary-network-capability".to_string(),
            message: "binary imports or strings indicate network capability".to_string(),
            evidence: evidence.to_string(),
        });
    }

    Some(BinaryScanOutput {
        analysis,
        findings,
        crypto,
        vulnerability_assessments,
    })
}

pub fn is_object_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}

fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(1024).any(|byte| *byte == 0)
}

fn is_interesting_symbol(symbol: &str) -> bool {
    let lower = symbol.to_ascii_lowercase();
    contains_network_indicator(&lower)
        || lower.contains("ssl")
        || lower.contains("tls")
        || lower.contains("crypto")
        || lower.contains("x509")
        || lower.contains("cert")
        || lower.contains("cipher")
        || lower.contains("encrypt")
        || lower.contains("decrypt")
}

fn inferred_library(symbol: &str) -> Option<&'static str> {
    let lower = symbol.to_ascii_lowercase();
    if lower.contains("openssl") || lower.starts_with("ssl_") || lower.starts_with("crypto_") {
        Some("OpenSSL")
    } else if lower.contains("rustls") {
        Some("rustls")
    } else if lower.contains("schannel") {
        Some("Schannel")
    } else if lower.contains("curl") {
        Some("libcurl")
    } else if lower.contains("socket") || lower.contains("connect") || lower.contains("getaddrinfo")
    {
        Some("system-network-api")
    } else {
        None
    }
}

fn contains_network_indicator(text: &str) -> bool {
    [
        "http://",
        "https://",
        "/dev/tcp",
        "socket",
        "connect",
        "getaddrinfo",
        "curl",
        "wget",
        "winhttp",
        "ws2_32",
        "dnsquery",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn extract_interesting_strings(bytes: &[u8]) -> Vec<String> {
    let mut strings = BTreeSet::new();
    let mut current = Vec::new();

    for byte in bytes.iter().copied().chain(std::iter::once(0)) {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
            continue;
        }

        if current.len() >= 4 {
            let value = String::from_utf8_lossy(&current).to_string();
            let lower = value.to_ascii_lowercase();
            if is_interesting_symbol(&lower)
                || contains_network_indicator(&lower)
                || lower.contains("http")
                || lower.contains("/bin/sh")
            {
                strings.insert(value);
            }
        }
        current.clear();
    }

    strings.into_iter().take(MAX_BINARY_STRINGS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzes_opaque_binary_strings() {
        let bytes = b"\0\0openssl TLSv1.0 https://callback.example.invalid\0";
        let output = analyze_binary("bin/tool", bytes).unwrap();
        assert!(
            output
                .crypto
                .iter()
                .any(|item| item.name == "OpenSSL" || item.algorithm.as_deref() == Some("TLS 1.0"))
        );
        assert!(
            output
                .findings
                .iter()
                .any(|finding| finding.category == "binary-network-capability")
        );
    }
}
