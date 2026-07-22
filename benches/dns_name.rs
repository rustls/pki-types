// Benchmarks are not built by the MSRV CI job (it runs `cargo check --lib`).
#![allow(clippy::incompatible_msrv)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use rustls_pki_types::DnsName;

fn dns_name(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_name");
    group.bench_function("typical", |b| {
        b.iter(|| {
            validate_all(&[
                "example.com",
                "www.example.com",
                "api.us-east-1.amazonaws.com",
                "a.b.c.d.e.f.example.org",
                "xn--bcher-kva.example",
                "very-long-subdomain-name-with-many-characters.example-domain.com",
            ])
        })
    });

    group.bench_function("ip_like_rejected", |b| {
        b.iter(|| validate_all(&["127.0.0.1", "192.168.100.200", "10.0.0.1"]))
    });

    let mut max_length = String::new();
    while max_length.len() < 250 {
        if !max_length.is_empty() {
            max_length.push('.');
        }
        max_length.push_str("abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz-abcdefgh");
    }
    max_length.truncate(249);
    assert!(DnsName::try_from(max_length.as_str()).is_ok());
    let max_length: &[&str] = &[&max_length];
    group.bench_function("max_length", |b| b.iter(|| validate_all(max_length)));

    group.finish();
}

fn validate_all(inputs: &[&str]) {
    for input in inputs {
        let _ = black_box(DnsName::try_from(black_box(*input)));
    }
}

criterion_group!(benches, dns_name);
criterion_main!(benches);
