use cr3st4n1::{content_hash, sign, validate, verify, Cr3st4n1Credential};
use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn load_fixture() -> Cr3st4n1Credential {
    let content = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/minimal.cr3st4n1"
    ));
    serde_yaml::from_str(content).unwrap()
}

fn bench_sign(c: &mut Criterion) {
    let key = SigningKey::generate(&mut OsRng);
    let cred = load_fixture();
    c.bench_function("sign", |b| {
        b.iter(|| {
            let mut c = cred.clone();
            sign(&mut c, &key).unwrap();
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let key = SigningKey::generate(&mut OsRng);
    let mut cred = load_fixture();
    sign(&mut cred, &key).unwrap();
    let vk = key.verifying_key();
    c.bench_function("verify", |b| b.iter(|| verify(&cred, &vk).unwrap()));
}

fn bench_content_hash(c: &mut Criterion) {
    let cred = load_fixture();
    c.bench_function("content_hash", |b| b.iter(|| content_hash(&cred).unwrap()));
}

fn bench_validate(c: &mut Criterion) {
    let cred = load_fixture();
    let value = serde_json::to_value(&cred).unwrap();
    c.bench_function("validate", |b| b.iter(|| validate(&value).unwrap()));
}

criterion_group!(
    benches,
    bench_sign,
    bench_verify,
    bench_content_hash,
    bench_validate
);
criterion_main!(benches);
