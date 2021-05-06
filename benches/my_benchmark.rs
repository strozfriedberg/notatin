use criterion::{criterion_group, criterion_main, Criterion};
use notatin::filter::Filter;
use notatin::registry::Registry;

fn test_read_small_reg() {
    let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

    let mut filter = Filter::new();
    Registry::from_bytes(&f[..], &mut filter).expect("Shouldn't fail");
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("read small reg", |b| b.iter(|| test_read_small_reg()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);