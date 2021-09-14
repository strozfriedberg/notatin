use criterion::{criterion_group, criterion_main, Criterion};
use notatin::parser_builder::ParserBuilder;

fn test_read_small_reg() {
    let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
        .build()
        .unwrap();
    for _key in parser.iter() {}
}

fn test_read_small_reg_with_deleted() {
    let mut parser = ParserBuilder::from_path("test_data/NTUSER.DAT")
        .recover_deleted(true)
        .build()
        .unwrap();
    for _key in parser.iter() {}
}

#[allow(clippy::redundant_closure)] // The documented way of calling Criterion benchmarks uses a redundant closure
pub fn bench(c: &mut Criterion) {
    let mut group1 = c.benchmark_group("read small reg");
    group1
        .sample_size(1000)
        .measurement_time(std::time::Duration::from_secs(5))
        .bench_function("read small reg", |b| b.iter(|| test_read_small_reg()))
        .bench_function("read small reg with deleted", |b| {
            b.iter(|| test_read_small_reg_with_deleted())
        });
    group1.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
