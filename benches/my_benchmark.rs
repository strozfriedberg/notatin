use criterion::{criterion_group, criterion_main, Criterion};
use notatin::parser::Parser;

fn test_read_small_reg() {
    let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, None, false).unwrap();
    for _key in parser.iter() {}
}

fn test_read_small_reg_with_deleted() {
    let mut parser = Parser::from_path("test_data/NTUSER.DAT", None, None, true).unwrap();
    for _key in parser.iter() {}
}

fn test_read_reg_without_logs() {
    let mut parser = Parser::from_path("test_data/system", None, None, false).unwrap();
    for _key in parser.iter() {}
}

fn test_read_reg_with_logs() {
    let mut parser = Parser::from_path(
        "test_data/system",
        Some(vec!["test_data/system.log1", "test_data/system.log2"]),
        None,
        true,
    )
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

    let mut group2 = c.benchmark_group("read reg");
    group2
        .sample_size(500)
        .measurement_time(std::time::Duration::from_secs(25))
        .bench_function("read reg without logs", |b| {
            b.iter(|| test_read_reg_without_logs())
        })
        .bench_function("read reg with logs", |b| {
            b.iter(|| test_read_reg_with_logs())
        });
    group2.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
