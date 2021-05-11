use criterion::{criterion_group, criterion_main, Criterion};
use notatin::filter::Filter;
use notatin::registry::Registry;
use notatin::registry::Parser;

fn test_read_small_reg() {
    let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

    let mut filter = Filter::new();

    let mut parser = Parser::new(&f, &mut filter);
    parser.init();
    for _key in parser {
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("read small reg", |b| b.iter(|| test_read_small_reg()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);