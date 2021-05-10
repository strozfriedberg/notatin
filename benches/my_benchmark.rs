use criterion::{criterion_group, criterion_main, Criterion};
use notatin::filter::Filter;
use notatin::registry::Registry;
use notatin::registry::Parser;

fn test_read_small_reg() {
    let f = std::fs::read("test_data/NTUSER.DAT").unwrap();

    let mut filter = Filter::new();
    //Registry::from_bytes(&f[..], &mut filter).expect("Shouldn't fail");

    let mut parser = Parser::new(&f, &mut filter);
    parser.init();
    let mut keys = 0;
    let mut values = 0;
    for _key in parser {
        //keys += 1;
        //values += key.sub_values.len();
        //println!("{}", key.path);
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("read small reg", |b| b.iter(|| test_read_small_reg()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);