//! The sync merge of a vault: the model merge alone, the KDBX read and write around it, and
//! what a sync does with the bytes (open the server copy and the base, merge, save).
//! Budget (rust-core.md §8): 5k entries under 300 ms on an iPhone 12.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use ov_benches::{count_entries, three_way, T_MERGE};

fn merge(c: &mut Criterion) {
    let mut g = c.benchmark_group("merge");
    g.sample_size(20);
    for total in [500u32, 5000] {
        let (base, local, remote, key) = three_way(total);
        let (merged, report) = ov_merge::merge(Some(&base), &local, &remote, T_MERGE);
        // 20 added; the 5 deleted moved to the Recycle Bin, so they still count
        assert_eq!(count_entries(&merged), total as usize + 20, "merged entries");
        assert!(!report.changes.is_empty());

        g.bench_function(format!("model/{total}"), |b| {
            b.iter(|| ov_merge::merge(Some(black_box(&base)), black_box(&local), black_box(&remote), T_MERGE))
        });

        let base_bytes = ov_kdbx::write(&base, &key).expect("write base");
        let remote_bytes = ov_kdbx::write(&remote, &key).expect("write remote");
        g.bench_function(format!("kdbx_read/{total}"), |b| {
            b.iter(|| ov_kdbx::read(black_box(&remote_bytes), &key).expect("read"))
        });
        g.bench_function(format!("kdbx_write/{total}"), |b| {
            b.iter(|| ov_kdbx::write(black_box(&merged), &key).expect("write"))
        });
        g.bench_function(format!("open_merge_save/{total}"), |b| {
            b.iter(|| {
                let server = ov_kdbx::read(black_box(&remote_bytes), &key).expect("read server copy");
                let base = ov_kdbx::read(black_box(&base_bytes), &key).expect("read base");
                let (m, _) = ov_merge::merge(Some(&base), &local, &server, T_MERGE);
                ov_kdbx::write(&m, &key).expect("write merged")
            })
        });
    }
    g.finish();
}

criterion_group!(benches, merge);
criterion_main!(benches);
