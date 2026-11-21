//! Phase 0 (M0) local technical spike benchmarks for `spec.md` §2.3 & §14.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Instant;

use airlock_policy::crypto::sha256;
use airlock_policy::PhantomToken;
use airlock_proto::{FrameFlags, StreamType, VsockFrame};
use airlockd::commit_gate::{inspect_diff, DiffAction, DiffEntry, JournaledCommitter};
use airlockd::cow::prepare_scrubbed_base;

fn create_synthetic_repo(root: &Path, num_files: usize) {
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join(".env"), "OPENAI_API_KEY=sk-real-secret999\n").unwrap();
    fs::write(root.join(".env.example"), "PORT=8080\nOPENAI_API_KEY=\n").unwrap();
    fs::write(
        root.join(".git/config"),
        "[remote \"origin\"]\n\turl = https://x:ghp_secretpat@github.com/org/app.git\n",
    )
    .unwrap();

    for d in 0..10 {
        fs::create_dir_all(root.join(format!("src/mod_{d}"))).unwrap();
    }
    for i in 0..num_files {
        let p = root.join(format!("src/mod_{}/file_{i}.rs", i % 10));
        fs::write(p, format!("pub fn f_{i}() -> u32 {{ {i} }}\n")).unwrap();
    }
}

fn dir_contains_str(dir: &Path, needle: &str) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if dir_contains_str(&p, needle) {
                return true;
            }
        } else if let Ok(bytes) = fs::read(&p) {
            if String::from_utf8_lossy(&bytes).contains(needle) {
                return true;
            }
        }
    }
    false
}

fn bench_cow_repo(base: &Path, count: usize) {
    let host_repo = base.join(format!("repo_{count} "));
    create_synthetic_repo(&host_repo, count);

    let mut samples_ms = Vec::new();
    let mut method_name = String::new();
    for iter in 0..5 {
        let stage = base.join(format!("stage_{count}_{iter}"));
        let t0 = Instant::now();
        let report = prepare_scrubbed_base(&host_repo, &stage, true).expect("scrub");
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        samples_ms.push(ms);
        method_name = format!("{:?}", report.clone_method);

        assert!(!dir_contains_str(&stage, "sk-real-secret999"));
        assert!(!dir_contains_str(&stage, "ghp_secretpat"));
        let _ = fs::remove_dir_all(&stage);
    }
    samples_ms.sort_by(|a, b| a.total_cmp(b));
    println!(
        "M0_COW_SCRUB files={count} method={method_name} median_ms={:.2} max_ms={:.2} leaked_secrets=0",
        samples_ms[2], samples_ms[4]
    );
}

fn bench_vsock_framing() {
    let payload = vec![0xABu8; 16 * 1024];
    let frame = VsockFrame::new(StreamType::ExecIo, 1, FrameFlags::NONE, payload);
    let mut wire = Vec::with_capacity(17 * 1024);

    let iters = 100_000usize;
    let t0 = Instant::now();
    for _ in 0..iters {
        frame.encode_into(&mut wire).unwrap();
        let (_decoded, _) = VsockFrame::decode(&wire).unwrap();
    }
    let elapsed = t0.elapsed();
    let total_bytes = (iters as f64) * (wire.len() as f64);
    let gbps = (total_bytes * 8.0) / (elapsed.as_secs_f64() * 1e9);
    let ns_per_op = elapsed.as_nanos() as f64 / (iters as f64);
    println!(
        "M0_VSOCK_FRAME iters={iters} payload_bytes=16384 throughput_gbps={gbps:.2} ns_per_roundtrip={ns_per_op:.1}"
    );
}

fn bench_phantom_tokens() {
    let key = [0x11u8; 32];
    let iters = 50_000usize;
    let t0 = Instant::now();
    for i in 0..iters {
        let tok = PhantomToken::mint(&key, "chmb_bench", 7, "github_agent_pr");
        let cap = PhantomToken::verify(&tok, &key, "chmb_bench", 7).unwrap();
        assert_eq!(cap, "github_agent_pr");
        std::hint::black_box(i);
    }
    let us_per_op = t0.elapsed().as_secs_f64() * 1e6 / (iters as f64);
    println!("M0_PHANTOM_HMAC iters={iters} us_per_mint_verify={us_per_op:.2}");
}

fn bench_commit_gate(base: &Path) {
    let repo = base.join("cg_repo");
    let undo_root = base.join("cg_undo");
    fs::create_dir_all(repo.join("src")).unwrap();

    let mut baseline = BTreeMap::new();
    let mut entries = Vec::new();
    for i in 0..500 {
        let rel = format!("src/f_{i}.rs");
        let orig = format!("pub fn f() -> usize {{ {i} }}\n").into_bytes();
        fs::write(repo.join(&rel), &orig).unwrap();
        baseline.insert(rel.clone(), sha256(&orig));
        entries.push(DiffEntry {
            rel_path: rel,
            action: DiffAction::WriteFile(format!("pub fn f() -> usize {{ {} }}\n", i + 1).into_bytes()),
            mode: 0o100644,
        });
    }

    let t0 = Instant::now();
    let report = inspect_diff(&repo, &baseline, &entries);
    let scan_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert!(!report.has_hard_blocks());
    assert!(!report.requires_review());

    let committer = JournaledCommitter::new(undo_root);
    let t1 = Instant::now();
    committer.apply_atomic(&repo, "m0_sess", &entries).unwrap();
    let apply_ms = t1.elapsed().as_secs_f64() * 1000.0;

    let t2 = Instant::now();
    committer.undo(&repo, "m0_sess").unwrap();
    let undo_ms = t2.elapsed().as_secs_f64() * 1000.0;

    assert_eq!(
        fs::read(repo.join("src/f_42.rs")).unwrap(),
        b"pub fn f() -> usize { 42 }\n"
    );
    println!(
        "M0_COMMIT_GATE files=500 scan_ms={scan_ms:.2} apply_ms={apply_ms:.2} undo_ms={undo_ms:.2} total_gate_ms={:.2}",
        scan_ms + apply_ms
    );
}

fn main() {
    let base = std::env::temp_dir().join(format!("airlock-m0-bench-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();

    bench_cow_repo(&base, 1_000);
    bench_cow_repo(&base, 10_000);
    bench_vsock_framing();
    bench_phantom_tokens();
    bench_commit_gate(&base);

    let _ = fs::remove_dir_all(&base);
}
