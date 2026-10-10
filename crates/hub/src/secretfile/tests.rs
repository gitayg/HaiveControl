use super::*;
use std::path::PathBuf;

/// A fresh, empty owner-only directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("it-ai-secretfile-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    ensure_private_dir(&dir).unwrap();
    dir
}

/// Every name in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
#[test]
fn a_rewritten_secret_is_owner_only_and_complete() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("complete");
    let p = dir.join("owner_tokens.json");
    // The upgrade case: a file a pre-secretfile hub left world-readable.
    std::fs::write(&p, "old").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    let body = "x".repeat(100_000);
    write_secret(&p, &body).unwrap();
    assert_eq!(mode(&p), 0o600, "the rewritten secret is not owner-only");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), body, "the rewritten secret is not the full content");
    // And a file that did not exist yet.
    let q = dir.join("vpn.json");
    write_secret(&q, "{}").unwrap();
    assert_eq!((mode(&q), std::fs::read_to_string(&q).unwrap().as_str()), (0o600, "{}"));
    assert_eq!(names(&dir), ["owner_tokens.json", "vpn.json"], "temp files left behind");
}

/// A reader racing a rewrite sees the old content or the new one — never an empty or
/// half-written file, as a truncate-then-write lets it.
#[test]
fn a_concurrent_reader_never_sees_a_partial_secret() {
    let dir = scratch("reader");
    let p = dir.join("device_secrets.json");
    let a = "a".repeat(256 * 1024);
    let b = "b".repeat(256 * 1024);
    write_secret(&p, &a).unwrap();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer = {
        let (p, a, b, done) = (p.clone(), a.clone(), b.clone(), done.clone());
        std::thread::spawn(move || {
            for i in 0..400 {
                write_secret(&p, if i % 2 == 0 { &b } else { &a }).unwrap();
            }
            done.store(true, std::sync::atomic::Ordering::SeqCst);
        })
    };
    let (mut reads, mut saw_a, mut saw_b, mut bad) = (0usize, false, false, Vec::new());
    while !done.load(std::sync::atomic::Ordering::SeqCst) {
        let got = read_secret(&p).unwrap().expect("the secret vanished");
        reads += 1;
        if got == a {
            saw_a = true;
        } else if got == b {
            saw_b = true;
        } else if bad.len() < 5 {
            bad.push(got.len());
        }
    }
    writer.join().unwrap();
    assert!(bad.is_empty(), "a reader saw a partial secret, lengths {bad:?} of {} ({reads} reads)", a.len());
    assert!(saw_a && saw_b && reads > 10, "control: the reader did not overlap the rewrites ({reads} reads, a {saw_a}, b {saw_b})");
}

#[test]
fn a_failed_rewrite_leaves_the_original_intact() {
    let dir = scratch("failed");
    let p = dir.join("vpn.json");
    write_secret(&p, "original").unwrap();
    let r = replace_secret(&p, "replacement", || {
        // Control: the failure is injected with the temp file fully written.
        let tmps: Vec<String> = names(&dir).into_iter().filter(|n| n != "vpn.json").collect();
        assert_eq!(tmps.len(), 1, "control: no temp file before the rename: {tmps:?}");
        assert_eq!(std::fs::read_to_string(dir.join(&tmps[0])).unwrap(), "replacement", "control: the temp file is not complete");
        Err(io::Error::other("injected failure before the rename"))
    });
    assert!(r.is_err(), "the injected failure was swallowed");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "original", "a failed rewrite damaged the original");
    assert_eq!(names(&dir), ["vpn.json"], "the failed rewrite left its temp file behind");
}

#[test]
fn rewrites_leave_no_temp_files_and_concurrent_writers_do_not_collide() {
    let dir = scratch("tempfiles");
    let p = dir.join("owner_tokens.json");
    let writers: Vec<_> = (0..4)
        .map(|w| {
            let p = p.clone();
            std::thread::spawn(move || {
                for i in 0..50 {
                    write_secret(&p, &format!("writer {w} write {i}")).unwrap_or_else(|e| panic!("writer {w}, write {i}: {e}"));
                }
            })
        })
        .collect();
    for w in writers {
        w.join().expect("a concurrent writer failed");
    }
    assert!(std::fs::read_to_string(&p).unwrap().ends_with(" write 49"), "the last write of some writer is not what is there");
    assert_eq!(names(&dir), ["owner_tokens.json"], "temp files left behind");
}
