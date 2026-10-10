// IT-AI — LAN remote control & screen sharing with an AI/MCP interface.

//! Owner-only persistence for the hub's private keys.
//!
//! `std::fs::write` creates a file 0666 & ~umask — 0644 on a normal host, i.e.
//! world-readable. For the CA key and the capability signing key that is not a
//! hardening nit: either one is the whole security boundary of the feature it
//! serves. Anyone who can read `cap.key` can mint capabilities and so bypass
//! `may_control`, `policy::enforce` and `audit`; anyone who can read `ca.key`
//! can sign a leaf for any agent name and impersonate that agent to a
//! controller. "Anyone" includes a second local account, a sidecar, a backup and
//! a volume snapshot.
//!
//! So secrets are created 0600 inside a 0700 directory. A secret FOUND with
//! wider permissions is tightened and reported at top volume, never quietly
//! used: the loud report is the point, because tightening alone would hide that
//! the key was readable for however long it sat there. It is only refused when
//! it cannot be tightened — see `read_secret`, which explains why an outage is
//! the wrong answer on the upgrade that fixes the problem.

use std::io;
use std::path::Path;

/// Create `dir` if needed and, on unix, make it owner-only. A pre-existing
/// directory is tightened too: the key files inside it are what this protects,
/// and a 0755 data dir lets a reader at least enumerate them.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Read a secret file. `Ok(None)` means it does not exist yet (generate one);
/// `Err` means it exists but must not be used — including the case that matters
/// most, a key whose mode grants any access to group or other.
pub fn read_secret(path: &Path) -> io::Result<Option<String>> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Any group or other bit at all. Owner bits are not checked: 0o400 and
        // 0o600 are both fine, and an owner-execute bit exposes nothing.
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            // UPGRADE PATH. Every hub that ran before this module existed has a
            // 0644 key sitting in a 0755 data dir, because `std::fs::write` made
            // it that way. Refusing outright would take those hubs down on the
            // upgrade that fixes the problem — and refusing does not un-expose a
            // key that has already been readable for months, it just adds an
            // outage to the exposure. So if we own the file we tighten it and say
            // so loudly; the operator still gets an auditable record and a reason
            // to rotate. If we CANNOT tighten it, something is wrong that we are
            // not entitled to paper over, and it is refused.
            match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
                Ok(()) => {
                    // println!, not eprintln!: the hub logs entirely on stdout
                    // (it contains no other eprintln!), and the container log
                    // view does not surface stderr — a warning nobody can read
                    // would make tightening-instead-of-refusing indefensible,
                    // because the audit record IS the justification.
                    println!(
                        "SECURITY: {} was mode {:04o} — readable beyond its owner — and has been \
                         tightened to 0600. It was exposed for as long as it sat there, so treat \
                         it as compromised and rotate it when you can.",
                        path.display(),
                        mode,
                    );
                    // The dir it lives in is just as much of a leak, and a hub
                    // upgrading from before this module has a 0755 one.
                    if let Some(dir) = path.parent() {
                        let _ = ensure_private_dir(dir);
                    }
                }
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "{} is mode {:04o} — readable beyond its owner — and could not be \
                             tightened ({e}), so it is refused rather than used. \
                             Run: chmod 600 {} && chmod 700 {}",
                            path.display(),
                            mode,
                            path.display(),
                            path.parent().unwrap_or(Path::new(".")).display(),
                        ),
                    ));
                }
            }
        }
    }
    let _ = meta;
    std::fs::read_to_string(path).map(Some)
}

/// Write a secret that does not exist yet, owner-only from the moment it is
/// created. `create_new` rather than `create`: the caller only reaches here when
/// `read_secret` said the file was missing or unusable, and clobbering a key that
/// turned out to be there (because another worker thread raced us, or because it
/// was rejected for its mode) would destroy it.
pub fn write_new_secret(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Set at open(2) time, so the file is never briefly world-readable.
        opts.mode(0o600);
    }
    // On Windows there is no mode here: the file inherits the ACL of the data
    // directory, which is whatever the deployment gives it. That is a weaker
    // guarantee than the unix path and is stated rather than papered over.
    let mut f = opts.open(path)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()
}

/// Write a secret that is REWRITTEN over its lifetime — a token map gains and
/// loses entries — so unlike `write_new_secret` an existing file is expected and is
/// replaced.
///
/// Replaced, never truncated in place: truncate-then-write lets a crash, or a reader
/// that opens the file mid-write, see it empty or half-written — and every caller
/// treats an unparseable file as no file, i.e. every owner token, device secret or
/// VPN pass gone. So the new content goes to a temp file in the same directory
/// (same filesystem, so the rename is atomic), created 0600 at open(2) time, synced,
/// then renamed over the target: a reader sees the old file or the new one, whole.
/// The rename also replaces a file an older hub left 0644 with a 0600 one.
pub fn write_secret(path: &Path, contents: &str) -> io::Result<()> {
    replace_secret(path, contents, || Ok(()))
}

/// `write_secret`, with `before_rename` run once the temp file is complete — the
/// point a test injects a failure at.
fn replace_secret(path: &Path, contents: &str, before_rename: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    // Unique per write, so two writers (threads, or two hub processes on one data dir)
    // never share a temp file; `create_new` refuses one that somehow exists.
    let tmp = dir.join(format!(".{name}.{}.{}.tmp", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
    let written = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
        drop(f);
        before_rename()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // The rename itself is durable only once the directory entry is: best effort, as
    // not every platform lets a directory be opened and synced.
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests;
