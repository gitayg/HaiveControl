// IT-AI — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The IT-AI Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

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
//! So secrets are created 0600 inside a 0700 directory, and — just as important
//! — a secret that is found with wider permissions is REFUSED rather than
//! quietly tightened or quietly used. Tightening would hide that the key was
//! readable for however long it sat there; using it anyway would make the
//! permissions decorative.

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
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is mode {:04o} — readable beyond its owner, so it is refused rather than used. \
                     Run: chmod 600 {} && chmod 700 {}",
                    path.display(),
                    mode,
                    path.display(),
                    path.parent().unwrap_or(Path::new(".")).display(),
                ),
            ));
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
