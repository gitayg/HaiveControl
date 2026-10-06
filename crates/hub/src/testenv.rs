// One HUB_DATA + env setup shared by every test module. Tests run on parallel
// threads in one process, and HUB_DATA / RELAY_TOKEN / MCP_TOKEN are process-wide:
// two fixtures each pointing HUB_DATA at their own dir would race, and a store
// file written under one dir would be looked for under the other.
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const MCP_TOKEN: &str = "legacy-jobs-test-token";
pub const RELAY_TOKEN: &str = "relay-shared-test-token";

pub fn init() -> &'static Path {
    static D: OnceLock<PathBuf> = OnceLock::new();
    D.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("it-ai-hub-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("policy.json"), r#"{"deny_patterns":["rm -rf"]}"#).unwrap();
        std::env::set_var("HUB_DATA", &dir);
        std::env::set_var("MCP_TOKEN", MCP_TOKEN);
        std::env::set_var("RELAY_TOKEN", RELAY_TOKEN);
        dir
    })
}
