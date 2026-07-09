// HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The HaiveControl Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// HaiveControl MCP server — exposes registered devices as MCP tools so an AI
// client can list_devices, screenshot, run_command, download_file, upload_file.
// Runs on the Mac next to the hub. Env: HAIVE_HUB, SCREEN_PW, HAIVE_CAFILE.
use base64::Engine;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use serde::Deserialize;

#[derive(Deserialize, Default, Clone)]
struct AgentInfo {
    name: String,
    ip: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    scheme: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct DeviceArg {
    device: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct RunArgs {
    device: String,
    command: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct DownloadArgs {
    device: String,
    remote_path: String,
    #[serde(default)]
    save_as: Option<String>,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct UploadArgs {
    device: String,
    local_path: String,
    #[serde(default)]
    remote_dir: Option<String>,
}

#[derive(Clone)]
struct Srv {
    #[allow(dead_code)]
    tool_router: ToolRouter<Srv>,
    hub: String,
    password: Option<String>,
    client: reqwest::Client,
}

fn err(e: impl ToString) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl Srv {
    fn new() -> Self {
        let cafile = std::env::var("HAIVE_CAFILE").ok();
        let mut b = reqwest::Client::builder();
        match cafile.and_then(|p| std::fs::read(p).ok()).and_then(|p| reqwest::Certificate::from_pem(&p).ok()) {
            Some(cert) => b = b.add_root_certificate(cert),
            None => b = b.danger_accept_invalid_certs(true),
        }
        Self {
            tool_router: Self::tool_router(),
            hub: std::env::var("HAIVE_HUB").unwrap_or_else(|_| "http://localhost:8770".to_string()),
            password: std::env::var("SCREEN_PW").ok(),
            client: b.build().expect("build http client"),
        }
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.password {
            Some(p) => rb.basic_auth("admin", Some(p)),
            None => rb,
        }
    }

    async fn agents(&self) -> Result<Vec<AgentInfo>, String> {
        let v: serde_json::Value = self
            .client
            .get(format!("{}/agents", self.hub.trim_end_matches('/')))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(serde_json::from_value(v["agents"].clone()).unwrap_or_default())
    }

    async fn resolve(&self, name: &str) -> Result<String, String> {
        let agents = self.agents().await?;
        let exact: Vec<&AgentInfo> = agents
            .iter()
            .filter(|a| a.name.eq_ignore_ascii_case(name) || a.ip == name)
            .collect();
        let m: Vec<&AgentInfo> = if exact.is_empty() {
            agents.iter().filter(|a| a.name.to_lowercase().contains(&name.to_lowercase())).collect()
        } else {
            exact
        };
        match m.len() {
            0 => Err(format!("no device matching '{name}' — call list_devices first")),
            1 => Ok(format!("{}://{}:{}", m[0].scheme, m[0].ip, m[0].port)),
            _ => Err(format!("ambiguous device: {}", m.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", "))),
        }
    }
}

#[tool_router]
impl Srv {
    #[tool(description = "List devices currently registered with the hub (ready to connect).")]
    async fn list_devices(&self) -> Result<CallToolResult, ErrorData> {
        let agents = self.agents().await.map_err(err)?;
        let text = if agents.is_empty() {
            "no devices registered".to_string()
        } else {
            agents
                .iter()
                .map(|a| format!("{} — {}://{}:{}", a.name, a.scheme, a.ip, a.port))
                .collect::<Vec<_>>()
                .join("\n")
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Run a shell command on the named device and return its output.")]
    async fn run_command(&self, Parameters(a): Parameters<RunArgs>) -> Result<CallToolResult, ErrorData> {
        let base = self.resolve(&a.device).await.map_err(err)?;
        let out: serde_json::Value = self
            .auth(self.client.post(format!("{base}/exec")))
            .json(&serde_json::json!({"cmd": a.command}))
            .send()
            .await
            .map_err(err)?
            .json()
            .await
            .map_err(err)?;
        let text = if out["ok"].as_bool().unwrap_or(false) {
            let s = format!("{}{}", out["stdout"].as_str().unwrap_or(""), out["stderr"].as_str().unwrap_or(""));
            if s.is_empty() { format!("(exit {})", out["code"].as_i64().unwrap_or(0)) } else { s }
        } else {
            format!("[error] {}", out["error"].as_str().unwrap_or("failed"))
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Capture the current screen of the named device as an image.")]
    async fn screenshot(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let base = self.resolve(&a.device).await.map_err(err)?;
        let bytes = self
            .auth(self.client.get(format!("{base}/frame")))
            .send()
            .await
            .map_err(err)?
            .bytes()
            .await
            .map_err(err)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok(CallToolResult::success(vec![ContentBlock::image(b64, "image/jpeg")]))
    }

    #[tool(description = "Download a file from the device to the Mac. Returns the local path.")]
    async fn download_file(&self, Parameters(a): Parameters<DownloadArgs>) -> Result<CallToolResult, ErrorData> {
        let base = self.resolve(&a.device).await.map_err(err)?;
        let url = format!("{base}/download?path={}", urlencode(&a.remote_path));
        let bytes = self.auth(self.client.get(url)).send().await.map_err(err)?.bytes().await.map_err(err)?;
        let local = a.save_as.filter(|s| !s.is_empty()).unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_default();
            let name = std::path::Path::new(&a.remote_path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "download".to_string());
            format!("{home}/Downloads/{name}")
        });
        std::fs::write(&local, &bytes).map_err(err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("saved to {local}"))]))
    }

    #[tool(description = "Upload a local file to the device. Returns the saved remote path.")]
    async fn upload_file(&self, Parameters(a): Parameters<UploadArgs>) -> Result<CallToolResult, ErrorData> {
        let base = self.resolve(&a.device).await.map_err(err)?;
        let data = std::fs::read(&a.local_path).map_err(err)?;
        let name = std::path::Path::new(&a.local_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "upload.bin".to_string());
        let part = reqwest::multipart::Part::bytes(data).file_name(name);
        let mut form = reqwest::multipart::Form::new().part("file", part);
        if let Some(dir) = a.remote_dir.filter(|d| !d.is_empty()) {
            form = form.text("dir", dir);
        }
        let out: serde_json::Value = self
            .auth(self.client.post(format!("{base}/upload")))
            .multipart(form)
            .send()
            .await
            .map_err(err)?
            .json()
            .await
            .map_err(err)?;
        let text = if out["ok"].as_bool().unwrap_or(false) {
            out["saved"].as_str().unwrap_or("").to_string()
        } else {
            format!("[error] {}", out["error"].as_str().unwrap_or("failed"))
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }
}

#[tool_handler]
impl ServerHandler for Srv {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions =
            Some("Control HaiveControl devices by hub name: list_devices, screenshot, run_command, download_file, upload_file.".to_string());
        info
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = Srv::new().serve((tokio::io::stdin(), tokio::io::stdout())).await?;
    service.waiting().await?;
    Ok(())
}
