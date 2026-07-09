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
#[derive(Deserialize, schemars::JsonSchema)]
struct ClickArgs {
    device: String,
    /// horizontal position as a fraction of the screen width, 0.0 (left) to 1.0 (right)
    x: f64,
    /// vertical position as a fraction of the screen height, 0.0 (top) to 1.0 (bottom)
    y: f64,
    /// "left" (default), "right", or "middle"
    #[serde(default)]
    button: Option<String>,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct TypeArgs {
    device: String,
    text: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct KeyArgs {
    device: String,
    /// key name, e.g. Enter, Tab, Escape, Backspace, ArrowDown, F5
    key: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct CameraArgs {
    device: String,
    /// camera index, default 0
    #[serde(default)]
    index: Option<u32>,
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

    async fn input(&self, base: &str, ev: serde_json::Value) -> Result<(), ErrorData> {
        self.auth(self.client.post(format!("{base}/input")))
            .json(&ev)
            .send()
            .await
            .map_err(err)?;
        Ok(())
    }
}

#[tool_router]
impl Srv {
    #[tool(description = "List devices registered with the hub, with full details (OS, user, CPU, memory, all network interfaces, last-seen seconds). Returns JSON.")]
    async fn list_devices(&self) -> Result<CallToolResult, ErrorData> {
        let v: serde_json::Value = self
            .client
            .get(format!("{}/agents", self.hub.trim_end_matches('/')))
            .send()
            .await
            .map_err(err)?
            .json()
            .await
            .map_err(err)?;
        let agents = v.get("agents").cloned().unwrap_or_else(|| serde_json::json!([]));
        let text = serde_json::to_string_pretty(&agents).unwrap_or_else(|_| "[]".to_string());
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

    #[tool(description = "Capture a photo from the device's camera (webcam). Optional index selects the camera (default 0).")]
    async fn camera_snapshot(&self, Parameters(a): Parameters<CameraArgs>) -> Result<CallToolResult, ErrorData> {
        let base = self.resolve(&a.device).await.map_err(err)?;
        let url = match a.index {
            Some(i) => format!("{base}/camera?index={i}"),
            None => format!("{base}/camera"),
        };
        let bytes = self.auth(self.client.get(url)).send().await.map_err(err)?.bytes().await.map_err(err)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok(CallToolResult::success(vec![ContentBlock::image(b64, "image/jpeg")]))
    }

    #[tool(description = "Update the agent on the device to the latest build hosted by the hub (self-replace + restart).")]
    async fn update_agent(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let base = self.resolve(&a.device).await.map_err(err)?;
        let url = format!("{}/x/update?target={}", self.hub.trim_end_matches('/'), urlencode(&base));
        let text = self.client.get(url).send().await.map_err(err)?.text().await.map_err(err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Dissolve the agent on the device — stop it and remove its autostart (the binary is not deleted).")]
    async fn dissolve_agent(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let base = self.resolve(&a.device).await.map_err(err)?;
        let url = format!("{}/x/dissolve?target={}", self.hub.trim_end_matches('/'), urlencode(&base));
        let text = self.client.get(url).send().await.map_err(err)?.text().await.map_err(err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
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

    #[tool(description = "Click at a position on the device's screen. x and y are fractions 0.0-1.0 from the top-left.")]
    async fn click(&self, Parameters(a): Parameters<ClickArgs>) -> Result<CallToolResult, ErrorData> {
        let base = self.resolve(&a.device).await.map_err(err)?;
        let btn = match a.button.as_deref() { Some("right") => 2, Some("middle") => 1, _ => 0 };
        self.input(&base, serde_json::json!({"type":"down","button":btn,"x":a.x,"y":a.y})).await?;
        self.input(&base, serde_json::json!({"type":"up","button":btn})).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("clicked at ({:.3}, {:.3})", a.x, a.y))]))
    }

    #[tool(description = "Type text on the device as keystrokes.")]
    async fn type_text(&self, Parameters(a): Parameters<TypeArgs>) -> Result<CallToolResult, ErrorData> {
        let base = self.resolve(&a.device).await.map_err(err)?;
        for c in a.text.chars() {
            let k = c.to_string();
            self.input(&base, serde_json::json!({"type":"key","action":"down","key":k})).await?;
            self.input(&base, serde_json::json!({"type":"key","action":"up","key":k})).await?;
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("typed {} chars", a.text.chars().count()))]))
    }

    #[tool(description = "Press a named key on the device (e.g. Enter, Tab, Escape, Backspace, ArrowDown).")]
    async fn press_key(&self, Parameters(a): Parameters<KeyArgs>) -> Result<CallToolResult, ErrorData> {
        let base = self.resolve(&a.device).await.map_err(err)?;
        self.input(&base, serde_json::json!({"type":"key","action":"down","key":a.key})).await?;
        self.input(&base, serde_json::json!({"type":"key","action":"up","key":a.key})).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("pressed {}", a.key))]))
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
