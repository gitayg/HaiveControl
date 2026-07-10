// HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The HaiveControl Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// HaiveControl MCP server — exposes registered devices as MCP tools so an AI
// client can list_devices, screenshot, run_command, control input, and move
// files. Runs on your Mac; it drives devices entirely through the hub's /m API
// (token + owner authed), so it works against cloud/relay devices too — not
// just the LAN. Env:
//   HAIVE_HUB       hub base URL (default http://localhost:8770)
//   HIVE_MCP_TOKEN  token for the hub's /m API (matches the hub's MCP_TOKEN)
//   HIVE_OWNER      owner id to act as (per-user hub scoping)
//   HAIVE_CAFILE    optional PEM to verify a self-signed hub cert
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

impl AgentInfo {
    /// The proxy target the hub understands: `relay://id` for relay devices,
    /// else `scheme://ip:port`.
    fn target(&self) -> String {
        if self.scheme == "relay" {
            format!("relay://{}", self.ip)
        } else {
            format!("{}://{}:{}", self.scheme, self.ip, self.port)
        }
    }
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
#[derive(Deserialize, schemars::JsonSchema)]
struct ReportArgs {
    device: String,
    /// one of: hardware, av, encryption, firewall, processes, services, network, packages
    kind: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct ActionArgs {
    device: String,
    /// one of: reboot, shutdown, sleep, logoff, firewall_on, firewall_off, usb_lock, usb_unlock
    action: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct MessageArgs {
    device: String,
    text: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct PackageArgs {
    device: String,
    /// package id (winget id on Windows, brew formula on macOS, apt package on Linux)
    package: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct FleetRunArgs {
    /// shell command to run on every device you own, in parallel
    command: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct FleetReportArgs {
    /// one of: hardware, av, encryption, firewall, processes, services, network, packages
    kind: String,
}

#[derive(Clone)]
struct Srv {
    #[allow(dead_code)]
    tool_router: ToolRouter<Srv>,
    hub: String,
    mtok: String,
    owner: String,
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
            mtok: std::env::var("HIVE_MCP_TOKEN").unwrap_or_default(),
            owner: std::env::var("HIVE_OWNER").unwrap_or_default(),
            client: b.build().expect("build http client"),
        }
    }

    /// Build a hub /m URL: `{hub}/m/{action}?mtok=…&owner=…[&extra]`.
    fn m(&self, action: &str, extra: &str) -> String {
        let base = self.hub.trim_end_matches('/');
        let mut u = format!("{base}/m/{action}?mtok={}&owner={}", urlencode(&self.mtok), urlencode(&self.owner));
        if !extra.is_empty() {
            u.push('&');
            u.push_str(extra);
        }
        u
    }

    async fn agents(&self) -> Result<Vec<AgentInfo>, String> {
        let v: serde_json::Value = self
            .client
            .get(self.m("agents", ""))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(serde_json::from_value(v["agents"].clone()).unwrap_or_default())
    }

    /// Resolve a device name to its hub proxy target.
    async fn resolve(&self, name: &str) -> Result<String, String> {
        let agents = self.agents().await?;
        let exact: Vec<&AgentInfo> = agents.iter().filter(|a| a.name.eq_ignore_ascii_case(name) || a.ip == name).collect();
        let m: Vec<&AgentInfo> = if exact.is_empty() {
            agents.iter().filter(|a| a.name.to_lowercase().contains(&name.to_lowercase())).collect()
        } else {
            exact
        };
        match m.len() {
            0 if agents.is_empty() => Err(format!(
                "no devices visible for this owner ('{}'). Check HIVE_OWNER matches how the device was enrolled (--owner …), or unset it to see all.",
                self.owner
            )),
            0 => Err(format!(
                "no device matching '{name}'. Visible devices: {}",
                agents.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", ")
            )),
            1 => Ok(m[0].target()),
            _ => Err(format!("ambiguous device: {}", m.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", "))),
        }
    }

    async fn input(&self, target: &str, ev: serde_json::Value) -> Result<(), ErrorData> {
        self.client
            .post(self.m("input", ""))
            .json(&serde_json::json!({"target": target, "ev": ev}))
            .send()
            .await
            .map_err(err)?;
        Ok(())
    }
}

#[tool_router]
impl Srv {
    #[tool(description = "List devices you own on the hub, with full details (OS, user, CPU, memory, live CPU load + free RAM, interfaces, cameras, mics, last-seen). Returns JSON.")]
    async fn list_devices(&self) -> Result<CallToolResult, ErrorData> {
        let v: serde_json::Value = self.client.get(self.m("agents", "")).send().await.map_err(err)?.json().await.map_err(err)?;
        let agents = v.get("agents").cloned().unwrap_or_else(|| serde_json::json!([]));
        let text = serde_json::to_string_pretty(&agents).unwrap_or_else(|_| "[]".to_string());
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Run a shell command on the named device and return its output.")]
    async fn run_command(&self, Parameters(a): Parameters<RunArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let out: serde_json::Value = self
            .client
            .post(self.m("exec", ""))
            .json(&serde_json::json!({"target": target, "cmd": a.command}))
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
        let target = self.resolve(&a.device).await.map_err(err)?;
        let bytes = self
            .client
            .get(self.m("frame", &format!("target={}", urlencode(&target))))
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
        let target = self.resolve(&a.device).await.map_err(err)?;
        let extra = match a.index {
            Some(i) => format!("target={}&index={i}", urlencode(&target)),
            None => format!("target={}", urlencode(&target)),
        };
        let bytes = self.client.get(self.m("camera", &extra)).send().await.map_err(err)?.bytes().await.map_err(err)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok(CallToolResult::success(vec![ContentBlock::image(b64, "image/jpeg")]))
    }

    #[tool(description = "Update the agent on the device to the latest build hosted by the hub (self-replace + restart).")]
    async fn update_agent(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let text = self.client.get(self.m("update", &format!("target={}", urlencode(&target)))).send().await.map_err(err)?.text().await.map_err(err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Dissolve the agent on the device — stop it and remove its autostart (the binary is not deleted).")]
    async fn dissolve_agent(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let text = self.client.get(self.m("dissolve", &format!("target={}", urlencode(&target)))).send().await.map_err(err)?.text().await.map_err(err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Download a file from the device to the Mac. Returns the local path.")]
    async fn download_file(&self, Parameters(a): Parameters<DownloadArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let url = self.m("download", &format!("target={}&path={}", urlencode(&target), urlencode(&a.remote_path)));
        let bytes = self.client.get(url).send().await.map_err(err)?.bytes().await.map_err(err)?;
        let local = a.save_as.filter(|s| !s.is_empty()).unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_default();
            let name = std::path::Path::new(&a.remote_path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "download".to_string());
            format!("{home}/Downloads/{name}")
        });
        std::fs::write(&local, &bytes).map_err(err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("saved to {local}"))]))
    }

    #[tool(description = "Upload a local file to the device. Returns the saved remote path.")]
    async fn upload_file(&self, Parameters(a): Parameters<UploadArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let data = std::fs::read(&a.local_path).map_err(err)?;
        let name = std::path::Path::new(&a.local_path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "upload.bin".to_string());
        let part = reqwest::multipart::Part::bytes(data).file_name(name);
        let mut form = reqwest::multipart::Form::new().part("file", part);
        if let Some(dir) = a.remote_dir.filter(|d| !d.is_empty()) {
            form = form.text("dir", dir);
        }
        let out: serde_json::Value = self
            .client
            .post(self.m("upload", &format!("target={}", urlencode(&target))))
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
        let target = self.resolve(&a.device).await.map_err(err)?;
        let btn = match a.button.as_deref() { Some("right") => 2, Some("middle") => 1, _ => 0 };
        self.input(&target, serde_json::json!({"type":"down","button":btn,"x":a.x,"y":a.y})).await?;
        self.input(&target, serde_json::json!({"type":"up","button":btn})).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("clicked at ({:.3}, {:.3})", a.x, a.y))]))
    }

    #[tool(description = "Type text on the device as keystrokes.")]
    async fn type_text(&self, Parameters(a): Parameters<TypeArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        for c in a.text.chars() {
            let k = c.to_string();
            self.input(&target, serde_json::json!({"type":"key","action":"down","key":k})).await?;
            self.input(&target, serde_json::json!({"type":"key","action":"up","key":k})).await?;
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("typed {} chars", a.text.chars().count()))]))
    }

    #[tool(description = "Press a named key on the device (e.g. Enter, Tab, Escape, Backspace, ArrowDown).")]
    async fn press_key(&self, Parameters(a): Parameters<KeyArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        self.input(&target, serde_json::json!({"type":"key","action":"down","key":a.key})).await?;
        self.input(&target, serde_json::json!({"type":"key","action":"up","key":a.key})).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("pressed {}", a.key))]))
    }

    async fn sys(&self, device: &str, kind: &str, arg: &str) -> Result<String, ErrorData> {
        let target = self.resolve(device).await.map_err(err)?;
        let mut extra = format!("kind={}&target={}", urlencode(kind), urlencode(&target));
        if !arg.is_empty() {
            extra.push_str(&format!("&arg={}", urlencode(arg)));
        }
        let v: serde_json::Value = self.client.get(self.m("sys", &extra)).send().await.map_err(err)?.json().await.map_err(err)?;
        Ok(v["output"].as_str().or_else(|| v["error"].as_str()).unwrap_or("failed").to_string())
    }

    #[tool(description = "Get a system report from a device. kind: hardware, av (antivirus status), encryption (disk encryption), firewall, processes, services, network (ARP neighbors), packages (installed software).")]
    async fn system_report(&self, Parameters(a): Parameters<ReportArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, &a.kind, "").await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Run a device action: reboot, shutdown, sleep, logoff, firewall_on, firewall_off, usb_lock, usb_unlock (USB storage lock is Windows-only).")]
    async fn device_action(&self, Parameters(a): Parameters<ActionArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, &a.action, "").await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("{}: {}", a.action, out))]))
    }

    #[tool(description = "Show a popup message to the logged-in user on the device.")]
    async fn message_user(&self, Parameters(a): Parameters<MessageArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, "message", &a.text).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Install a software package on the device (winget on Windows, brew on macOS, apt on Linux).")]
    async fn install_package(&self, Parameters(a): Parameters<PackageArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, "install", &a.package).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Uninstall a software package from the device (winget/brew/apt).")]
    async fn uninstall_package(&self, Parameters(a): Parameters<PackageArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, "uninstall", &a.package).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Check for available OS/app updates on the device (winget upgrade / softwareupdate -l / apt upgradable). Use device_action 'update_all' to apply them.")]
    async fn check_updates(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, "updates", "").await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Run a security compliance check on the device (disk encryption, firewall, antivirus, OS updates) and return a score/grade with per-check pass/fail.")]
    async fn compliance_posture(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let v: serde_json::Value = self.client.get(self.m("sys", &format!("kind=posture&target={}", urlencode(&target)))).send().await.map_err(err)?.json().await.map_err(err)?;
        let mut s = format!("Compliance: {} ({}/100)\n", v["grade"].as_str().unwrap_or("?"), v["score"].as_i64().unwrap_or(0));
        if let Some(cs) = v["checks"].as_array() {
            for c in cs {
                s.push_str(&format!("  [{}] {}\n", if c["pass"].as_bool().unwrap_or(false) { "PASS" } else { "FAIL" }, c["check"].as_str().unwrap_or("")));
            }
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(s)]))
    }

    async fn fleet(&self, extra: &str) -> Result<String, ErrorData> {
        let v: serde_json::Value = self.client.get(self.m("fleet", extra)).send().await.map_err(err)?.json().await.map_err(err)?;
        let out = v["results"]
            .as_array()
            .map(|arr| arr.iter().map(|r| format!("### {}\n{}", r["device"].as_str().unwrap_or("?"), r["output"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n\n"))
            .unwrap_or_else(|| "no devices".to_string());
        Ok(out)
    }

    #[tool(description = "Run a shell command on EVERY device you own, in parallel, and return each device's output.")]
    async fn fleet_run(&self, Parameters(a): Parameters<FleetRunArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.fleet(&format!("kind=exec&cmd={}", urlencode(&a.command))).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Run a system report (hardware, av, encryption, firewall, processes, services, network, packages) on EVERY device you own, in parallel.")]
    async fn fleet_report(&self, Parameters(a): Parameters<FleetReportArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.fleet(&format!("kind={}", urlencode(&a.kind))).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }
}

#[tool_handler]
impl ServerHandler for Srv {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(
            "Control HaiveControl devices by hub name: list_devices, screenshot, run_command, click/type_text/press_key, download_file, upload_file, camera_snapshot, update_agent, dissolve_agent.".to_string(),
        );
        info
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = Srv::new().serve((tokio::io::stdin(), tokio::io::stdout())).await?;
    service.waiting().await?;
    Ok(())
}
