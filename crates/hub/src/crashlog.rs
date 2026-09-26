// IT-AI — LAN remote control & screen sharing with an AI/MCP interface.
//
// Make the hub's own deaths visible in its log.
//
// AppCrane's log view shows stdout only. A Rust panic is printed to stderr, and a
// kernel OOM kill prints nothing at all, so for a long time both looked identical:
// a bare "IT-AI hub <ver>" startup banner with no reason in front of it. This
// module fixes both halves:
//
// - a panic hook that reports the panic on STDOUT (thread, file:line, message,
//   backtrace) before the default hook runs;
// - a memory watch that logs the container's cgroup memory against its limit as
//   it grows, plus the cgroup's own `oom_kill` counter. The kernel kills on
//   cgroup `memory.current` reaching `memory.max` — which counts more than the
//   process RSS — so that is the number worth watching, with RSS alongside.
//
// Reading the next restart then answers the question directly: a PANIC line means
// a code bug at a known location; memory climbing toward the limit (and/or a
// rising oom_kill) with no PANIC line means the 512 MB limit is killing us.

use std::io::Write;
use std::time::Duration;

pub fn install() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown location>".to_string());
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());
        let bt = std::backtrace::Backtrace::force_capture();
        println!("PANIC in thread '{name}' at {loc}: {msg}\n{bt}");
        let _ = std::io::stdout().flush();
        default_hook(info);
    }));

    if let Some(m) = sample() {
        // At startup this is the evidence for the PREVIOUS death: if the container
        // was restarted in place and the kernel OOM-killed it, oom_kill is > 0 here.
        println!("mem: startup {}", m.line());
    }
    spawn_memory_watch();
}

struct Sample {
    rss_mb: Option<u64>,
    cg_mb: Option<u64>,
    limit_mb: Option<u64>,
    oom_kills: Option<u64>,
}

impl Sample {
    fn line(&self) -> String {
        let f = |v: Option<u64>| v.map(|n| n.to_string()).unwrap_or_else(|| "?".to_string());
        format!(
            "rss={}MB cgroup={}MB/{}MB oom_kill={}",
            f(self.rss_mb),
            f(self.cg_mb),
            self.limit_mb.map(|n| n.to_string()).unwrap_or_else(|| "none".to_string()),
            f(self.oom_kills),
        )
    }
}

fn spawn_memory_watch() {
    let _ = std::thread::Builder::new().name("memwatch".into()).spawn(|| {
        let mut last_logged: u64 = 0;
        let mut last_ooms: Option<u64> = None;
        let mut tick: u32 = 0;
        loop {
            std::thread::sleep(Duration::from_secs(30));
            tick = tick.wrapping_add(1);
            let Some(m) = sample() else { continue };
            let used = m.cg_mb.or(m.rss_mb).unwrap_or(0);
            let grew = used >= last_logged + 32;
            // Within 40% of the limit, log every sample: that is the window a
            // death happens in, and a 30 s gap is all we'd have before it.
            let near = m.limit_mb.is_some_and(|l| used * 10 >= l * 6);
            let ooms_moved = m.oom_kills.is_some() && m.oom_kills != last_ooms;
            let heartbeat = tick % 60 == 0; // every 30 min
            if grew || near || ooms_moved || heartbeat {
                println!("mem: {}", m.line());
                last_logged = used;
            }
            last_ooms = m.oom_kills;
        }
    });
}

fn sample() -> Option<Sample> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let rss_mb = std::fs::read_to_string("/proc/self/status").ok().and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("VmRSS:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<u64>().ok())
            .map(|kb| kb / 1024)
    });
    // cgroup v2 first, then v1.
    let read_u64 = |p: &str| std::fs::read_to_string(p).ok().and_then(|s| s.trim().parse::<u64>().ok());
    let mb = |b: u64| b / (1024 * 1024);
    let cg_mb = read_u64("/sys/fs/cgroup/memory.current")
        .or_else(|| read_u64("/sys/fs/cgroup/memory/memory.usage_in_bytes"))
        .map(mb);
    // "max" (v2) or a huge sentinel (v1) both mean no limit.
    let limit_mb = read_u64("/sys/fs/cgroup/memory.max")
        .or_else(|| read_u64("/sys/fs/cgroup/memory/memory.limit_in_bytes"))
        .filter(|b| *b < (1u64 << 60))
        .map(mb);
    let oom_kills = std::fs::read_to_string("/sys/fs/cgroup/memory.events").ok().and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("oom_kill "))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|n| n.parse::<u64>().ok())
    });
    Some(Sample { rss_mb, cg_mb, limit_mb, oom_kills })
}
