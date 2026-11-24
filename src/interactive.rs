use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::fmt::{self, Display};
use std::io::{self, BufWriter, Write};
use std::sync::Arc;

use singbox_clash_api::{Client, Connection, Snapshot};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{self, Instant, MissedTickBehavior};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const SCROLLOFF: usize = 5;
const MIN_SIZE: (u16, u16) = (42, 8);
const GAP: &str = "  ";
const COLUMNS: usize = 5;
const HEADERS: [&str; COLUMNS] = ["TYPE", "NAME", "M", "NOW", "MS"];
const ALIGNS: [Align; COLUMNS] = [
    Align::Left,
    Align::Left,
    Align::Right,
    Align::Left,
    Align::Right,
];
const DELAY_CAP: usize = 24;
const DELAY_STALE_AFTER: Duration = Duration::from_secs(60);
const HINT: &str =
    " Enter select | c conns | / filter | esc clear | h/j/k/l move | o open | q quit";
const CONN_COLS: usize = 8;
const CONN_HEADERS: [&str; CONN_COLS] = [
    "NET",
    "SOURCE",
    "DESTINATION",
    "CHAIN",
    "RULE",
    "UP",
    "DOWN",
    "AGE",
];
const CONN_ALIGNS: [Align; CONN_COLS] = [
    Align::Left,
    Align::Left,
    Align::Left,
    Align::Left,
    Align::Left,
    Align::Right,
    Align::Right,
    Align::Right,
];
const CONN_HINT: &str = " K kill | X all | V visible | c/esc back | h/j/k/l move | o open | q quit";

const PROXY_DELAY_INTERVAL: Duration = Duration::from_secs(5);
const BACKGROUNG_PROXY_DELAY_INTERVAL: Duration = Duration::from_secs(14);
const PROXIES_REFRESH_INTERVAL: Duration = Duration::from_secs(21);
const CONNECTIONS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const BACKGROUND_CONNECTIONS_REFRESH_INTERVAL: Duration = Duration::from_secs(14);
const DELAY_MAX_CONCURRENT_PROBES: usize = 100;

const SLEEP_TIMEOUT: Duration = Duration::from_secs(60);

macro_rules! reset_term {
    ($out:expr) => {
        queue!(
            $out,
            crossterm::style::SetAttribute(crossterm::style::Attribute::Reset),
            crossterm::cursor::Hide
        )
    };
}

#[derive(Clone, Copy)]
enum Align {
    Left,
    Right,
}

const PAD: &str = "                                                                                                                ";

fn write_pad(out: &mut impl Write, mut n: usize) -> io::Result<()> {
    while n > 0 {
        let chunk = n.min(PAD.len());
        out.write_all(&PAD[..chunk].as_bytes())?;
        n -= chunk;
    }
    Ok(())
}

fn write_fit(out: &mut impl Write, text: &str, width: usize, align: Align) -> io::Result<()> {
    let tw = text.width();
    if tw <= width {
        let pad = width - tw;
        match align {
            Align::Left => {
                out.write_all(text.as_bytes())?;
                write_pad(out, pad)?;
            }
            Align::Right => {
                write_pad(out, pad)?;
                out.write_all(text.as_bytes())?;
            }
        }
        return Ok(());
    }
    let mut used = 0usize;
    let mut end = 0usize;
    for (i, ch) in text.char_indices() {
        let w = ch.width().unwrap_or(0);
        if used + w + 1 > width {
            break;
        }
        used += w;
        end = i + ch.len_utf8();
    }
    let truncated = &text[..end];
    let pad = width.saturating_sub(used + 1);
    match align {
        Align::Left => {
            out.write_all(truncated.as_bytes())?;
            out.write_all("…".as_bytes())?;
            write_pad(out, pad)?;
        }
        Align::Right => {
            write_pad(out, pad)?;
            out.write_all("…".as_bytes())?;
            out.write_all(truncated.as_bytes())?;
        }
    }
    Ok(())
}

fn restore_terminal() {
    let _ = execute!(io::stdout(), cursor::Show, LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
}

struct TerminalGuard;

impl TerminalGuard {
    fn new() -> io::Result<Self> {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            default_hook(info);
        }));
        terminal::enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, cursor::Hide)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

#[derive(Debug, Clone, Copy)]
enum Delay {
    None,
    Success { ms: u16, at: Instant },
    Fail { at: Instant },
}

impl Delay {
    fn display(&self) -> (String, Color) {
        match *self {
            Delay::None => ("-".into(), Color::White),
            Delay::Fail { at } => {
                let color = if at.elapsed() > DELAY_STALE_AFTER {
                    Color::White
                } else {
                    Color::Red
                };
                ("X".into(), color)
            }
            Delay::Success { ms, at } => {
                let color = if at.elapsed() > DELAY_STALE_AFTER {
                    Color::White
                } else {
                    match ms {
                        0..=75 => Color::Cyan,
                        76..=150 => Color::Green,
                        151..=300 => Color::Yellow,
                        301..=1000 => Color::Red,
                        1001..=2000 => Color::Magenta,
                        _ => Color::Blue,
                    }
                };
                (ms.to_string(), color)
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    kind: String,
    name: String,
    members: Vec<String>,
    now: Option<String>,
    delay: Delay,
    kind_lower: String,
    name_lower: String,
    popup_mem: [String; 5],
}

impl Entry {
    fn new(kind: String, name: String, members: Vec<String>, now: Option<String>) -> Self {
        Self {
            kind_lower: kind.to_lowercase(),
            name_lower: name.to_lowercase(),
            kind,
            name,
            members,
            now,
            delay: Delay::None,
            popup_mem: [
                String::with_capacity(32),
                String::with_capacity(32),
                String::with_capacity(32),
                String::with_capacity(32),
                String::with_capacity(32),
            ],
        }
    }

    fn filter_rank(&self, query: &str, query_lower: &str) -> Option<u8> {
        if self.name.starts_with(query) {
            Some(0)
        } else if self.name_lower.starts_with(query_lower) {
            Some(1)
        } else if self.name_lower.contains(query_lower) {
            Some(2)
        } else if self.kind_lower.contains(query_lower) {
            Some(3)
        } else {
            None
        }
    }

    fn probe_name(&self) -> &str {
        self.now
            .as_deref()
            .filter(|now| !now.is_empty())
            .unwrap_or(&self.name)
    }

    fn popup<'a>(
        &'a mut self,
        size: (u16, u16),
        delays: Option<&VecDeque<Delay>>,
    ) -> (&'a [String], &'a str, (u16, u16, u16, u16)) {
        const COLSN: u16 = 7;

        let stat = delays.map(DelaysStat::from).unwrap_or_default();

        for s in &mut self.popup_mem {
            s.clear();
        }
        let [name, now, delay, median, prate, ..] = &mut self.popup_mem[..] else {
            unreachable!()
        };

        name.push_str(&self.name);
        now.push_str(self.now.as_deref().unwrap_or("-"));

        let _ = match stat.last {
            0 => write!(delay, "delay  -"),
            v => write!(delay, "delay  {v}ms"),
        };
        let _ = match stat.median {
            0 => write!(median, "median -"),
            v => write!(median, "median {v}ms"),
        };
        let _ = match stat.prate {
            0 => write!(prate, "prate  -"),
            v => write!(prate, "prate  {v}%"),
        };

        let width = self
            .popup_mem
            .iter()
            .map(|s| s.width() as u16)
            .max()
            .unwrap_or(8)
            .max(self.kind.width() as u16);

        (
            &self.popup_mem,
            self.kind.as_str(),
            (size.0 / 2 - width / 2, size.1 / 2 - COLSN, width + 2, COLSN),
        )
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct DelaysStat {
    last: u16,
    median: u16,
    prate: u8,
}

impl From<&VecDeque<Delay>> for DelaysStat {
    fn from(value: &VecDeque<Delay>) -> Self {
        let mut samples: Vec<u16> = value
            .iter()
            .filter_map(|d| match d {
                Delay::Success { ms, .. } => Some(*ms),
                _ => None,
            })
            .collect();

        let Some(&last) = samples.last() else {
            return Self::default();
        };

        let prate = (samples.len() * 100 / value.len()) as u8;
        let mid = samples.len() / 2;
        let median = *samples.select_nth_unstable(mid).1;

        Self {
            last,
            median,
            prate,
        }
    }
}

fn kind_color(kind: &str) -> Color {
    match kind {
        "Fallback" => Color::Red,
        "Selector" => Color::Magenta,
        "Direct" => Color::Reset,
        "URLTest" => Color::Yellow,
        _ => Color::Blue,
    }
}

#[inline]
fn count_digits(n: usize) -> usize {
    if n == 0 { 1 } else { n.ilog10() as usize + 1 }
}

fn measure_entrys(entries: &[Entry]) -> [usize; COLUMNS] {
    let mut widths = HEADERS.map(|header| header.width());
    for entry in entries {
        widths[0] = widths[0].max(entry.kind.width());
        widths[1] = widths[1].max(entry.name.width());
        widths[2] = widths[2].max(count_digits(entry.members.len()));
        widths[3] = widths[3].max(entry.now.as_deref().map_or(1, |now| now.width()));
        widths[4] = widths[4].max(entry.delay.display().0.len());
    }
    widths
}

fn entries_from_proxies(proxies: singbox_clash_api::Proxies) -> Vec<Entry> {
    proxies
        .into_iter()
        .map(|(_, proxy)| {
            Entry::new(
                proxy.kind,
                proxy.name,
                proxy.all.unwrap_or_default(),
                proxy.now,
            )
        })
        .collect()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn parse_rfc3339(s: &str) -> Option<i64> {
    let num = |a: usize, z: usize| -> Option<i64> { s.get(a..z)?.parse::<i64>().ok() };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, se) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);

    let rest = s
        .get(19..)?
        .trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    let off = if rest.is_empty() || rest.starts_with('Z') {
        0
    } else {
        let sign = if rest.starts_with('-') { -1 } else { 1 };
        let oh = rest.get(1..3)?.parse::<i64>().ok()?;
        let om = rest.get(4..6)?.parse::<i64>().ok()?;
        sign * (oh * 3600 + om * 60)
    };

    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + se - off)
}

struct Bytes(u64);

impl Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0;
        if n < 1024 {
            return write!(f, "{n}B");
        }
        let mut v = n as f64 / 1024.0;
        for unit in ["K", "M", "G", "T"] {
            if v < 1024.0 || unit == "T" {
                return write!(f, "{v:.1}{unit}");
            }
            v /= 1024.0;
        }
        unreachable!()
    }
}

struct Age(i64);

impl Display for Age {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.max(0);
        match s {
            0..=59 => write!(f, "{s}s"),
            60..=3599 => write!(f, "{}m{:02}s", s / 60, s % 60),
            3600..=86399 => write!(f, "{}h{:02}m", s / 3600, s % 3600 / 60),
            _ => write!(f, "{}d{:02}h", s / 86400, s % 86400 / 3600),
        }
    }
}

fn addr(mut ip: String, port: &str) -> String {
    if port.is_empty() {
        ip
    } else if ip.contains(':') {
        let mut s = String::with_capacity(ip.len() + port.len() + 3);
        s.push('[');
        s.push_str(&ip);
        s.push_str("]:");
        s.push_str(port);
        s
    } else {
        ip.push(':');
        ip.push_str(port);
        ip
    }
}

fn net_color(network: &str) -> Color {
    match network {
        "tcp" => Color::Cyan,
        "udp" => Color::Yellow,
        _ => Color::Reset,
    }
}

struct ConnRow {
    id: String,
    network: String,
    inbound: String,
    source: String,
    dest: String,
    dest_ip: String,
    process: String,
    chain: String,
    rule: String,
    upload: u64,
    download: u64,
    started: Option<i64>,
    haystack: String,
    popup_mem: [String; 7],
}

impl ConnRow {
    fn new(c: Connection) -> Self {
        let chain = c.chains.join("›");
        let started = parse_rfc3339(&c.start);
        let m = c.metadata;
        let source = addr(m.source_ip, &m.source_port);
        let dest_ip = addr(m.destination_ip, &m.destination_port);
        let dest = if m.host.is_empty() {
            String::new()
        } else if m.destination_port.is_empty() {
            m.host
        } else {
            let mut d = m.host;
            d.push(':');
            d.push_str(&m.destination_port);
            d
        };

        Self {
            id: c.id,
            network: m.network,
            inbound: m.kind,
            source,
            dest,
            dest_ip,
            process: m.process_path,
            chain,
            rule: c.rule,
            upload: c.upload,
            download: c.download,
            started,
            haystack: String::new(),
            popup_mem: [
                String::with_capacity(32),
                String::with_capacity(64),
                String::with_capacity(64),
                String::with_capacity(64),
                String::with_capacity(64),
                String::with_capacity(64),
                String::with_capacity(32),
            ],
        }
    }

    #[inline]
    fn dest(&self) -> &str {
        if self.dest.is_empty() {
            &self.dest_ip
        } else {
            &self.dest
        }
    }

    fn haystack(&mut self) -> &str {
        if self.haystack.is_empty() {
            let fields = [
                self.network.as_str(),
                self.inbound.as_str(),
                self.source.as_str(),
                self.dest(),
                self.dest_ip.as_str(),
                self.process.as_str(),
                self.chain.as_str(),
                self.rule.as_str(),
                self.id.as_str(),
            ];
            let cap = fields.iter().map(|s| s.len()).sum::<usize>() + fields.len();
            let mut h = String::with_capacity(cap);
            for (i, s) in fields.iter().enumerate() {
                if i > 0 {
                    h.push('\n');
                }
                h.extend(s.chars().flat_map(char::to_lowercase));
            }
            self.haystack = h;
        }
        &self.haystack
    }

    fn detail(&self) -> String {
        let mut s = String::with_capacity(
            48 + self.inbound.len()
                + self.id.len()
                + self.dest_ip.len()
                + self.rule.len()
                + self.process.len()
                + self.chain.len(),
        );
        let _ = write!(
            s,
            " {} {}→ {} {}",
            self.inbound, self.source, self.dest_ip, self.rule
        );
        if !self.process.is_empty() {
            let _ = write!(s, " {}", self.process);
        }
        let _ = write!(s, " {}", self.chain);
        s
    }

    fn popup<'a>(&'a mut self, size: (u16, u16)) -> (&'a [String], &'a str, (u16, u16, u16, u16)) {
        const COLSN: u16 = 9;

        for s in &mut self.popup_mem {
            s.clear();
        }
        let [head, source, dest, dest_ip, chain, rule, process, ..] = &mut self.popup_mem[..]
        else {
            unreachable!()
        };

        head.push_str(&self.inbound);
        let _ = match self.started {
            Some(s) => write!(head, " {}", Age(unix_now().saturating_sub(s))),
            None => write!(head, " -"),
        };
        source.push_str(&self.source);
        dest.push_str(&self.dest);
        dest_ip.push_str(&self.dest_ip);
        chain.push_str(&self.chain);
        rule.push_str(&self.rule);
        process.push_str(if self.process.is_empty() {
            "-"
        } else {
            &self.process
        });

        let width = self
            .popup_mem
            .iter()
            .map(|s| s.width() as u16)
            .max()
            .unwrap_or(8)
            .max(4);

        (
            &self.popup_mem,
            "Conn",
            (
                (size.0 / 2).saturating_sub(width / 2),
                (size.1 / 2).saturating_sub(COLSN),
                width + 2,
                COLSN,
            ),
        )
    }
}

#[derive(Default)]
struct ConnView {
    rows: Vec<ConnRow>,
    visible: Vec<usize>,
    filter: String,
    cursor: usize,
    top: usize,
    download_total: u64,
    upload_total: u64,
    memory: u64,
    col_max: [usize; 5],
}

impl ConnView {
    fn selected(&self) -> Option<usize> {
        self.visible.get(self.cursor).copied()
    }

    fn refilter(&mut self) {
        self.visible.clear();
        if self.filter.is_empty() {
            self.visible.extend(0..self.rows.len());
            return;
        }
        let q = self.filter.to_lowercase();
        for (i, r) in self.rows.iter_mut().enumerate() {
            if r.haystack().contains(&q) {
                self.visible.push(i);
            }
        }
    }

    fn set_filter(&mut self, filter: String, _height: usize) {
        self.filter = filter;
        self.refilter();
        self.cursor = 0;
        self.top = 0;
    }

    fn apply(&mut self, snapshot: Snapshot, height: usize) {
        let selected_id = self
            .selected()
            .map(|i| std::mem::take(&mut self.rows[i].id));

        self.download_total = snapshot.download_total;
        self.upload_total = snapshot.upload_total;
        self.memory = snapshot.memory;

        self.rows.clear();
        self.rows
            .extend(snapshot.connections.into_iter().map(ConnRow::new));
        self.rows
            .sort_unstable_by(|a, b| b.started.cmp(&a.started).then_with(|| a.id.cmp(&b.id)));

        let mut mx = [0usize; 5];
        for r in &self.rows {
            mx[0] = mx[0].max(r.network.width());
            mx[1] = mx[1].max(r.source.width());
            mx[2] = mx[2].max(r.dest().width());
            mx[3] = mx[3].max(r.chain.width());
            mx[4] = mx[4].max(r.rule.width());
        }
        self.col_max = mx;

        self.refilter();

        let pos =
            selected_id.and_then(|id| self.visible.iter().position(|&i| self.rows[i].id == id));
        self.cursor = pos
            .unwrap_or(self.cursor)
            .min(self.visible.len().saturating_sub(1));
        self.scroll_into_view(height);
    }

    fn move_to(&mut self, target: usize, height: usize) {
        self.cursor = target.min(self.visible.len().saturating_sub(1));
        self.scroll_into_view(height);
    }

    fn move_by(&mut self, delta: isize, height: usize) {
        self.move_to(self.cursor.saturating_add_signed(delta), height);
    }

    fn scroll_into_view(&mut self, height: usize) {
        let off = SCROLLOFF.min(height.saturating_sub(1) / 2);
        if self.cursor < self.top + off {
            self.top = self.cursor.saturating_sub(off);
        }
        if self.cursor + off >= self.top + height {
            self.top = self.cursor + off + 1 - height;
        }
        self.top = self.top.min(self.visible.len().saturating_sub(height));
    }

    fn rows_on_screen(&self, height: usize) -> impl Iterator<Item = (usize, &ConnRow)> + '_ {
        let start = self.top.min(self.visible.len());
        let end = (self.top + height).min(self.visible.len());
        self.visible[start..end]
            .iter()
            .copied()
            .map(move |i| (i, &self.rows[i]))
    }

    fn layout(&self, width: usize) -> [usize; CONN_COLS] {
        let mut w = CONN_HEADERS.map(|h| h.width());
        for (wi, m) in w.iter_mut().zip(self.col_max) {
            *wi = (*wi).max(m);
        }
        w[5] = 7;
        w[6] = 7;
        w[7] = 7;

        let gaps = 1 + GAP.len() * (CONN_COLS - 1);
        let flex = width.saturating_sub(gaps + w[0] + w[5] + w[6] + w[7]);

        let caps = [24, 48, 48, 32];
        let mut f = [
            w[1].min(caps[0]),
            w[2].min(caps[1]),
            w[3].min(caps[2]),
            w[4].min(caps[3]),
        ];
        while f.iter().sum::<usize>() > flex {
            let (i, &m) = f.iter().enumerate().max_by_key(|&(_, &v)| v).unwrap();
            if m <= 4 {
                break;
            }
            f[i] -= 1;
        }
        let mut widths = [w[0], f[0], f[1], f[2], f[3], w[5], w[6], w[7]];
        let used: usize = widths.iter().sum::<usize>() + gaps;
        widths[CONN_COLS - 1] += width.saturating_sub(used);
        widths[CONN_COLS - 1] -= 1;
        widths
    }
}

fn write_conn_line(
    out: &mut impl Write,
    width: usize,
    widths: &[usize; CONN_COLS],
    attr: Attribute,
    cells: [(&str, Color); CONN_COLS],
) -> io::Result<()> {
    queue!(out, SetAttribute(attr), Print(' '))?;
    let mut used = 1;
    for (i, (text, color)) in cells.into_iter().enumerate() {
        if i > 0 {
            queue!(out, Print(GAP))?;
            used += GAP.len();
        }
        queue!(out, SetForegroundColor(color))?;
        write_fit(out, text, widths[i], CONN_ALIGNS[i])?;
        used += widths[i];
    }
    write_pad(out, width.saturating_sub(used))?;
    reset_term!(out)
}

fn draw_connections(
    out: &mut impl Write,
    view: &ConnView,
    cols: u16,
    rows: u16,
    sleep: bool,
) -> io::Result<()> {
    use std::fmt::Write as _;

    let width = usize::from(cols);
    let height = usize::from(rows).saturating_sub(4);
    reset_term!(out)?;

    // title bar
    const TITLE: &str = " CONNECTIONS ";
    let stat = format!(
        "↑{} ↓{} mem {} ",
        Bytes(view.upload_total),
        Bytes(view.download_total),
        Bytes(view.memory),
    );
    let counter = format!(" {}/{} ", view.visible.len(), view.rows.len());
    let right_w = stat.width() + counter.width();
    let title_w = TITLE.width().min(width.saturating_sub(right_w));
    let rest = width.saturating_sub(title_w + right_w);
    let filter_raw = if view.filter.is_empty() {
        String::new()
    } else {
        format!(" /{}", view.filter)
    };
    let filter_w = filter_raw.width().min(rest);

    queue!(
        out,
        cursor::MoveTo(0, 0),
        SetAttribute(Attribute::Reverse),
        SetAttribute(Attribute::Bold),
    )?;
    if sleep {
        queue!(out, SetForegroundColor(Color::Magenta))?;
    }
    write_fit(out, TITLE, title_w, Align::Left)?;
    reset_term!(out)?;
    queue!(
        out,
        ResetColor,
        SetAttribute(Attribute::Underlined),
        SetForegroundColor(Color::Yellow),
    )?;
    write_fit(out, &filter_raw, filter_w, Align::Left)?;
    write_pad(out, rest - filter_w)?;
    queue!(
        out,
        SetForegroundColor(Color::Cyan),
        Print(&stat),
        SetForegroundColor(Color::White),
        Print(&counter),
        SetAttribute(Attribute::Reset),
        ResetColor,
    )?;

    // header
    let widths = view.layout(width);
    queue!(out, cursor::MoveTo(0, 1))?;
    write_conn_line(
        out,
        width,
        &widths,
        Attribute::Bold,
        CONN_HEADERS.map(|h| (h, Color::White)),
    )?;

    // rows
    let now = unix_now();
    let (mut up, mut down, mut age) = (String::new(), String::new(), String::new());

    for line in 0..height {
        let pos = view.top + line;
        queue!(out, cursor::MoveTo(0, line as u16 + 2))?;
        let Some(&i) = view.visible.get(pos) else {
            write_pad(out, width)?;
            continue;
        };
        let r = &view.rows[i];
        let attr = if pos == view.cursor {
            Attribute::Reverse
        } else {
            Attribute::Reset
        };

        up.clear();
        down.clear();
        age.clear();
        let _ = write!(up, "{}", Bytes(r.upload));
        let _ = write!(down, "{}", Bytes(r.download));
        match r.started {
            Some(s) => {
                let _ = write!(age, "{}", Age(now.saturating_sub(s)));
            }
            None => age.push('-'),
        }

        let rule_color = if r.rule == "final" {
            Color::Yellow
        } else {
            Color::Reset
        };
        write_conn_line(
            out,
            width,
            &widths,
            attr,
            [
                (r.network.as_str(), net_color(&r.network)),
                (r.source.as_str(), Color::Reset),
                (r.dest(), Color::Blue),
                (r.chain.as_str(), Color::Reset),
                (r.rule.as_str(), rule_color),
                (up.as_str(), Color::Green),
                (down.as_str(), Color::Red),
                (age.as_str(), Color::Reset),
            ],
        )?;
    }

    // details of selected connection
    let detail = view
        .selected()
        .map(|i| view.rows[i].detail())
        .unwrap_or_default();
    queue!(
        out,
        cursor::MoveTo(0, rows.saturating_sub(2)),
        SetForegroundColor(Color::Magenta),
    )?;
    write_fit(out, &detail, width.saturating_sub(1), Align::Left)?;
    reset_term!(out)
}

struct Table {
    entries: Vec<Entry>,
    by_name: HashMap<String, usize>,
    selectors_of: HashMap<String, Vec<String>>,
    visible: Vec<usize>,
    widths: [usize; COLUMNS],
}

impl Table {
    fn new(entries: Vec<Entry>) -> Self {
        let by_name: HashMap<_, _> = entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.name.clone(), i))
            .collect();

        let mut selectors_of: HashMap<String, Vec<String>> = HashMap::new();
        for e in &entries {
            for m in &e.members {
                selectors_of
                    .entry(m.clone())
                    .or_default()
                    .push(e.name.clone());
            }
        }

        Self {
            by_name,
            selectors_of,
            visible: (0..entries.len()).collect(),
            widths: measure_entrys(&entries),
            entries,
        }
    }

    fn is_group(&self, index: usize) -> bool {
        let e = &self.entries[index];
        !e.members.is_empty() || e.now.is_some()
    }

    fn selectors_for(&self, name: &str) -> Vec<Entry> {
        self.selectors_of
            .get(name)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| self.by_name.get(n))
                    .map(|&i| self.entries[i].clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn members_of(&self, index: usize) -> Table {
        Table::new(
            self.entries[index]
                .members
                .iter()
                .filter_map(|name| self.by_name.get(name))
                .map(|&member| self.entries[member].clone())
                .collect(),
        )
    }

    fn set_delay_by_probe(&mut self, probe: &str, delay: &Delay) {
        let mut changed = false;
        for entry in &mut self.entries {
            if entry.probe_name() == probe {
                entry.delay = delay.clone();
                changed = true;
            }
        }
        if changed {
            self.widths = measure_entrys(&self.entries);
        }
    }

    fn probes(&self) -> Vec<String> {
        let mut probes: Vec<String> = self
            .entries
            .iter()
            .map(|entry| entry.probe_name().to_owned())
            .collect();
        probes.sort_unstable();
        probes.dedup();
        probes
    }

    fn apply_filter(&mut self, query: &str) {
        self.visible.clear();
        if query.is_empty() {
            self.visible.extend(0..self.entries.len());
            return;
        }
        let query_lower = query.to_lowercase();
        let mut ranked: Vec<(u8, usize)> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                entry
                    .filter_rank(query, &query_lower)
                    .map(|rank| (rank, index))
            })
            .collect();
        ranked.sort_by_key(|&(rank, _)| rank);
        self.visible
            .extend(ranked.into_iter().map(|(_, index)| index));
    }

    fn layout(&self, pane_width: usize) -> [usize; COLUMNS] {
        let [kind, name, mem, now, delay] = self.widths;
        let flex =
            pane_width.saturating_sub(1 + GAP.len() * (COLUMNS - 1) + kind + mem + delay + 1);
        let now_width = if name + now <= flex {
            now
        } else {
            now.min(flex / 3)
        };
        let name_width = (name.min(flex.saturating_sub(now_width)) + 1).min(flex);
        [kind, name_width, mem, flex - name_width, delay]
    }
}

struct Pane {
    title: String,
    table: Table,
    filter: String,
    cursor: usize,
    top: usize,
}

impl Pane {
    fn new(title: impl Into<String>, table: Table) -> Self {
        Self {
            title: title.into(),
            table,
            filter: String::new(),
            cursor: 0,
            top: 0,
        }
    }

    fn selected(&self) -> Option<usize> {
        self.table.visible.get(self.cursor).copied()
    }

    fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        self.table.apply_filter(&self.filter);
        self.cursor = 0;
        self.top = 0;
    }

    fn move_to(&mut self, target: usize, height: usize) {
        self.cursor = target.min(self.table.visible.len().saturating_sub(1));
        self.scroll_into_view(height);
    }

    fn move_by(&mut self, delta: isize, height: usize) {
        self.move_to(self.cursor.saturating_add_signed(delta), height);
    }

    fn scroll_into_view(&mut self, height: usize) {
        let off = SCROLLOFF.min(height.saturating_sub(1) / 2);
        if self.cursor < self.top + off {
            self.top = self.cursor.saturating_sub(off);
        }
        if self.cursor + off >= self.top + height {
            self.top = self.cursor + off + 1 - height;
        }
        self.top = self
            .top
            .min(self.table.visible.len().saturating_sub(height));
    }

    fn replace_table(&mut self, mut table: Table, height: usize) {
        let selected_name = self
            .selected()
            .map(|index| self.table.entries[index].name.clone());

        table.apply_filter(&self.filter);
        self.table = table;

        let position = selected_name.and_then(|name| {
            let index = *self.table.by_name.get(&name)?;
            self.table.visible.iter().position(|&v| v == index)
        });
        self.cursor = position
            .unwrap_or(self.cursor)
            .min(self.table.visible.len().saturating_sub(1));
        self.scroll_into_view(height);
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Side {
    Left,
    Right,
}

enum Mode {
    Normal,
    Input { saved_filter: String, conns: bool },
    Connections,
}

enum Msg {
    Term(io::Result<Event>),
    Proxies(Vec<Entry>),
    Delay { probe: String, delay: Delay },
    Redraw,
    Sleep(bool),
    Snapshot(Snapshot),
}

struct App {
    size: (u16, u16),
    left: Pane,
    right: Pane,
    center_offset: i32,
    right_source: Option<String>,
    delays: HashMap<String, VecDeque<Delay>>,
    active: Side,
    mode: Mode,
    client: Arc<Client>,
    is_sleep: bool,
    connections: ConnView,
    show_conn_popup: Option<String>,
    show_popup: bool,
}

impl App {
    fn new(proxies: Table, client: Arc<Client>) -> io::Result<Self> {
        let mut app = Self {
            size: terminal::size()?,
            left: Pane::new("PROXIES", proxies),
            right: Pane::new("MEMBERS", Table::new(Vec::new())),
            center_offset: 2,
            right_source: None,
            delays: HashMap::new(),
            active: Side::Left,
            mode: Mode::Normal,
            client,
            is_sleep: false,
            connections: ConnView::default(),
            show_conn_popup: None,
            show_popup: false,
        };
        app.sync_right();
        Ok(app)
    }

    fn list_height(&self) -> usize {
        usize::from(self.size.1).saturating_sub(3)
    }

    fn active_pane(&self) -> &Pane {
        match self.active {
            Side::Left => &self.left,
            Side::Right => &self.right,
        }
    }

    fn probes(&self) -> Vec<String> {
        self.left.table.probes()
    }

    fn sync_right(&mut self) {
        let selected = self.left.selected();
        let name = selected.map(|i| self.left.table.entries[i].name.clone());
        if name == self.right_source {
            return;
        }

        let (title, table) = match selected {
            Some(index) => {
                let entry = &self.left.table.entries[index];
                if self.left.table.is_group(index) {
                    (
                        format!("MEMBERS · {}", entry.name),
                        self.left.table.members_of(index),
                    )
                } else {
                    (
                        format!("SELECTORS · {}", entry.name),
                        Table::new(self.left.table.selectors_for(&entry.name)),
                    )
                }
            }
            None => ("MEMBERS".into(), Table::new(Vec::new())),
        };
        self.right = Pane::new(title, table);
        self.right_source = name;
    }

    fn apply_delay(&mut self, probe: String, delay: Delay) {
        if let Some(h) = self.delays.get_mut(&probe) {
            h.push_back(delay);
            if h.len() >= DELAY_CAP {
                h.pop_front();
            }
        } else {
            let mut h = VecDeque::with_capacity(DELAY_CAP);
            h.push_back(delay);
            self.delays.insert(probe.clone(), h);
        }
        self.left
            .table
            .set_delay_by_probe(&probe, self.delays[&probe].back().unwrap_or(&Delay::None));
        self.right
            .table
            .set_delay_by_probe(&probe, self.delays[&probe].back().unwrap_or(&Delay::None));
    }

    fn apply_proxies(&mut self, mut entries: Vec<Entry>) {
        for entry in &mut entries {
            if let Some(delays) = self.delays.get(entry.probe_name()) {
                entry.delay = delays.back().unwrap_or(&Delay::None).clone();
            }
        }

        let height = self.list_height();
        self.left.replace_table(Table::new(entries), height);

        let selected = self.left.selected();
        let name = selected.map(|index| self.left.table.entries[index].name.clone());
        let same_source = name.is_some() && name == self.right_source;

        match selected {
            Some(index) if same_source => {
                let entry = &self.left.table.entries[index];
                let members = if self.left.table.is_group(index) {
                    self.left.table.members_of(index)
                } else {
                    Table::new(self.left.table.selectors_for(&entry.name))
                };
                self.right.replace_table(members, height);
            }
            _ => self.sync_right(),
        }
    }

    fn conn_height(&self) -> usize {
        usize::from(self.size.1).saturating_sub(4)
    }

    fn conn_visible(&self) -> bool {
        matches!(
            self.mode,
            Mode::Connections | Mode::Input { conns: true, .. }
        )
    }

    fn apply_connections_snapshot(&mut self, snapshot: Snapshot) {
        let h = self.conn_height();
        self.connections.apply(snapshot, h);
    }

    fn set_filter(&mut self, conns: bool, filter: String) {
        if conns {
            let h = self.conn_height();
            self.connections.set_filter(filter, h);
        } else {
            self.edit_active(|p, _| p.set_filter(filter));
        }
    }

    fn edit_active(&mut self, edit: impl FnOnce(&mut Pane, usize)) {
        let height = self.list_height();
        let pane = match self.active {
            Side::Left => &mut self.left,
            Side::Right => &mut self.right,
        };
        edit(pane, height);
        self.sync_right();
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        self.size = (cols, rows);
        let height = self.list_height();
        self.left.scroll_into_view(height);
        self.right.scroll_into_view(height);
        self.center_offset = 2;
        let ch = self.conn_height();
        self.connections.scroll_into_view(ch);
    }

    fn resize_pane(&mut self, side: Side, val: i32) {
        if side == Side::Left {
            self.center_offset -= val;
            self.center_offset = self.center_offset.max((self.size.0 / 2) as i32 * -1 + 32);
        } else {
            self.center_offset += val;
            self.center_offset = self.center_offset.min((self.size.0 / 2) as i32 - 32);
        }
    }

    /// Returns `true` when the app should quit.
    async fn handle_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        if ctrl && key.code == KeyCode::Char('c') {
            return true;
        }
        match self.mode {
            Mode::Input { .. } => {
                self.handle_input_key(key.code, ctrl);
                false
            }
            Mode::Normal => self.handle_normal_key(key.code, ctrl, shift).await,
            Mode::Connections => self.handle_connections_key(key.code, ctrl, shift).await,
        }
    }

    async fn handle_normal_key(&mut self, code: KeyCode, ctrl: bool, shift: bool) -> bool {
        self.show_popup = false;
        match code {
            KeyCode::Char('q') => return true,

            KeyCode::Char('o') => self.show_popup = true,
            KeyCode::Enter => {
                if self.active == Side::Left {
                    self.active = Side::Right;
                }
                let selected_l = self.left.selected().map(|index| {
                    let e = &self.left.table.entries[index];
                    (e.kind.clone(), e.name.clone())
                });
                let selected_r = self.right.selected().map(|index| {
                    let e = &self.right.table.entries[index];
                    (e.kind.clone(), e.name.clone(), e.delay)
                });

                if let (Some((kind_l, name_l)), Some((kind_r, name_r, delays_r))) =
                    (selected_l, selected_r)
                {
                    if kind_l == "Selector" {
                        match self.client.select_proxy(&name_l, &name_r).await {
                            Ok(_) => {
                                if let Some(&index) = self.left.table.by_name.get(&name_l) {
                                    let entry = &mut self.left.table.entries[index];
                                    entry.now = Some(name_r);
                                    entry.delay = delays_r;
                                    self.left.table.widths =
                                        measure_entrys(&self.left.table.entries);
                                }
                            }
                            Err(_) => { /* show error */ }
                        }
                    } else if kind_r == "Selector" {
                        match self.client.select_proxy(&name_r, &name_l).await {
                            Ok(_) => {
                                if let Some(&index) = self.right.table.by_name.get(&name_r) {
                                    let entry = &mut self.right.table.entries[index];
                                    entry.now = Some(name_l.clone());
                                    self.right.table.widths =
                                        measure_entrys(&self.right.table.entries);
                                }
                                if let Some(&index) = self.left.table.by_name.get(&name_r) {
                                    let entry = &mut self.left.table.entries[index];
                                    entry.now = Some(name_l);
                                    self.left.table.widths =
                                        measure_entrys(&self.left.table.entries);
                                }
                            }
                            Err(_) => { /* show error */ }
                        }
                    }
                }
            }
            KeyCode::Char('h') | KeyCode::Char('H') | KeyCode::Left => {
                if !shift {
                    if self.active == Side::Left {
                        self.mode = Mode::Connections;
                    } else {
                        self.active = Side::Left;
                    }
                } else {
                    self.resize_pane(Side::Left, 1);
                }
            }
            KeyCode::Char('l') | KeyCode::Char('L') | KeyCode::Right => {
                if !shift {
                    if self.active == Side::Right {
                        self.mode = Mode::Connections;
                    } else {
                        self.active = Side::Right;
                    }
                } else {
                    self.resize_pane(Side::Right, 1);
                }
            }
            KeyCode::PageDown => self.edit_active(|p, h| p.move_by(h as isize, h)),
            KeyCode::PageUp => self.edit_active(|p, h| p.move_by(-(h as isize), h)),
            KeyCode::Char('-') => self.resize_pane(Side::Left, 1),
            KeyCode::Char('+') => self.resize_pane(Side::Right, 1),
            KeyCode::Char('=') => self.center_offset = 0,
            KeyCode::Tab => {
                self.active = match self.active {
                    Side::Left => Side::Right,
                    Side::Right => Side::Left,
                }
            }
            KeyCode::Char('j') | KeyCode::Down => self.edit_active(|p, h| p.move_by(1, h)),
            KeyCode::Char('k') | KeyCode::Up => self.edit_active(|p, h| p.move_by(-1, h)),
            KeyCode::Char('d') if ctrl => {
                self.edit_active(|p, h| p.move_by((h / 2) as isize, h));
            }
            KeyCode::Char('u') if ctrl => {
                self.edit_active(|p, h| p.move_by(-((h / 2) as isize), h));
            }
            KeyCode::Char('g') | KeyCode::Home => self.edit_active(|p, h| p.move_to(0, h)),
            KeyCode::Char('G') | KeyCode::End => self.edit_active(|p, h| p.move_to(usize::MAX, h)),
            KeyCode::Char(':' | '/' | 'i') => {
                self.mode = Mode::Input {
                    saved_filter: self.active_pane().filter.clone(),
                    conns: false,
                };
            }
            KeyCode::Esc | KeyCode::Char(' ') => {
                self.edit_active(|p, _| p.set_filter(String::new()))
            }
            KeyCode::Char('c') => self.mode = Mode::Connections,
            _ => {}
        }
        false
    }

    async fn handle_connections_key(&mut self, code: KeyCode, ctrl: bool, _shift: bool) -> bool {
        let h = self.conn_height();
        self.show_conn_popup = None;
        match code {
            KeyCode::Char('q') => return true,

            KeyCode::Char('o') => {
                let conn_id = self
                    .connections
                    .selected()
                    .map(|i| self.connections.rows[i].id.as_str())
                    .unwrap_or("");
                if !conn_id.is_empty() {
                    self.show_conn_popup = Some(conn_id.into());
                }
            }
            KeyCode::Char('K') => {
                let conn_id = self
                    .connections
                    .selected()
                    .map(|i| self.connections.rows[i].id.as_str())
                    .unwrap_or("");
                if !conn_id.is_empty() {
                    let _ = self.client.close_connection(conn_id).await;
                }
            }

            KeyCode::Char('X') => {
                let _ = self.client.close_all_connections().await;
            }
            KeyCode::Char('V') => {
                for (_, row) in self.connections.rows_on_screen(self.size.1 as usize) {
                    let _ = self.client.close_connection(row.id.as_str()).await;
                }
            }
            KeyCode::Esc => {
                if self.connections.filter.is_empty() {
                    self.mode = Mode::Normal;
                } else {
                    self.connections.set_filter(String::new(), h);
                }
            }
            KeyCode::Char('c') => self.mode = Mode::Normal,
            KeyCode::Char('h') | KeyCode::Left => {
                self.active = Side::Right;
                self.mode = Mode::Normal;
            }
            KeyCode::Char('l') | KeyCode::Right => {
                self.active = Side::Left;
                self.mode = Mode::Normal;
            }
            KeyCode::Char(' ') => self.connections.set_filter(String::new(), h),
            KeyCode::Char('j') | KeyCode::Down => self.connections.move_by(1, h),
            KeyCode::Char('k') | KeyCode::Up => self.connections.move_by(-1, h),
            KeyCode::Char('d') if ctrl => self.connections.move_by((h / 2) as isize, h),
            KeyCode::Char('u') if ctrl => self.connections.move_by(-((h / 2) as isize), h),
            KeyCode::Char('g') | KeyCode::Home => self.connections.move_to(0, h),
            KeyCode::Char('G') | KeyCode::End => self.connections.move_to(usize::MAX, h),
            KeyCode::Char(':' | '/' | 'i') => {
                self.mode = Mode::Input {
                    saved_filter: self.connections.filter.clone(),
                    conns: true,
                };
            }
            _ => {}
        }
        false
    }

    fn handle_input_key(&mut self, code: KeyCode, ctrl: bool) {
        let conns = matches!(self.mode, Mode::Input { conns: true, .. });
        let back = if conns {
            Mode::Connections
        } else {
            Mode::Normal
        };
        let current = if conns {
            self.connections.filter.clone()
        } else {
            self.active_pane().filter.clone()
        };
        match code {
            KeyCode::Enter => self.mode = back,
            KeyCode::Esc => {
                if let Mode::Input { saved_filter, .. } = std::mem::replace(&mut self.mode, back) {
                    self.set_filter(conns, saved_filter);
                }
            }
            KeyCode::Backspace => {
                let mut f = current;
                f.pop();
                self.set_filter(conns, f);
            }
            KeyCode::Char('u') if ctrl => self.set_filter(conns, String::new()),
            KeyCode::Char(ch) if !ctrl => {
                let mut f = current;
                f.push(ch);
                self.set_filter(conns, f);
            }
            _ => {}
        }
    }

    fn draw(&mut self, out: &mut impl Write) -> io::Result<()> {
        let (cols, rows) = self.size;
        if cols < MIN_SIZE.0 || rows < MIN_SIZE.1 {
            queue!(
                out,
                Clear(ClearType::All),
                cursor::MoveTo(0, 0),
                Print("Terminal too small")
            )?;
            return out.flush();
        }

        if self.conn_visible() {
            draw_connections(out, &self.connections, cols, rows, self.is_sleep)?;
            self.draw_footer(out)?;
            if let Some(id) = self.show_conn_popup.as_deref() {
                match self.connections.rows.iter_mut().find(|r| r.id == id) {
                    Some(conn) => {
                        out.flush()?;
                        let (content, title, area) = conn.popup(self.size);
                        draw_popup(out, area, title, content, 0, Color::Cyan)?;
                    }
                    None => self.show_conn_popup = None,
                }
            }
            return out.flush();
        }

        let height = self.list_height();
        let sep_x = ((cols as i32) / 2 + self.center_offset).clamp(2, cols as i32 - 3) as u16;
        let right_x = sep_x + 1;

        reset_term!(out)?;
        queue!(out, SetForegroundColor(Color::White))?;
        for y in 0..rows - 1 {
            queue!(out, cursor::MoveTo(sep_x, y), Print('│'))?;
        }
        reset_term!(out)?;

        draw_pane(
            out,
            &self.left,
            0,
            sep_x as usize,
            height,
            self.active == Side::Left,
            self.is_sleep,
            Highlight::None,
        )?;

        let highlight = match self.left.selected().map(|i| &self.left.table.entries[i]) {
            Some(e) => match e.now.as_deref() {
                Some(now) => Highlight::ByName(now),
                None => Highlight::ByNow(&e.name),
            },
            None => Highlight::None,
        };
        draw_pane(
            out,
            &self.right,
            right_x,
            (cols - right_x) as usize,
            height,
            self.active == Side::Right,
            self.is_sleep,
            highlight,
        )?;
        self.draw_footer(out)?;

        if self.show_popup {
            if let Some(selected) = self.active_pane().selected() {
                out.flush()?;
                let pane = match self.active {
                    Side::Left => &mut self.left,
                    Side::Right => &mut self.right,
                };
                let entry = &mut pane.table.entries[selected];
                let delays = self.delays.get(entry.probe_name());
                let (content, title, area) = entry.popup(self.size, delays);
                draw_popup(out, area, title, content, 0, Color::Cyan)?;
            }
        }

        out.flush()
    }

    fn draw_footer(&self, out: &mut impl Write) -> io::Result<()> {
        let (cols, rows) = self.size;
        queue!(
            out,
            SetAttribute(Attribute::Reverse),
            cursor::MoveTo(0, rows - 1)
        )?;
        match self.mode {
            Mode::Input { .. } => {
                let filter = if self.conn_visible() {
                    &self.connections.filter
                } else {
                    &self.active_pane().filter
                };
                let text = format!(" /{}", filter);
                let caret = text.width().min(usize::from(cols) - 1) as u16;
                queue!(out, cursor::MoveTo(0, rows - 1))?;
                write_fit(out, &text, cols as usize, Align::Left)?;
                queue!(out, cursor::MoveTo(caret, rows - 1), cursor::Show)
            }
            Mode::Normal | Mode::Connections => {
                if self.is_sleep {
                    queue!(out, SetForegroundColor(Color::Magenta))?;
                } else {
                    queue!(out, SetForegroundColor(Color::White))?;
                }
                let hint = if matches!(self.mode, Mode::Connections) {
                    CONN_HINT
                } else {
                    HINT
                };
                write_fit(out, hint, cols as usize, Align::Left)
            }
        }
    }
}

pub fn draw_popup(
    out: &mut impl Write,
    area: (u16, u16, u16, u16),
    title: &str,
    lines: &[String],
    scroll: usize,
    border: Color,
) -> io::Result<()> {
    const HLINE: &str = "──────────────────────────────────────────────────────────────────────────────────────────────────────";
    let (x, y, w, h) = area;
    if w < 3 || h < 3 {
        return Ok(());
    }
    let inner_w = (w - 2) as usize;
    let inner_h = (h - 2) as usize;
    queue!(
        out,
        cursor::MoveTo(x, y),
        SetForegroundColor(border),
        Print('┌'),
        Print(&HLINE[..inner_w.min(HLINE.len() / 3) * 3]),
        Print('┐'),
        ResetColor,
    )?;
    if !title.is_empty() {
        queue!(
            out,
            cursor::MoveTo(x + 1, y),
            SetAttribute(Attribute::Reverse),
            SetAttribute(Attribute::Bold),
        )?;
        let mut printed = 0usize;
        for ch in title.chars().take(inner_w) {
            queue!(out, Print(ch))?;
            printed += 1;
        }
        if printed < inner_w {
            write_pad(out, inner_w - printed)?;
        }
        queue!(out, SetAttribute(Attribute::Reset))?;
    }
    for row in 0..inner_h {
        let cy = y + 1 + row as u16;
        queue!(
            out,
            cursor::MoveTo(x, cy),
            SetForegroundColor(border),
            Print('│'),
            ResetColor,
            cursor::MoveTo(x + 1, cy),
        )?;
        match lines.get(scroll + row) {
            Some(line) => {
                let mut n = 0usize;
                for ch in line.chars() {
                    if n >= inner_w {
                        break;
                    }
                    queue!(out, Print(ch))?;
                    n += 1;
                }
                if n < inner_w {
                    write_pad(out, inner_w - n)?;
                }
            }
            None => {
                write_pad(out, inner_w)?;
            }
        }
        queue!(
            out,
            cursor::MoveTo(x + w - 1, cy),
            SetForegroundColor(border),
            Print('│'),
            ResetColor,
        )?;
    }
    queue!(
        out,
        cursor::MoveTo(x, y + h - 1),
        SetForegroundColor(border),
        Print('└'),
        Print(&HLINE[..inner_w.min(HLINE.len() / 3) * 3]),
        Print('┘'),
        ResetColor,
    )
}

fn write_line(
    out: &mut impl Write,
    widths: &[usize; COLUMNS],
    attr: Attribute,
    cells: [(&str, Color); COLUMNS],
) -> io::Result<()> {
    queue!(out, SetAttribute(attr), Print(' '))?;
    for (i, (text, color)) in cells.into_iter().enumerate() {
        if i > 0 {
            queue!(out, Print(GAP))?;
        }
        queue!(out, SetForegroundColor(color))?;
        write_fit(out, text, widths[i], ALIGNS[i])?;
    }
    reset_term!(out)
}

#[derive(Clone, Copy)]
enum Highlight<'a> {
    None,
    ByName(&'a str),
    ByNow(&'a str),
}

impl Highlight<'_> {
    fn matches(self, entry: &Entry) -> bool {
        match self {
            Highlight::None => false,
            Highlight::ByName(s) => entry.name == s,
            Highlight::ByNow(s) => entry.now.as_deref() == Some(s),
        }
    }
}

fn write_entry(
    out: &mut impl Write,
    widths: &[usize; COLUMNS],
    attr: Attribute,
    entry: &Entry,
    selected: Highlight,
) -> io::Result<()> {
    let members = if entry.members.is_empty() {
        "-".to_owned()
    } else {
        entry.members.len().to_string()
    };
    let members_color = if entry.members.is_empty() {
        Color::White
    } else {
        Color::Reset
    };
    let now_color = if entry.now.is_some() {
        Color::Reset
    } else {
        Color::White
    };
    let (delay, delay_color) = entry.delay.display();
    let (name_color, name) = if selected.matches(entry) {
        (Color::Green, format!("·{}", entry.name))
    } else {
        (Color::Reset, entry.name.clone())
    };
    write_line(
        out,
        widths,
        attr,
        [
            (entry.kind.as_str(), kind_color(&entry.kind)),
            (name.as_str(), name_color),
            (members.as_str(), members_color),
            (entry.now.as_deref().unwrap_or("-"), now_color),
            (delay.as_str(), delay_color),
        ],
    )
}

fn draw_pane(
    out: &mut impl Write,
    pane: &Pane,
    x: u16,
    width: usize,
    height: usize,
    active: bool,
    sleep: bool,
    highlight: Highlight,
) -> io::Result<()> {
    let title_raw = format!(" {} ", pane.title);
    let counter = format!("{}/{} ", pane.table.visible.len(), pane.table.entries.len());
    let title_width = title_raw.width().min(width.saturating_sub(counter.width()));

    let filter_raw = if pane.filter.is_empty() {
        String::new()
    } else {
        format!(" /{}", pane.filter)
    };
    let rest = width.saturating_sub(title_width + counter.width());
    let filter_width = filter_raw.width().min(rest);

    queue!(out, cursor::MoveTo(x, 0))?;
    if active {
        queue!(
            out,
            SetAttribute(Attribute::Reverse),
            SetAttribute(Attribute::Bold)
        )?;
    } else {
        queue!(out, SetAttribute(Attribute::Underlined))?;
    }
    if sleep {
        queue!(out, SetForegroundColor(Color::Magenta))?;
    }

    // title
    write_fit(out, &title_raw, title_width, Align::Left)?;
    reset_term!(out)?;

    // filter + padding
    queue!(
        out,
        SetAttribute(Attribute::Underlined),
        SetForegroundColor(Color::Yellow),
    )?;
    write_fit(out, &filter_raw, filter_width, Align::Left)?;
    write_pad(out, rest - filter_width)?;

    // counter
    queue!(
        out,
        ResetColor,
        SetForegroundColor(Color::White),
        Print(&counter),
    )?;
    reset_term!(out)?;

    // header
    let widths = pane.table.layout(width);
    let tail = width.saturating_sub(1 + widths.iter().sum::<usize>() + GAP.len() * (COLUMNS - 1));

    queue!(out, cursor::MoveTo(x, 1))?;
    write_line(
        out,
        &widths,
        Attribute::Bold,
        HEADERS.map(|header| (header, Color::White)),
    )?;
    write_pad(out, tail)?;
    reset_term!(out)?;

    // rows
    for line in 0..height {
        let position = pane.top + line;
        queue!(out, cursor::MoveTo(x, line as u16 + 2))?;
        match pane.table.visible.get(position) {
            Some(&index) => {
                let attr = match (position == pane.cursor, active) {
                    (true, true) => Attribute::Reverse,
                    (true, false) => Attribute::Underlined,
                    _ => Attribute::Reset,
                };
                write_entry(out, &widths, attr, &pane.table.entries[index], highlight)?;
                write_pad(out, tail)?;
            }
            None => write_pad(out, width)?,
        }
    }
    reset_term!(out)
}

async fn wait_active(rx: &mut watch::Receiver<bool>) -> bool {
    rx.wait_for(|a| *a).await.is_ok()
}

fn spawn_input_thread(
    tx: mpsc::UnboundedSender<Msg>,
    last_active: Arc<std::sync::Mutex<Instant>>,
    active_tx: Arc<watch::Sender<bool>>,
) {
    std::thread::spawn(move || {
        loop {
            let event = event::read();
            let failed = event.is_err();
            *last_active.lock().unwrap() = Instant::now();
            active_tx.send_if_modified(|a| !std::mem::replace(a, true));
            if tx.send(Msg::Term(event)).is_err() || failed {
                break;
            }
        }
    });
}

fn spawn_idle_watcher(
    tx: mpsc::UnboundedSender<Msg>,
    last_active: Arc<std::sync::Mutex<Instant>>,
    active_tx: Arc<watch::Sender<bool>>,
) {
    tokio::spawn(async move {
        let start = Instant::now() + Duration::from_secs(1);
        let mut tick = time::interval_at(start, Duration::from_secs(1));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut n: u32 = 0;
        loop {
            tick.tick().await;
            n = n.wrapping_add(1);

            let idle = last_active.lock().unwrap().elapsed() > SLEEP_TIMEOUT;
            let msg = if !idle {
                Some(Msg::Sleep(false))
            } else if active_tx.send_if_modified(|a| std::mem::replace(a, false)) {
                Some(Msg::Sleep(true))
            } else if n % 5 == 0 {
                Some(Msg::Redraw)
            } else {
                None
            };

            if let Some(msg) = msg {
                if tx.send(msg).is_err() {
                    break;
                }
            }
        }
    });
}

fn spawn_connections_poller(
    client: Arc<Client>,
    tx: mpsc::UnboundedSender<Msg>,
    mut active_rx: watch::Receiver<bool>,
    mut conns_open_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            let period = if *conns_open_rx.borrow() {
                CONNECTIONS_REFRESH_INTERVAL
            } else {
                BACKGROUND_CONNECTIONS_REFRESH_INTERVAL
            };
            let sleep = time::sleep(period);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep => {}
                _ = conns_open_rx.changed() => continue,
            }

            if !wait_active(&mut active_rx).await {
                break;
            }
            if let Ok(snapshot) = client.connections().await {
                if tx.send(Msg::Snapshot(snapshot)).is_err() {
                    break;
                }
            }
        }
    });
}

fn spawn_proxies_poller(
    client: Arc<Client>,
    tx: mpsc::UnboundedSender<Msg>,
    mut active_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let start = Instant::now() + PROXIES_REFRESH_INTERVAL;
        let mut tick = time::interval_at(start, PROXIES_REFRESH_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if !wait_active(&mut active_rx).await {
                break;
            }
            if let Ok(proxies) = client.proxies().await {
                if tx
                    .send(Msg::Proxies(entries_from_proxies(proxies)))
                    .is_err()
                {
                    break;
                }
            }
        }
    });
}

async fn probe_all(
    client: &Arc<Client>,
    tx: &mpsc::UnboundedSender<Msg>,
    semaphore: &Arc<Semaphore>,
    url: &Arc<str>,
    timeout: Duration,
    probes: Vec<String>,
) {
    let mut set = JoinSet::new();
    for probe in probes {
        let client = Arc::clone(client);
        let semaphore = Arc::clone(semaphore);
        let tx = tx.clone();
        let url = Arc::clone(url);
        set.spawn(async move {
            let Ok(_permit) = semaphore.acquire().await else {
                return;
            };
            let delay = match client.proxy_delay(&probe, &url, timeout).await {
                Ok(d) => Delay::Success {
                    ms: d.as_millis().min(u128::from(u16::MAX)) as u16,
                    at: Instant::now(),
                },
                Err(_) => Delay::Fail { at: Instant::now() },
            };
            let _ = tx.send(Msg::Delay { probe, delay });
        });
    }
    while set.join_next().await.is_some() {}
}

fn spawn_delay_prober(
    client: Arc<Client>,
    tx: mpsc::UnboundedSender<Msg>,
    mut active_rx: watch::Receiver<bool>,
    mut conns_open_rx: watch::Receiver<bool>,
    targets_rx: watch::Receiver<Vec<String>>,
    url: Arc<str>,
    timeout: Duration,
) {
    tokio::spawn(async move {
        let semaphore = Arc::new(Semaphore::new(DELAY_MAX_CONCURRENT_PROBES));
        let mut last_probe: Option<Instant> = None;

        loop {
            if let Some(last) = last_probe {
                let period = if *conns_open_rx.borrow() {
                    BACKGROUNG_PROXY_DELAY_INTERVAL
                } else {
                    PROXY_DELAY_INTERVAL
                };
                let sleep = time::sleep_until(last + period);
                tokio::pin!(sleep);
                tokio::select! {
                    _ = &mut sleep => {}
                    res = conns_open_rx.changed() => {
                        if res.is_err() { break; }
                        continue;
                    }
                }
            }

            if !wait_active(&mut active_rx).await {
                break;
            }

            let probes = targets_rx.borrow().clone();
            last_probe = Some(Instant::now());
            probe_all(&client, &tx, &semaphore, &url, timeout, probes).await;

            if tx.is_closed() {
                break;
            }
        }
    });
}

async fn handle_msg(
    msg: Msg,
    app: &mut App,
    out: &mut BufWriter<io::Stdout>,
    conns_open_tx: &watch::Sender<bool>,
    targets_tx: &watch::Sender<Vec<String>>,
) -> crate::Result<bool> {
    match msg {
        Msg::Term(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
            let was_conns = app.conn_visible();
            if app.handle_key(key).await {
                return Ok(true);
            }
            let now_conns = app.conn_visible();
            if was_conns != now_conns {
                conns_open_tx.send(now_conns).ok();
            }
        }
        Msg::Term(event) => {
            if let Event::Resize(cols, rows) = event? {
                app.resize(cols, rows);
                queue!(out, Clear(ClearType::All))?;
            }
        }
        Msg::Delay { probe, delay } => app.apply_delay(probe, delay),
        Msg::Proxies(entries) => {
            app.apply_proxies(entries);
            let probes = app.probes();
            targets_tx.send_if_modified(|current| {
                if *current == probes {
                    false
                } else {
                    *current = probes;
                    true
                }
            });
        }
        Msg::Redraw => {}
        Msg::Sleep(v) => app.is_sleep = v,
        Msg::Snapshot(snapshot) => app.apply_connections_snapshot(snapshot),
    }
    Ok(false)
}

pub async fn run(args: &crate::cli::Args, client: Client) -> crate::Result<()> {
    let client = Arc::new(client);
    let url: Arc<str> = Arc::from(args.url.as_str());

    let initial = Table::new(entries_from_proxies(client.proxies().await?));

    let _guard = TerminalGuard::new()?;
    let mut out = BufWriter::new(io::stdout());
    let mut app = App::new(initial, client.clone())?;
    if let Ok(snapshot) = client.connections().await {
        app.apply_connections_snapshot(snapshot);
    }
    app.draw(&mut out)?;

    let last_active = Arc::new(std::sync::Mutex::new(Instant::now()));
    let (active_tx, active_rx) = watch::channel(true);
    let active_tx = Arc::new(active_tx);

    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    let (targets_tx, targets_rx) = watch::channel(app.probes());
    let (conns_open_tx, conns_open_rx) = watch::channel(app.conn_visible());

    spawn_input_thread(tx.clone(), last_active.clone(), active_tx.clone());
    spawn_idle_watcher(tx.clone(), last_active, active_tx);
    spawn_connections_poller(
        client.clone(),
        tx.clone(),
        active_rx.clone(),
        conns_open_rx.clone(),
    );
    spawn_proxies_poller(client.clone(), tx.clone(), active_rx.clone());
    spawn_delay_prober(
        client,
        tx.clone(),
        active_rx,
        conns_open_rx,
        targets_rx,
        url,
        Duration::from_millis(args.timeout_ms),
    );
    drop(tx);

    'main: loop {
        let Some(first) = rx.recv().await else { break };

        let mut next = Some(first);
        while let Some(msg) = next.take().or_else(|| rx.try_recv().ok()) {
            if handle_msg(msg, &mut app, &mut out, &conns_open_tx, &targets_tx).await? {
                break 'main;
            }
        }

        app.draw(&mut out)?;
    }

    Ok(())
}
