use std::collections::HashMap;
use std::io::{self, BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use singbox_clash_api::Client;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{self, Instant, MissedTickBehavior};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const SCROLLOFF: usize = 6;
const MIN_SIZE: (u16, u16) = (60, 8);
const GAP: &str = "  ";
const COLUMNS: usize = 5;
const HEADERS: [&str; COLUMNS] = ["TYPE", "NAME", "MEM", "NOW", "MS"];
const ALIGNS: [Align; COLUMNS] = [
    Align::Left,
    Align::Left,
    Align::Right,
    Align::Left,
    Align::Right,
];
const DELAY_STALE_AFTER: Duration = Duration::from_secs(10);
const HINT: &str = " q quit   h/l pane   j/k move   g/G ends   / filter   esc clear   Enter select";

const DELAY_INTERVAL: Duration = Duration::from_secs(7);
const PROXIES_REFRESH: Duration = Duration::from_secs(21);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_PROBES: usize = 42;

const SLEEP_TIMEOUT: Duration = DELAY_STALE_AFTER;

#[derive(Clone, Copy)]
enum Align {
    Left,
    Right,
}

fn fit(text: &str, width: usize, align: Align) -> String {
    let (mut shown, used) = if text.width() <= width {
        (text.to_owned(), text.width())
    } else {
        let mut shown = String::new();
        let mut used = 0;
        for ch in text.chars() {
            let w = ch.width().unwrap_or(0);
            if used + w + 1 > width {
                break;
            }
            shown.push(ch);
            used += w;
        }
        if width > 0 {
            shown.push('…');
            used += 1;
        }
        (shown, used)
    };
    let pad = " ".repeat(width.saturating_sub(used));
    match align {
        Align::Left => {
            shown.push_str(&pad);
            shown
        }
        Align::Right => pad + &shown,
    }
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
    Fail,
}

impl Delay {
    fn display(&self) -> (String, Color) {
        match *self {
            Delay::None => ("-".into(), Color::DarkGrey),
            Delay::Fail => ("X".into(), Color::Red),
            Delay::Success { ms, at } => {
                let color = if at.elapsed() > DELAY_STALE_AFTER {
                    Color::DarkGrey
                } else {
                    match ms {
                        0..=75 => Color::Cyan,
                        76..=150 => Color::Green,
                        151..=300 => Color::Yellow,
                        301..=1000 => Color::Red,
                        1001..=2000 => Color::Magenta,
                        _ => Color::Black,
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

fn measure(entries: &[Entry]) -> [usize; COLUMNS] {
    let mut widths = HEADERS.map(|header| header.width());
    for entry in entries {
        widths[0] = widths[0].max(entry.kind.width());
        widths[1] = widths[1].max(entry.name.width());
        widths[2] = widths[2].max(entry.members.len().to_string().len());
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
            widths: measure(&entries),
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

    fn set_delay_by_probe(&mut self, probe: &str, delay: Delay) {
        let mut changed = false;
        for entry in &mut self.entries {
            if entry.probe_name() == probe {
                entry.delay = delay;
                changed = true;
            }
        }
        if changed {
            self.widths = measure(&self.entries);
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
        let flex = pane_width.saturating_sub(1 + GAP.len() * (COLUMNS - 1) + kind + mem + delay);
        let now_width = if name + now <= flex {
            now
        } else {
            now.min(flex / 3)
        };
        let name_width = name.min(flex - now_width);
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
    Input { saved_filter: String },
}

enum Msg {
    Term(io::Result<Event>),
    Proxies(Vec<Entry>),
    Delay { probe: String, delay: Delay },
}

struct App {
    size: (u16, u16),
    left: Pane,
    right: Pane,
    right_source: Option<String>,
    delays: HashMap<String, Delay>,
    active: Side,
    mode: Mode,
    client: Arc<Client>,
}

impl App {
    fn new(proxies: Table, client: Arc<Client>) -> io::Result<Self> {
        let mut app = Self {
            size: terminal::size()?,
            left: Pane::new("PROXIES", proxies),
            right: Pane::new("MEMBERS", Table::new(Vec::new())),
            right_source: None,
            delays: HashMap::new(),
            active: Side::Left,
            mode: Mode::Normal,
            client,
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
        self.left.table.set_delay_by_probe(&probe, delay);
        self.right.table.set_delay_by_probe(&probe, delay);
        self.delays.insert(probe, delay);
    }

    fn apply_proxies(&mut self, mut entries: Vec<Entry>) {
        for entry in &mut entries {
            if let Some(&delay) = self.delays.get(entry.probe_name()) {
                entry.delay = delay;
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
    }

    /// Returns `true` when the app should quit.
    async fn handle_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            return true;
        }
        match self.mode {
            Mode::Input { .. } => {
                self.handle_input_key(key.code, ctrl);
                false
            }
            Mode::Normal => self.handle_normal_key(key.code, ctrl).await,
        }
    }

    async fn handle_normal_key(&mut self, code: KeyCode, ctrl: bool) -> bool {
        match code {
            KeyCode::Char('q') => return true,

            KeyCode::Enter => {
                let selected_l = self.left.selected().map(|index| {
                    let e = &self.left.table.entries[index];
                    (e.kind.clone(), e.name.clone())
                });
                let selected_r = self.right.selected().map(|index| {
                    let e = &self.right.table.entries[index];
                    (e.kind.clone(), e.name.clone(), e.delay)
                });

                if let (Some((kind_l, name_l)), Some((kind_r, name_r, delay_r))) =
                    (selected_l, selected_r)
                {
                    if kind_l == "Selector" {
                        // режим MEMBERS: левый селектор -> правый член
                        match self.client.select_proxy(&name_l, &name_r).await {
                            Ok(_) => {
                                if let Some(&index) = self.left.table.by_name.get(&name_l) {
                                    let entry = &mut self.left.table.entries[index];
                                    entry.now = Some(name_r);
                                    entry.delay = delay_r;
                                    self.left.table.widths = measure(&self.left.table.entries);
                                }
                            }
                            Err(_) => { /* show error */ }
                        }
                    } else if kind_r == "Selector" {
                        match self.client.select_proxy(&name_r, &name_l).await {
                            Ok(_) => {
                                // правая таблица: селектор теперь смотрит на name_l
                                if let Some(&index) = self.right.table.by_name.get(&name_r) {
                                    let entry = &mut self.right.table.entries[index];
                                    entry.now = Some(name_l.clone());
                                    self.right.table.widths = measure(&self.right.table.entries);
                                }
                                // левая таблица: тот же селектор, обновляем и там
                                if let Some(&index) = self.left.table.by_name.get(&name_r) {
                                    let entry = &mut self.left.table.entries[index];
                                    entry.now = Some(name_l);
                                    self.left.table.widths = measure(&self.left.table.entries);
                                }
                            }
                            Err(_) => { /* show error */ }
                        }
                    }
                }
            }

            KeyCode::Char('h') | KeyCode::Left => self.active = Side::Left,
            KeyCode::Char('l') | KeyCode::Right => self.active = Side::Right,
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
                };
            }
            KeyCode::Esc => self.edit_active(|p, _| p.set_filter(String::new())),
            _ => {}
        }
        false
    }

    fn handle_input_key(&mut self, code: KeyCode, ctrl: bool) {
        match code {
            KeyCode::Enter => self.mode = Mode::Normal,
            KeyCode::Esc => {
                if let Mode::Input { saved_filter } =
                    std::mem::replace(&mut self.mode, Mode::Normal)
                {
                    self.edit_active(|p, _| p.set_filter(saved_filter));
                }
            }
            KeyCode::Backspace => self.edit_active(|p, _| {
                let mut filter = std::mem::take(&mut p.filter);
                filter.pop();
                p.set_filter(filter);
            }),
            KeyCode::Char('u') if ctrl => self.edit_active(|p, _| p.set_filter(String::new())),
            KeyCode::Char(ch) if !ctrl => self.edit_active(|p, _| {
                let mut filter = std::mem::take(&mut p.filter);
                filter.push(ch);
                p.set_filter(filter);
            }),
            _ => {}
        }
    }

    fn draw(&self, out: &mut impl Write) -> io::Result<()> {
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

        let height = self.list_height();
        let left_width = cols / 2;

        for y in 0..rows - 1 {
            queue!(
                out,
                cursor::MoveTo(left_width - 1, y),
                SetForegroundColor(Color::DarkGrey),
                Print('│'),
                ResetColor
            )?;
        }
        draw_pane(
            out,
            &self.left,
            0,
            usize::from(left_width - 1),
            height,
            self.active == Side::Left,
            Highlight::None,
        )?;
        let highlight = match self.left.selected().map(|i| &self.left.table.entries[i]) {
            Some(e) if e.now.is_some() => Highlight::ByName(e.now.as_deref().unwrap()),
            Some(e) => Highlight::ByNow(&e.name),
            None => Highlight::None,
        };
        draw_pane(
            out,
            &self.right,
            left_width,
            usize::from(cols - left_width),
            height,
            self.active == Side::Right,
            highlight,
        )?;
        self.draw_footer(out)?;
        out.flush()
    }

    fn draw_footer(&self, out: &mut impl Write) -> io::Result<()> {
        let (cols, rows) = self.size;
        queue!(out, cursor::MoveTo(0, rows - 1))?;
        match self.mode {
            Mode::Input { .. } => {
                let text = format!(" /{}", self.active_pane().filter);
                let caret = text.width().min(usize::from(cols) - 1) as u16;
                queue!(
                    out,
                    Print(fit(&text, usize::from(cols), Align::Left)),
                    cursor::MoveTo(caret, rows - 1),
                    cursor::Show
                )
            }
            Mode::Normal => queue!(
                out,
                SetForegroundColor(Color::DarkGrey),
                Print(fit(HINT, usize::from(cols), Align::Left)),
                ResetColor,
                cursor::Hide
            ),
        }
    }
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
        queue!(
            out,
            SetForegroundColor(color),
            Print(fit(text, widths[i], ALIGNS[i]))
        )?;
    }
    queue!(out, ResetColor, SetAttribute(Attribute::Reset))
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
    highlight: Highlight,
) -> io::Result<()> {
    let members = if entry.members.is_empty() {
        "-".to_owned()
    } else {
        entry.members.len().to_string()
    };
    let members_color = if entry.members.is_empty() {
        Color::DarkGrey
    } else {
        Color::Reset
    };
    let now_color = if entry.now.is_some() {
        Color::Reset
    } else {
        Color::DarkGrey
    };
    let (delay, delay_color) = entry.delay.display();
    let name_color = if highlight.matches(entry) {
        Color::Green
    } else {
        Color::Reset
    };
    write_line(
        out,
        widths,
        attr,
        [
            (entry.kind.as_str(), kind_color(&entry.kind)),
            (entry.name.as_str(), name_color),
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
    highlight: Highlight,
) -> io::Result<()> {
    let counter = format!("{}/{} ", pane.table.visible.len(), pane.table.entries.len());
    let title = format!(" {} ", pane.title);
    let title_width = title.width().min(width.saturating_sub(counter.width()));
    let title = fit(&title, title_width, Align::Left);
    let filter = if pane.filter.is_empty() {
        String::new()
    } else {
        format!(" /{}", pane.filter)
    };
    let filter = fit(
        &filter,
        width.saturating_sub(title_width + counter.width()),
        Align::Left,
    );

    queue!(out, cursor::MoveTo(x, 0))?;
    if active {
        queue!(
            out,
            SetAttribute(Attribute::Reverse),
            SetAttribute(Attribute::Bold)
        )?;
    } else {
        queue!(out, SetForegroundColor(Color::DarkGrey))?;
    }
    queue!(
        out,
        Print(title),
        SetAttribute(Attribute::Reset),
        ResetColor,
        SetForegroundColor(Color::Yellow),
        Print(filter),
        SetForegroundColor(Color::DarkGrey),
        Print(counter),
        ResetColor
    )?;

    let widths = pane.table.layout(width);
    queue!(out, cursor::MoveTo(x, 1))?;
    write_line(
        out,
        &widths,
        Attribute::Bold,
        HEADERS.map(|header| (header, Color::DarkGrey)),
    )?;

    for line in 0..height {
        let position = pane.top + line;
        queue!(out, cursor::MoveTo(x, line as u16 + 2))?;
        match pane.table.visible.get(position) {
            Some(&index) => {
                let attr = match (position == pane.cursor, active) {
                    (true, true) => Attribute::Reverse,
                    (true, false) => Attribute::Bold,
                    _ => Attribute::Reset,
                };
                write_entry(out, &widths, attr, &pane.table.entries[index], highlight)?;
            }
            None => queue!(out, Print(" ".repeat(width)))?,
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct SharedState {
    last_active: Instant,
}

impl SharedState {
    fn new() -> Self {
        Self {
            last_active: Instant::now(),
        }
    }
}

pub async fn run(args: &crate::cli::Args) -> crate::Result<()> {
    let client = Arc::new(args.build_singbox_clash_api_client()?);
    let url = args.url.clone();

    let initial = Table::new(entries_from_proxies(client.proxies().await?));

    let _guard = TerminalGuard::new()?;
    let mut out = BufWriter::new(io::stdout());
    let ss = Arc::new(Mutex::new(SharedState::new()));
    let mut app = App::new(initial, client.clone())?;
    app.draw(&mut out)?;

    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    let (targets_tx, targets_rx) = watch::channel(app.probes());

    {
        let tx = tx.clone();
        let ss = ss.clone();
        let mut n = 0;
        std::thread::spawn(move || {
            loop {
                let event = event::read();
                let failed = event.is_err();
                if tx.send(Msg::Term(event)).is_err() || failed {
                    break;
                }
                if n % 2 == 0 {
                    ss.lock().unwrap().last_active = Instant::now();
                }
                n += 1;
            }
        });
    }

    {
        let client = Arc::clone(&client);
        let ss = ss.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let start = time::Instant::now() + PROXIES_REFRESH;
            let mut tick = time::interval_at(start, PROXIES_REFRESH);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                {
                    let guard = ss.lock().unwrap();
                    if guard.last_active.elapsed() > SLEEP_TIMEOUT {
                        continue;
                    }
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

    {
        let client = Arc::clone(&client);
        let ss = ss.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES));
            let mut tick = time::interval(DELAY_INTERVAL); // первый тик — сразу
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                {
                    let guard = ss.lock().unwrap();
                    if guard.last_active.elapsed() > SLEEP_TIMEOUT {
                        continue;
                    }
                }
                let probes = targets_rx.borrow().clone();

                let mut set = JoinSet::new();
                for probe in probes {
                    let client = Arc::clone(&client);
                    let semaphore = Arc::clone(&semaphore);
                    let tx = tx.clone();
                    let url = url.clone();
                    set.spawn(async move {
                        let Ok(_permit) = semaphore.acquire().await else {
                            return;
                        };
                        let delay = match client.proxy_delay(&probe, &url, PROBE_TIMEOUT).await {
                            Ok(d) => Delay::Success {
                                ms: d.as_millis().min(u128::from(u16::MAX)) as u16,
                                at: Instant::now(),
                            },
                            Err(_) => Delay::Fail,
                        };
                        let _ = tx.send(Msg::Delay { probe, delay });
                    });
                }
                while set.join_next().await.is_some() {}

                if tx.is_closed() {
                    break;
                }
            }
        });
    }

    'main: loop {
        let Some(first) = rx.recv().await else { break };

        let mut next = Some(first);
        while let Some(msg) = next.take().or_else(|| rx.try_recv().ok()) {
            match msg {
                Msg::Term(event) => match event? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        if app.handle_key(key).await {
                            break 'main;
                        }
                    }
                    Event::Resize(cols, rows) => {
                        app.resize(cols, rows);
                        queue!(out, Clear(ClearType::All))?;
                    }
                    _ => {}
                },
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
            }
        }

        app.draw(&mut out)?;
    }

    Ok(())
}
