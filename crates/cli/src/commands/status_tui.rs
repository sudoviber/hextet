//! `hextet status --tui`：ratatui + crossterm 交互式状态视图。
//!
//! 仅 Linux 编译（`#[cfg(target_os = "linux")]`）；macOS 开发机无法编译/运行本模块，
//! 其正确性靠交叉 target（`x86_64-unknown-linux-gnu`）编译 + 真机 TTY 交互验证。
//! 绘制循环本身**不做单元测试**（需要真实 TTY），只有无 TTY 的纯逻辑
//! （`build_report` 与各列格式化 helper）在 `status.rs` 里被覆盖。

use std::io::{self, Stdout};
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use hextet_core::config::Config;
use hextet_engine::status::build_report;
use hextet_proto::{StatusReport, StatusRow};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Style, Stylize};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};

use super::status::{daemon_header, handshake_column, punch_column, routes_column};

/// 刷新间隔：每秒重读一次 daemon 状态并重绘。
const REFRESH: Duration = Duration::from_secs(1);

/// 列宽（与人类 `status` 表格同列序；TUI 不含 `lan` 计数列）。
const COLUMN_WIDTHS: [Constraint; 9] = [
    Constraint::Length(14), // peer
    Constraint::Length(30), // address
    Constraint::Length(34), // endpoint
    Constraint::Length(8),  // source
    Constraint::Length(22), // punch
    Constraint::Length(11), // handshake
    Constraint::Length(8),  // rx
    Constraint::Length(8),  // tx
    Constraint::Min(12),    // routes
];

/// 终端守卫：进入 raw mode + alternate screen，`Drop` 时恢复。
///
/// `Drop` 在正常退出与 panic 展开两条路径上都会跑，保证 panic 后终端不被留在
/// 坏状态里（离开 alternate screen + 关闭 raw mode）。
struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    fn new() -> anyhow::Result<Self> {
        let mut stdout = io::stdout();
        enable_raw_mode().context("无法启用 raw mode")?;
        execute!(stdout, EnterAlternateScreen).context("无法进入 alternate screen")?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout)).context("无法初始化终端")?;
        Ok(Self { terminal })
    }

    fn draw(&mut self, report: Option<&StatusReport>, err: Option<&str>) -> anyhow::Result<()> {
        self.terminal.draw(|f| {
            let footer_height = if err.is_some() { 1 } else { 0 };
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Min(0),
                    Constraint::Length(footer_height),
                ])
                .split(f.area());

            // 头部：daemon 存活 + 多久前更新（与人类 status 同逻辑）
            let header = match report {
                Some(r) => daemon_header(r.daemon.as_ref()),
                None => match err {
                    Some(e) => format!("状态不可用：{e}"),
                    None => "读取中…".to_string(),
                },
            };
            f.render_widget(Paragraph::new(header), chunks[0]);

            // peer 表格
            let rows = report.map(|r| peer_rows(&r.peers)).unwrap_or_default();
            let table = Table::new(rows, COLUMN_WIDTHS)
                .header(header_row())
                .block(Block::default().borders(Borders::ALL).title("peers"))
                .column_spacing(2);
            f.render_widget(table, chunks[1]);

            // 读取失败时在底部显示一行错误，而不是 panic
            if let Some(e) = err {
                f.render_widget(
                    Paragraph::new(format!("⚠ {e}")).style(Style::default().red()),
                    chunks[2],
                );
            }
        })?;
        Ok(())
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

fn header_row() -> Row<'static> {
    Row::new(vec![
        "peer",
        "address",
        "endpoint",
        "source",
        "punch",
        "handshake",
        "rx",
        "tx",
        "routes",
    ])
    .style(Style::default().bold())
}

fn peer_rows(peers: &[StatusRow]) -> Vec<Row<'static>> {
    peers
        .iter()
        .map(|r| {
            Row::new(vec![
                r.peer.clone(),
                r.address.clone(),
                r.endpoint.clone().unwrap_or_default(),
                r.endpoint_source.clone().unwrap_or_else(|| "-".to_string()),
                punch_column(r),
                handshake_column(r),
                r.rx_bytes.to_string(),
                r.tx_bytes.to_string(),
                routes_column(r),
            ])
        })
        .collect()
}

/// 是否应退出循环：`q`/`Esc`/`Ctrl-C` 的按下事件。
///
/// 抽出成纯函数，便于无 TTY 单测（见模块底部）——ratatui 绘制循环本身不单测。
fn quit_requested(event: &Event) -> bool {
    let Event::Key(key) = event else {
        return false;
    };
    if key.kind != KeyEventKind::Press {
        return false;
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
        _ => false,
    }
}

/// 交互循环：每秒重读 `build_report` 并重绘，`q`/`Esc`/`Ctrl-C` 退出。
///
/// 对 `build_report` 失败保持弹性（state 文件瞬时不可读等）：保留上次好报告、
/// 底部显示错误行，继续轮询。终端初始化失败则直接返回错误（`run` 的调用方
/// 会把错误冒泡到 main）。
pub(crate) fn run(cfg: &Config, backend: impl hextet_wg::WgBackend) -> anyhow::Result<()> {
    let mut tui = Tui::new()?;
    let mut last_report: Option<StatusReport> = None;

    loop {
        // 重读状态：成功则更新 last-good 报告；失败则保留上次报告、底部显示错误行。
        let mut error: Option<String> = None;
        match build_report(cfg, &backend, SystemTime::now()) {
            Ok(report) => last_report = Some(report),
            Err(e) => error = Some(format!("读取状态失败：{e:#}")),
        }

        tui.draw(last_report.as_ref(), error.as_deref())?;

        if event::poll(REFRESH).context("轮询键盘事件失败")?
            && quit_requested(&event::read().context("读取键盘事件失败")?)
        {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    #[test]
    fn quit_keys_are_recognized() {
        // q / Esc / Ctrl-C 的按下事件都应退出；其余按键与释放事件不应退出。
        assert!(quit_requested(&Event::Key(KeyEvent::new(
            KeyCode::Char('q'),
            KeyModifiers::NONE
        ))));
        assert!(quit_requested(&Event::Key(KeyEvent::new(
            KeyCode::Esc,
            KeyModifiers::NONE
        ))));
        assert!(quit_requested(&Event::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        ))));

        // 非 CONTROL 修饰下的 c 不退出
        assert!(!quit_requested(&Event::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::NONE
        ))));
        // 其他按键不退出
        assert!(!quit_requested(&Event::Key(KeyEvent::new(
            KeyCode::Char('j'),
            KeyModifiers::NONE
        ))));
        // 非键盘事件不退出
        assert!(!quit_requested(&Event::Resize(10, 20)));
        // 释放（Release）事件不退出
        let mut release = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        assert!(!quit_requested(&Event::Key(release)));
    }
}
