//! Remotino TUI: a terminal-native SSH connection manager over the same encrypted store the
//! desktop app uses. SSH only - RDP is graphical and has no place in a text terminal.
//!
//! Flow: unlock your identity (passphrase), read + decrypt the connection tree, browse a
//! filterable list of SSH hosts, and drop into a live shell. Credentials come from the vault
//! and stay in-process.

mod ssh;

use std::io::{stdout, Stdout, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{execute, terminal};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph};
use ratatui::{Frame, Terminal};

use remotino_crypto::identity::{Identity, SealedIdentity};
use remotino_crypto::repository::Repository as _;
use remotino_model::event::Event as ChainEvent;
use remotino_model::ids::CredentialId;
use remotino_model::projection::{ConnectionKind, Credential, CredentialSecret, Projection};
use remotino_model::structure::Structure;
use remotino_store::SqliteRepo;

/// One SSH host as the browser shows it, with its resolved credential (if any).
struct Host {
    name: String,
    host: String,
    port: u16,
    folder: String,
    credential: Option<Credential>,
}

type Tui = Terminal<CrosstermBackend<Stdout>>;

#[tokio::main]
async fn main() -> Result<()> {
    if let Err(e) = real_main().await {
        // Make sure the terminal is usable if we bailed mid-TUI.
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
        eprintln!("remotino: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

async fn real_main() -> Result<()> {
    let dir = resolve_data_dir()?;
    let identity = unlock(&dir)?;
    let hosts = load_hosts(&dir, &identity)?;
    if hosts.is_empty() {
        bail!("no SSH connections found in this vault — add some in the Remotino desktop app");
    }
    run_tui(hosts).await
}

// ---- data dir + unlock (plain terminal, before the TUI) ----

/// Where the desktop app keeps `identity.cbor` + `store.db`. Overridable, and we probe both
/// the current bundle id and the product name in case the app's data dir convention differs.
fn resolve_data_dir() -> Result<PathBuf> {
    if let Some(arg) = std::env::args().nth(1) {
        if arg == "--data-dir" {
            if let Some(p) = std::env::args().nth(2) {
                return Ok(PathBuf::from(p));
            }
        }
    }
    if let Ok(p) = std::env::var("REMOTINO_DATA_DIR") {
        return Ok(PathBuf::from(p));
    }
    let base = dirs::data_dir().context("could not locate a data directory")?;
    Ok(base.join("sk.tibtech.remotino"))
}

fn unlock(dir: &Path) -> Result<Identity> {
    let id_path = dir.join("identity.cbor");
    if !id_path.exists() {
        bail!(
            "no identity at {} — set up Remotino in the desktop app first, or pass --data-dir",
            id_path.display()
        );
    }
    let bytes = std::fs::read(&id_path).context("reading identity")?;
    let sealed: SealedIdentity =
        ciborium::from_reader(bytes.as_slice()).map_err(|_| anyhow!("identity file unreadable"))?;

    for attempt in 0..3 {
        let pass = rpassword::prompt_password("Passphrase: ").context("reading passphrase")?;
        match sealed.unlock(&pass) {
            Ok(id) => return Ok(id),
            Err(_) if attempt < 2 => eprintln!("Wrong passphrase, try again."),
            Err(_) => bail!("wrong passphrase"),
        }
    }
    unreachable!()
}

fn load_hosts(dir: &Path, identity: &Identity) -> Result<Vec<Host>> {
    let repo = SqliteRepo::open(&dir.join("store.db")).context("opening the store")?;
    let entries = repo.read_from(None).context("reading the store")?;
    let events: Vec<ChainEvent> = entries
        .iter()
        .map(|e| ChainEvent::from_payload(&e.body.payload))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("decoding the log: {e}"))?;
    let structure = Structure::fold(&events).map_err(|e| anyhow!("folding the log: {e}"))?;
    let projection =
        Projection::project(&structure, identity).map_err(|e| anyhow!("decrypting: {e}"))?;

    let mut hosts: Vec<Host> = Vec::new();
    for (id, conn) in &projection.connections {
        if conn.kind != ConnectionKind::Ssh {
            continue; // SSH only
        }
        let folder = structure
            .entries
            .get(id)
            .and_then(|node| projection.folders.get(&node.folder))
            .and_then(|f| f.name.clone())
            .unwrap_or_default();
        let credential = conn
            .credential_ref
            .as_deref()
            .and_then(parse_cred_id)
            .and_then(|cid| projection.credentials.get(&cid).cloned());
        hosts.push(Host {
            name: conn.name.clone(),
            host: conn.host.clone(),
            port: conn.port,
            folder,
            credential,
        });
    }
    hosts.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(hosts)
}

fn parse_cred_id(hex_str: &str) -> Option<CredentialId> {
    let bytes = hex::decode(hex_str).ok()?;
    let arr: [u8; 16] = bytes.as_slice().try_into().ok()?;
    Some(CredentialId(arr))
}

// ---- the TUI ----

async fn run_tui(all: Vec<Host>) -> Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout()))?;

    let result = browse(&mut term, &all).await;

    disable_raw_mode()?;
    execute!(stdout(), LeaveAlternateScreen)?;
    result
}

async fn browse(term: &mut Tui, all: &[Host]) -> Result<()> {
    let mut filter = String::new();
    let mut selected = 0usize;
    let mut status = String::new();

    loop {
        let filtered = filter_hosts(all, &filter);
        if selected >= filtered.len() {
            selected = filtered.len().saturating_sub(1);
        }
        term.draw(|f| draw(f, &filtered, &filter, selected, &status))?;

        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue; // Windows sends key-release too
        }
        status.clear();
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if ctrl => break,
            KeyCode::Char('q') if ctrl => break,
            KeyCode::Esc => {
                if filter.is_empty() {
                    break;
                }
                filter.clear();
                selected = 0;
            }
            KeyCode::Up => selected = selected.saturating_sub(1),
            KeyCode::Char('p') if ctrl => selected = selected.saturating_sub(1),
            KeyCode::Down => {
                if selected + 1 < filtered.len() {
                    selected += 1;
                }
            }
            KeyCode::Char('n') if ctrl => {
                if selected + 1 < filtered.len() {
                    selected += 1;
                }
            }
            KeyCode::Backspace => {
                filter.pop();
                selected = 0;
            }
            KeyCode::Enter => {
                if let Some(host) = filtered.get(selected) {
                    suspend()?;
                    let outcome = connect(host).await;
                    resume(term)?;
                    if let Err(e) = outcome {
                        status = format!("{e:#}");
                    }
                }
            }
            KeyCode::Char(c) if !ctrl => {
                filter.push(c);
                selected = 0;
            }
            _ => {}
        }
    }
    Ok(())
}

fn filter_hosts<'a>(all: &'a [Host], filter: &str) -> Vec<&'a Host> {
    let q = filter.trim().to_lowercase();
    all.iter()
        .filter(|h| {
            q.is_empty()
                || h.name.to_lowercase().contains(&q)
                || h.host.to_lowercase().contains(&q)
                || h.folder.to_lowercase().contains(&q)
        })
        .collect()
}

fn draw(f: &mut Frame, hosts: &[&Host], filter: &str, selected: usize, status: &str) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(f.area());

    let title = Line::from(vec![
        Span::styled(
            " \u{203a}_ remotino",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ssh  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} host{}", hosts.len(), if hosts.len() == 1 { "" } else { "s" }),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    f.render_widget(Paragraph::new(title), rows[0]);

    let filter_line = Line::from(vec![
        Span::styled(" filter: ", Style::default().fg(Color::DarkGray)),
        Span::styled(filter, Style::default().fg(Color::White)),
        Span::styled("\u{258f}", Style::default().fg(Color::Green)),
    ]);
    f.render_widget(Paragraph::new(filter_line), rows[1]);

    let items: Vec<ListItem> = hosts
        .iter()
        .map(|h| {
            let mut spans = vec![
                Span::styled(format!("{:<26}", trunc(&h.name, 26)), Style::default().fg(Color::White)),
                Span::styled(format!("{}:{}", h.host, h.port), Style::default().fg(Color::Cyan)),
            ];
            if !h.folder.is_empty() {
                spans.push(Span::styled(format!("   {}", h.folder), Style::default().fg(Color::DarkGray)));
            }
            if h.credential.is_some() {
                spans.push(Span::styled("  key", Style::default().fg(Color::Yellow)));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = List::new(items)
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(18, 38, 28))
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" \u{203a} ");
    let mut state = ListState::default();
    if !hosts.is_empty() {
        state.select(Some(selected));
    }
    f.render_stateful_widget(list, rows[2], &mut state);

    let footer = if status.is_empty() {
        Line::from(Span::styled(
            " \u{2191}/\u{2193} move   \u{21b5} connect   type to filter   esc clear/quit   ^C quit",
            Style::default().fg(Color::DarkGray),
        ))
    } else {
        Line::from(Span::styled(format!(" ! {status}"), Style::default().fg(Color::Red)))
    };
    f.render_widget(Paragraph::new(footer), rows[3]);
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('\u{2026}');
        out
    }
}

// ---- connecting: suspend the TUI, run the shell, resume ----

fn suspend() -> Result<()> {
    disable_raw_mode()?;
    execute!(stdout(), LeaveAlternateScreen)?;
    Ok(())
}

fn resume(term: &mut Tui) -> Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    term.clear()?;
    Ok(())
}

async fn connect(host: &Host) -> Result<()> {
    // Resolve auth on the normal (cooked) screen, so any prompt behaves.
    let auth = match &host.credential {
        Some(cred) => cred_to_auth(cred)?,
        None => prompt_auth(host)?,
    };
    println!("Connecting to {} ({}:{})\u{2026}", host.name, host.host, host.port);
    let _ = stdout().flush();

    // The passthrough needs raw mode; the TUI's raw mode was dropped in suspend().
    enable_raw_mode()?;
    let size = terminal::size().unwrap_or((80, 24));
    let result = ssh::run(&host.host, host.port, auth, size.0, size.1).await;
    disable_raw_mode()?;
    println!(); // tidy the cursor after the session
    result
}

fn cred_to_auth(cred: &Credential) -> Result<ssh::Auth> {
    match &cred.secret {
        CredentialSecret::Password { password } => Ok(ssh::Auth::Password {
            username: cred.username.clone(),
            password: password.clone(),
        }),
        CredentialSecret::Key {
            private_key,
            passphrase,
            ..
        } => Ok(ssh::Auth::Key {
            username: cred.username.clone(),
            private_key: private_key.clone(),
            passphrase: passphrase.clone(),
        }),
        _ => bail!("that credential type isn't usable for SSH"),
    }
}

fn prompt_auth(host: &Host) -> Result<ssh::Auth> {
    print!("Username for {}: ", host.host);
    stdout().flush().ok();
    let mut username = String::new();
    std::io::stdin()
        .read_line(&mut username)
        .context("reading username")?;
    let username = username.trim().to_owned();
    let password = rpassword::prompt_password("Password: ").context("reading password")?;
    Ok(ssh::Auth::Password { username, password })
}
