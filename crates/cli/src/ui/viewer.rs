//! Interactive diff viewer using ratatui
//!
//! Provides a TUI for navigating and viewing file diffs with features like:
//! - File list navigation
//! - Scrollable diff view
//! - Hunk jumping
//! - Multiple diff formats

use anyhow::{Context, Result};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use similar::{ChangeTag, TextDiff};
use std::io;

use crate::ui::icons::Icons;

/// A single diff line
#[derive(Debug, Clone)]
pub enum DiffLine {
    /// Context line (unchanged)
    Context {
        /// Line number in the file
        line_num: Option<usize>,
        /// Line content
        content: String,
    },
    /// Added line
    Add {
        /// Line number in the new file
        line_num: Option<usize>,
        /// Line content
        content: String,
    },
    /// Removed line
    Remove {
        /// Line number in the old file
        line_num: Option<usize>,
        /// Line content
        content: String,
    },
    /// Hunk header
    Header {
        /// Old file line range (start, length)
        old_range: (usize, usize),
        /// New file line range (start, length)
        new_range: (usize, usize),
    },
}

/// A hunk of changes in a file
#[derive(Debug, Clone)]
pub struct Hunk {
    /// Old file line range (start, length)
    pub old_range: (usize, usize),
    /// New file line range (start, length)
    pub new_range: (usize, usize),
    /// Lines in this hunk
    pub lines: Vec<DiffLine>,
}

/// Diff information for a single file
#[derive(Debug, Clone)]
pub struct FileDiff {
    /// Relative path to the file
    pub path: String,
    /// File status (added, modified, deleted)
    pub status: FileStatus,
    /// Hunks of changes
    pub hunks: Vec<Hunk>,
    /// Old content (for reference)
    pub old_content: String,
    /// New content (for reference)
    pub new_content: String,
}

/// File change status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// File is new
    Added,
    /// File is modified
    Modified,
    /// File is deleted
    Deleted,
}

impl FileDiff {
    /// Create a new `FileDiff` from old and new content
    #[must_use]
    pub fn new(path: String, old_content: String, new_content: String, status: FileStatus) -> Self {
        let hunks = Self::compute_hunks(&old_content, &new_content, 3);

        Self {
            path,
            status,
            hunks,
            old_content,
            new_content,
        }
    }

    /// Compute hunks from old and new content
    fn compute_hunks(old_content: &str, new_content: &str, context_lines: usize) -> Vec<Hunk> {
        let diff = TextDiff::from_lines(old_content, new_content);
        let mut hunks = Vec::new();

        for group in diff.grouped_ops(context_lines) {
            if group.is_empty() {
                continue;
            }

            let first = &group[0];
            let last = &group[group.len() - 1];

            let old_start = first.old_range().start + 1;
            let old_len = last.old_range().end - first.old_range().start;
            let new_start = first.new_range().start + 1;
            let new_len = last.new_range().end - first.new_range().start;

            let mut lines = Vec::new();

            // Add hunk header
            lines.push(DiffLine::Header {
                old_range: (old_start, old_len),
                new_range: (new_start, new_len),
            });

            // Add diff lines
            let mut old_line_num = old_start;
            let mut new_line_num = new_start;

            for op in &group {
                for change in diff.iter_changes(op) {
                    let content = change.value().trim_end_matches('\n').to_string();

                    match change.tag() {
                        ChangeTag::Equal => {
                            lines.push(DiffLine::Context {
                                line_num: Some(new_line_num),
                                content,
                            });
                            old_line_num += 1;
                            new_line_num += 1;
                        }
                        ChangeTag::Insert => {
                            lines.push(DiffLine::Add {
                                line_num: Some(new_line_num),
                                content,
                            });
                            new_line_num += 1;
                        }
                        ChangeTag::Delete => {
                            lines.push(DiffLine::Remove {
                                line_num: Some(old_line_num),
                                content,
                            });
                            old_line_num += 1;
                        }
                    }
                }
            }

            hunks.push(Hunk {
                old_range: (old_start, old_len),
                new_range: (new_start, new_len),
                lines,
            });
        }

        hunks
    }

    /// Get total number of diff lines (for scrolling)
    #[must_use]
    pub fn total_lines(&self) -> usize {
        self.hunks.iter().map(|h| h.lines.len()).sum()
    }
}

/// Interactive diff viewer state
pub struct InteractiveDiffViewer {
    /// All file diffs
    files: Vec<FileDiff>,
    /// Currently selected file index
    selected_file: usize,
    /// File list scroll state
    file_list_state: ListState,
    /// Diff view scroll offset
    diff_scroll: usize,
    /// Show help
    show_help: bool,
}

impl InteractiveDiffViewer {
    /// Create a new interactive diff viewer
    #[must_use]
    pub fn new(files: Vec<FileDiff>) -> Self {
        let mut file_list_state = ListState::default();
        if !files.is_empty() {
            file_list_state.select(Some(0));
        }

        Self {
            files,
            selected_file: 0,
            file_list_state,
            diff_scroll: 0,
            show_help: false,
        }
    }

    /// Run the interactive diff viewer
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Terminal setup fails (raw mode, alternate screen)
    /// - Event handling fails
    /// - Terminal restoration fails
    pub fn run(&mut self) -> Result<()> {
        // Setup terminal
        enable_raw_mode().context("Failed to enable raw mode")?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
            .context("Failed to enter alternate screen")?;

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

        // Run app
        let res = self.run_app(&mut terminal);

        // Restore terminal
        disable_raw_mode().context("Failed to disable raw mode")?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )
        .context("Failed to leave alternate screen")?;
        terminal.show_cursor().context("Failed to show cursor")?;

        res
    }

    /// Main application loop
    fn run_app<B: ratatui::backend::Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            terminal.draw(|f| self.render(f))?;

            if let Event::Key(key) = event::read()? {
                // Check for Ctrl+C
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    break;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('?') => self.show_help = !self.show_help,
                    // Up/Down arrows, j/k, and Tab/BackTab switch between files (vim-like)
                    KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab if !self.show_help => {
                        self.next_file();
                    }
                    KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab if !self.show_help => {
                        self.prev_file();
                    }
                    // Ctrl+F/B for full page scroll (vim-like)
                    KeyCode::Char('f')
                        if key.modifiers.contains(KeyModifiers::CONTROL) && !self.show_help =>
                    {
                        self.page_down_full();
                    }
                    KeyCode::Char('b')
                        if key.modifiers.contains(KeyModifiers::CONTROL) && !self.show_help =>
                    {
                        self.page_up_full();
                    }
                    // Ctrl+D/U for half page scroll (vim-like)
                    KeyCode::Char('d')
                        if key.modifiers.contains(KeyModifiers::CONTROL) && !self.show_help =>
                    {
                        self.page_down();
                    }
                    KeyCode::Char('u')
                        if key.modifiers.contains(KeyModifiers::CONTROL) && !self.show_help =>
                    {
                        self.page_up();
                    }
                    // PageUp/PageDown for full page scroll
                    KeyCode::PageDown if !self.show_help => self.page_down_full(),
                    KeyCode::PageUp if !self.show_help => self.page_up_full(),
                    // d/u for half page scroll
                    KeyCode::Char('d') if !self.show_help => self.page_down(),
                    KeyCode::Char('u') if !self.show_help => self.page_up(),
                    // n/N for next/previous hunk
                    KeyCode::Char('n') if !self.show_help => self.next_hunk(),
                    KeyCode::Char('N') if !self.show_help => self.prev_hunk(),
                    // Home/End go to top/bottom of current file
                    KeyCode::Home if !self.show_help => self.scroll_to_top(),
                    KeyCode::End if !self.show_help => self.scroll_to_bottom(),
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Render the UI
    fn render(&self, frame: &mut Frame) {
        if self.show_help {
            Self::render_help(frame);
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(30), // File list
                Constraint::Percentage(70), // Diff view
            ])
            .split(frame.area());

        self.render_file_list(frame, chunks[0]);
        self.render_diff_view(frame, chunks[1]);
    }

    /// Render file list
    fn render_file_list(&self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .files
            .iter()
            .map(|file| {
                let (icon, color) = match file.status {
                    FileStatus::Added => (Icons::ACTION_ADD, Color::Green),
                    FileStatus::Modified => (Icons::ACTION_MODIFY, Color::Yellow),
                    FileStatus::Deleted => (Icons::ACTION_REMOVE, Color::Red),
                };

                ListItem::new(Line::from(vec![
                    Span::styled(icon, Style::default().fg(color)),
                    Span::raw(format!(" {}", file.path)),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .title(format!(
                        " Files ({}/{}) ",
                        self.selected_file + 1,
                        self.files.len()
                    ))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("❯ ");

        let mut state = self.file_list_state.clone();
        frame.render_stateful_widget(list, area, &mut state);
    }

    /// Render diff view
    fn render_diff_view(&self, frame: &mut Frame, area: Rect) {
        if let Some(file) = self.files.get(self.selected_file) {
            let title = format!(" {} ", file.path);

            let mut lines = Vec::new();

            for hunk in &file.hunks {
                for diff_line in &hunk.lines {
                    let line = match diff_line {
                        DiffLine::Header {
                            old_range,
                            new_range,
                        } => Line::from(vec![Span::styled(
                            format!(
                                "@@ -{},{} +{},{} @@",
                                old_range.0, old_range.1, new_range.0, new_range.1
                            ),
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        )]),
                        DiffLine::Add { line_num, content } => {
                            let num_str =
                                line_num.map_or_else(|| "     ".to_string(), |n| format!("{n:4} "));
                            Line::from(vec![
                                Span::styled(num_str, Style::default().fg(Color::DarkGray)),
                                Span::styled(
                                    "+",
                                    Style::default()
                                        .fg(Color::Green)
                                        .add_modifier(Modifier::BOLD),
                                ),
                                Span::styled(content.clone(), Style::default().fg(Color::Green)),
                            ])
                        }
                        DiffLine::Remove { line_num, content } => {
                            let num_str =
                                line_num.map_or_else(|| "     ".to_string(), |n| format!("{n:4} "));
                            Line::from(vec![
                                Span::styled(num_str, Style::default().fg(Color::DarkGray)),
                                Span::styled(
                                    "-",
                                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                                ),
                                Span::styled(content.clone(), Style::default().fg(Color::Red)),
                            ])
                        }
                        DiffLine::Context { line_num, content } => {
                            let num_str =
                                line_num.map_or_else(|| "     ".to_string(), |n| format!("{n:4} "));
                            Line::from(vec![
                                Span::styled(num_str, Style::default().fg(Color::DarkGray)),
                                Span::raw(" "),
                                Span::raw(content.clone()),
                            ])
                        }
                    };
                    lines.push(line);
                }

                // Add blank line between hunks
                lines.push(Line::from(""));
            }

            let paragraph = Paragraph::new(lines)
                .block(
                    Block::default()
                        .title(title)
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan)),
                )
                .scroll((
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        self.diff_scroll as u16
                    },
                    0,
                ));

            frame.render_widget(paragraph, area);
        } else {
            let text = Text::from("No files to display");
            let paragraph = Paragraph::new(text)
                .block(Block::default().borders(Borders::ALL))
                .alignment(Alignment::Center);
            frame.render_widget(paragraph, area);
        }
    }

    /// Create header for help screen
    fn create_help_header() -> Vec<Line<'static>> {
        vec![
            Line::from(vec![Span::styled(
                "Interactive Diff Viewer",
                Style::default().add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
        ]
    }

    /// Create file navigation help section
    fn create_file_navigation_help() -> Vec<Line<'static>> {
        vec![
            Line::from(vec![Span::styled(
                "Files:",
                Style::default().add_modifier(Modifier::UNDERLINED),
            )]),
            Line::from(vec![
                Span::styled("  j/↓       ", Style::default().fg(Color::Cyan)),
                Span::raw("Next file"),
            ]),
            Line::from(vec![
                Span::styled("  k/↑       ", Style::default().fg(Color::Cyan)),
                Span::raw("Previous file"),
            ]),
            Line::from(vec![
                Span::styled("  Tab       ", Style::default().fg(Color::Cyan)),
                Span::raw("Next file"),
            ]),
            Line::from(vec![
                Span::styled("  Shift+Tab ", Style::default().fg(Color::Cyan)),
                Span::raw("Previous file"),
            ]),
            Line::from(""),
        ]
    }

    /// Create scroll help section
    fn create_scroll_help() -> Vec<Line<'static>> {
        vec![
            Line::from(vec![Span::styled(
                "Scroll Content:",
                Style::default().add_modifier(Modifier::UNDERLINED),
            )]),
            Line::from(vec![
                Span::styled("  Ctrl+F    ", Style::default().fg(Color::Cyan)),
                Span::raw("Scroll down full page"),
            ]),
            Line::from(vec![
                Span::styled("  Ctrl+B    ", Style::default().fg(Color::Cyan)),
                Span::raw("Scroll up full page"),
            ]),
            Line::from(vec![
                Span::styled("  Ctrl+D/d  ", Style::default().fg(Color::Cyan)),
                Span::raw("Scroll down half page"),
            ]),
            Line::from(vec![
                Span::styled("  Ctrl+U/u  ", Style::default().fg(Color::Cyan)),
                Span::raw("Scroll up half page"),
            ]),
            Line::from(vec![
                Span::styled("  PageDown  ", Style::default().fg(Color::Cyan)),
                Span::raw("Scroll down full page"),
            ]),
            Line::from(vec![
                Span::styled("  PageUp    ", Style::default().fg(Color::Cyan)),
                Span::raw("Scroll up full page"),
            ]),
            Line::from(vec![
                Span::styled("  Home      ", Style::default().fg(Color::Cyan)),
                Span::raw("Go to top of file"),
            ]),
            Line::from(vec![
                Span::styled("  End       ", Style::default().fg(Color::Cyan)),
                Span::raw("Go to bottom of file"),
            ]),
            Line::from(""),
        ]
    }

    /// Create hunk navigation help section
    fn create_hunk_help() -> Vec<Line<'static>> {
        vec![
            Line::from(vec![Span::styled(
                "Hunks:",
                Style::default().add_modifier(Modifier::UNDERLINED),
            )]),
            Line::from(vec![
                Span::styled("  n         ", Style::default().fg(Color::Cyan)),
                Span::raw("Next hunk"),
            ]),
            Line::from(vec![
                Span::styled("  N         ", Style::default().fg(Color::Cyan)),
                Span::raw("Previous hunk"),
            ]),
            Line::from(""),
        ]
    }

    /// Create other commands help section
    fn create_other_help() -> Vec<Line<'static>> {
        vec![
            Line::from(vec![Span::styled(
                "Other:",
                Style::default().add_modifier(Modifier::UNDERLINED),
            )]),
            Line::from(vec![
                Span::styled("  ?         ", Style::default().fg(Color::Cyan)),
                Span::raw("Toggle help"),
            ]),
            Line::from(vec![
                Span::styled("  q/Esc     ", Style::default().fg(Color::Cyan)),
                Span::raw("Quit"),
            ]),
            Line::from(vec![
                Span::styled("  Ctrl+C    ", Style::default().fg(Color::Cyan)),
                Span::raw("Force quit"),
            ]),
        ]
    }

    /// Render help screen
    fn render_help(frame: &mut Frame) {
        let mut help_text = Vec::new();
        help_text.extend(Self::create_help_header());
        help_text.extend(Self::create_file_navigation_help());
        help_text.extend(Self::create_scroll_help());
        help_text.extend(Self::create_hunk_help());
        help_text.extend(Self::create_other_help());

        let paragraph = Paragraph::new(help_text)
            .block(
                Block::default()
                    .title(" Help (Press ? to close) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: false });

        let area = centered_rect(60, 80, frame.area());
        frame.render_widget(ratatui::widgets::Clear, area);
        frame.render_widget(paragraph, area);
    }

    // Navigation methods
    fn page_down(&mut self) {
        // Half page scroll (vim Ctrl+D)
        if let Some(file) = self.files.get(self.selected_file) {
            let max_scroll = file.total_lines().saturating_sub(1);
            self.diff_scroll = (self.diff_scroll + 10).min(max_scroll);
        }
    }

    fn page_up(&mut self) {
        // Half page scroll (vim Ctrl+U)
        self.diff_scroll = self.diff_scroll.saturating_sub(10);
    }

    fn page_down_full(&mut self) {
        // Full page scroll (vim Ctrl+F)
        if let Some(file) = self.files.get(self.selected_file) {
            let max_scroll = file.total_lines().saturating_sub(1);
            self.diff_scroll = (self.diff_scroll + 20).min(max_scroll);
        }
    }

    fn page_up_full(&mut self) {
        // Full page scroll (vim Ctrl+B)
        self.diff_scroll = self.diff_scroll.saturating_sub(20);
    }

    fn scroll_to_top(&mut self) {
        self.diff_scroll = 0;
    }

    fn scroll_to_bottom(&mut self) {
        if let Some(file) = self.files.get(self.selected_file) {
            let max_scroll = file.total_lines().saturating_sub(1);
            self.diff_scroll = max_scroll;
        }
    }

    fn next_hunk(&mut self) {
        if let Some(file) = self.files.get(self.selected_file) {
            let mut current_line = 0;
            for hunk in &file.hunks {
                if current_line > self.diff_scroll {
                    self.diff_scroll = current_line;
                    return;
                }
                current_line += hunk.lines.len();
            }
        }
    }

    fn prev_hunk(&mut self) {
        if let Some(file) = self.files.get(self.selected_file) {
            let mut prev_hunk_start = 0;
            let mut current_line = 0;

            for hunk in &file.hunks {
                if current_line >= self.diff_scroll {
                    self.diff_scroll = prev_hunk_start;
                    return;
                }
                prev_hunk_start = current_line;
                current_line += hunk.lines.len();
            }
        }
    }

    fn next_file(&mut self) {
        if !self.files.is_empty() {
            // Cycle to first file if at the end
            if self.selected_file < self.files.len() - 1 {
                self.selected_file += 1;
            } else {
                self.selected_file = 0;
            }
            self.file_list_state.select(Some(self.selected_file));
            self.diff_scroll = 0;
        }
    }

    fn prev_file(&mut self) {
        if !self.files.is_empty() {
            // Cycle to last file if at the beginning
            if self.selected_file > 0 {
                self.selected_file -= 1;
            } else {
                self.selected_file = self.files.len() - 1;
            }
            self.file_list_state.select(Some(self.selected_file));
            self.diff_scroll = 0;
        }
    }
}

/// Helper function to create a centered rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    // Tests for FileStatus

    #[test]
    fn test_file_status_equality() {
        assert_eq!(FileStatus::Added, FileStatus::Added);
        assert_eq!(FileStatus::Modified, FileStatus::Modified);
        assert_eq!(FileStatus::Deleted, FileStatus::Deleted);
        assert_ne!(FileStatus::Added, FileStatus::Modified);
    }

    #[test]
    fn test_file_status_clone() {
        let status = FileStatus::Added;
        let cloned = status;
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_file_status_copy() {
        let status = FileStatus::Modified;
        let copied = status;
        // After copy, original should still be usable
        assert_eq!(status, FileStatus::Modified);
        assert_eq!(copied, FileStatus::Modified);
    }

    // Tests for DiffLine

    #[test]
    fn test_diff_line_context() {
        let line = DiffLine::Context {
            line_num: Some(5),
            content: "unchanged line".to_string(),
        };

        match line {
            DiffLine::Context { line_num, content } => {
                assert_eq!(line_num, Some(5));
                assert_eq!(content, "unchanged line");
            }
            _ => panic!("Expected Context variant"),
        }
    }

    #[test]
    fn test_diff_line_add() {
        let line = DiffLine::Add {
            line_num: Some(10),
            content: "new line".to_string(),
        };

        match line {
            DiffLine::Add { line_num, content } => {
                assert_eq!(line_num, Some(10));
                assert_eq!(content, "new line");
            }
            _ => panic!("Expected Add variant"),
        }
    }

    #[test]
    fn test_diff_line_remove() {
        let line = DiffLine::Remove {
            line_num: Some(7),
            content: "deleted line".to_string(),
        };

        match line {
            DiffLine::Remove { line_num, content } => {
                assert_eq!(line_num, Some(7));
                assert_eq!(content, "deleted line");
            }
            _ => panic!("Expected Remove variant"),
        }
    }

    #[test]
    fn test_diff_line_header() {
        let line = DiffLine::Header {
            old_range: (1, 5),
            new_range: (1, 7),
        };

        match line {
            DiffLine::Header {
                old_range,
                new_range,
            } => {
                assert_eq!(old_range, (1, 5));
                assert_eq!(new_range, (1, 7));
            }
            _ => panic!("Expected Header variant"),
        }
    }

    #[test]
    fn test_diff_line_clone() {
        let line = DiffLine::Add {
            line_num: Some(1),
            content: "test".to_string(),
        };
        let cloned = line.clone();

        match (line, cloned) {
            (
                DiffLine::Add {
                    line_num: ln1,
                    content: c1,
                },
                DiffLine::Add {
                    line_num: ln2,
                    content: c2,
                },
            ) => {
                assert_eq!(ln1, ln2);
                assert_eq!(c1, c2);
            }
            _ => panic!("Clone mismatch"),
        }
    }

    // Tests for Hunk

    #[test]
    fn test_hunk_creation() {
        let hunk = Hunk {
            old_range: (10, 5),
            new_range: (10, 6),
            lines: vec![
                DiffLine::Header {
                    old_range: (10, 5),
                    new_range: (10, 6),
                },
                DiffLine::Context {
                    line_num: Some(10),
                    content: "line1".to_string(),
                },
            ],
        };

        assert_eq!(hunk.old_range, (10, 5));
        assert_eq!(hunk.new_range, (10, 6));
        assert_eq!(hunk.lines.len(), 2);
    }

    #[test]
    fn test_hunk_clone() {
        let hunk = Hunk {
            old_range: (1, 1),
            new_range: (1, 1),
            lines: vec![],
        };

        let cloned = hunk.clone();
        assert_eq!(cloned.old_range, (1, 1));
        assert_eq!(cloned.new_range, (1, 1));
    }

    // Tests for FileDiff

    #[test]
    fn test_file_diff_new_no_changes() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nline2\nline3\n";

        let diff = FileDiff::new(
            "test.txt".to_string(),
            old.to_string(),
            new.to_string(),
            FileStatus::Modified,
        );

        assert_eq!(diff.path, "test.txt");
        assert_eq!(diff.status, FileStatus::Modified);
        assert_eq!(diff.hunks.len(), 0); // No changes = no hunks
        assert_eq!(diff.old_content, old);
        assert_eq!(diff.new_content, new);
    }

    #[test]
    fn test_file_diff_new_with_changes() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nmodified\nline3\n";

        let diff = FileDiff::new(
            "test.txt".to_string(),
            old.to_string(),
            new.to_string(),
            FileStatus::Modified,
        );

        assert_eq!(diff.path, "test.txt");
        assert_eq!(diff.status, FileStatus::Modified);
        assert!(!diff.hunks.is_empty()); // Should have at least one hunk
    }

    #[test]
    fn test_file_diff_total_lines_empty() {
        let diff = FileDiff::new(
            "test.txt".to_string(),
            "same\n".to_string(),
            "same\n".to_string(),
            FileStatus::Modified,
        );

        assert_eq!(diff.total_lines(), 0); // No hunks = 0 lines
    }

    #[test]
    fn test_file_diff_total_lines_with_hunks() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nmodified\nline3\n";

        let diff = FileDiff::new(
            "test.txt".to_string(),
            old.to_string(),
            new.to_string(),
            FileStatus::Modified,
        );

        // Total lines = sum of all hunk lines
        let expected_lines: usize = diff.hunks.iter().map(|h| h.lines.len()).sum();
        assert_eq!(diff.total_lines(), expected_lines);
    }

    #[test]
    fn test_file_diff_added_status() {
        let diff = FileDiff::new(
            "new.txt".to_string(),
            String::new(),
            "new content\n".to_string(),
            FileStatus::Added,
        );

        assert_eq!(diff.status, FileStatus::Added);
    }

    #[test]
    fn test_file_diff_deleted_status() {
        let diff = FileDiff::new(
            "old.txt".to_string(),
            "old content\n".to_string(),
            String::new(),
            FileStatus::Deleted,
        );

        assert_eq!(diff.status, FileStatus::Deleted);
    }

    #[test]
    fn test_file_diff_clone() {
        let diff = FileDiff::new(
            "test.txt".to_string(),
            "old\n".to_string(),
            "new\n".to_string(),
            FileStatus::Modified,
        );

        let cloned = diff.clone();
        assert_eq!(cloned.path, "test.txt");
        assert_eq!(cloned.status, FileStatus::Modified);
        assert_eq!(cloned.old_content, "old\n");
        assert_eq!(cloned.new_content, "new\n");
    }

    // Tests for InteractiveDiffViewer

    fn create_test_files() -> Vec<FileDiff> {
        vec![
            FileDiff::new(
                "file1.txt".to_string(),
                "old1\n".to_string(),
                "new1\n".to_string(),
                FileStatus::Modified,
            ),
            FileDiff::new(
                "file2.txt".to_string(),
                String::new(),
                "added\n".to_string(),
                FileStatus::Added,
            ),
            FileDiff::new(
                "file3.txt".to_string(),
                "deleted\n".to_string(),
                String::new(),
                FileStatus::Deleted,
            ),
        ]
    }

    #[test]
    fn test_viewer_new_empty() {
        let viewer = InteractiveDiffViewer::new(vec![]);

        assert_eq!(viewer.files.len(), 0);
        assert_eq!(viewer.selected_file, 0);
        assert_eq!(viewer.diff_scroll, 0);
        assert!(!viewer.show_help);
        assert_eq!(viewer.file_list_state.selected(), None);
    }

    #[test]
    fn test_viewer_new_with_files() {
        let files = create_test_files();
        let viewer = InteractiveDiffViewer::new(files);

        assert_eq!(viewer.files.len(), 3);
        assert_eq!(viewer.selected_file, 0);
        assert_eq!(viewer.diff_scroll, 0);
        assert!(!viewer.show_help);
        assert_eq!(viewer.file_list_state.selected(), Some(0));
    }

    #[test]
    fn test_viewer_next_file() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        assert_eq!(viewer.selected_file, 0);

        viewer.next_file();
        assert_eq!(viewer.selected_file, 1);
        assert_eq!(viewer.file_list_state.selected(), Some(1));
        assert_eq!(viewer.diff_scroll, 0); // Should reset scroll

        viewer.next_file();
        assert_eq!(viewer.selected_file, 2);
    }

    #[test]
    fn test_viewer_next_file_wraps_around() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        // Go to last file
        viewer.next_file();
        viewer.next_file();
        assert_eq!(viewer.selected_file, 2);

        // Next should wrap to first
        viewer.next_file();
        assert_eq!(viewer.selected_file, 0);
        assert_eq!(viewer.file_list_state.selected(), Some(0));
    }

    #[test]
    fn test_viewer_prev_file() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        // Move to second file
        viewer.next_file();
        assert_eq!(viewer.selected_file, 1);

        // Previous should go back to first
        viewer.prev_file();
        assert_eq!(viewer.selected_file, 0);
        assert_eq!(viewer.file_list_state.selected(), Some(0));
        assert_eq!(viewer.diff_scroll, 0); // Should reset scroll
    }

    #[test]
    fn test_viewer_prev_file_wraps_around() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        assert_eq!(viewer.selected_file, 0);

        // Previous from first should wrap to last
        viewer.prev_file();
        assert_eq!(viewer.selected_file, 2);
        assert_eq!(viewer.file_list_state.selected(), Some(2));
    }

    #[test]
    fn test_viewer_scroll_to_top() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        // Set scroll to non-zero
        viewer.diff_scroll = 50;

        viewer.scroll_to_top();
        assert_eq!(viewer.diff_scroll, 0);
    }

    #[test]
    fn test_viewer_scroll_to_bottom() {
        let files = vec![FileDiff::new(
            "file.txt".to_string(),
            "line1\nline2\nline3\n".to_string(),
            "line1\nmodified\nline3\nline4\n".to_string(),
            FileStatus::Modified,
        )];
        let mut viewer = InteractiveDiffViewer::new(files);

        viewer.scroll_to_bottom();

        let expected_max = viewer.files[0].total_lines().saturating_sub(1);
        assert_eq!(viewer.diff_scroll, expected_max);
    }

    #[test]
    fn test_viewer_page_down() {
        // Create a file with lots of lines to ensure scrolling works
        let old_lines: Vec<String> = (1..=100).map(|i| format!("line{i}\n")).collect();
        let new_lines: Vec<String> = (1..=100).map(|i| format!("modified{i}\n")).collect();

        let files = vec![FileDiff::new(
            "large.txt".to_string(),
            old_lines.join(""),
            new_lines.join(""),
            FileStatus::Modified,
        )];
        let mut viewer = InteractiveDiffViewer::new(files);

        let initial_scroll = viewer.diff_scroll;
        viewer.page_down();

        // Should scroll down by 10 lines (half page)
        assert_eq!(viewer.diff_scroll, initial_scroll + 10);
    }

    #[test]
    fn test_viewer_page_down_respects_max() {
        let files = vec![FileDiff::new(
            "small.txt".to_string(),
            "a\n".to_string(),
            "b\n".to_string(),
            FileStatus::Modified,
        )];
        let mut viewer = InteractiveDiffViewer::new(files);

        // Page down multiple times
        for _ in 0..10 {
            viewer.page_down();
        }

        // Should not exceed max scroll
        let max_scroll = viewer.files[0].total_lines().saturating_sub(1);
        assert!(viewer.diff_scroll <= max_scroll);
    }

    #[test]
    fn test_viewer_page_up() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        // Scroll down first
        viewer.diff_scroll = 50;

        viewer.page_up();

        // Should scroll up by 10 lines (half page)
        assert_eq!(viewer.diff_scroll, 40);
    }

    #[test]
    fn test_viewer_page_up_saturates_at_zero() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        viewer.diff_scroll = 5;
        viewer.page_up(); // 5 - 10 = saturate to 0

        assert_eq!(viewer.diff_scroll, 0);

        viewer.page_up(); // Already at 0
        assert_eq!(viewer.diff_scroll, 0);
    }

    #[test]
    fn test_viewer_page_down_full() {
        // Create a file with lots of lines to ensure scrolling works
        let old_lines: Vec<String> = (1..=100).map(|i| format!("line{i}\n")).collect();
        let new_lines: Vec<String> = (1..=100).map(|i| format!("modified{i}\n")).collect();

        let files = vec![FileDiff::new(
            "large.txt".to_string(),
            old_lines.join(""),
            new_lines.join(""),
            FileStatus::Modified,
        )];
        let mut viewer = InteractiveDiffViewer::new(files);

        let initial_scroll = viewer.diff_scroll;
        viewer.page_down_full();

        // Should scroll down by 20 lines (full page)
        assert_eq!(viewer.diff_scroll, initial_scroll + 20);
    }

    #[test]
    fn test_viewer_page_up_full() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        viewer.diff_scroll = 50;
        viewer.page_up_full();

        // Should scroll up by 20 lines (full page)
        assert_eq!(viewer.diff_scroll, 30);
    }

    #[test]
    fn test_viewer_page_up_full_saturates_at_zero() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        viewer.diff_scroll = 10;
        viewer.page_up_full(); // 10 - 20 = saturate to 0

        assert_eq!(viewer.diff_scroll, 0);
    }

    #[test]
    fn test_viewer_next_file_resets_scroll() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        // Set scroll on first file
        viewer.diff_scroll = 50;

        // Move to next file
        viewer.next_file();

        // Scroll should reset
        assert_eq!(viewer.diff_scroll, 0);
    }

    #[test]
    fn test_viewer_prev_file_resets_scroll() {
        let files = create_test_files();
        let mut viewer = InteractiveDiffViewer::new(files);

        // Move to second file and set scroll
        viewer.next_file();
        viewer.diff_scroll = 50;

        // Move back to previous file
        viewer.prev_file();

        // Scroll should reset
        assert_eq!(viewer.diff_scroll, 0);
    }

    #[test]
    fn test_viewer_next_file_empty_files() {
        let mut viewer = InteractiveDiffViewer::new(vec![]);

        // Should not panic
        viewer.next_file();
        assert_eq!(viewer.selected_file, 0);
    }

    #[test]
    fn test_viewer_prev_file_empty_files() {
        let mut viewer = InteractiveDiffViewer::new(vec![]);

        // Should not panic
        viewer.prev_file();
        assert_eq!(viewer.selected_file, 0);
    }

    // Tests for centered_rect helper

    #[test]
    fn test_centered_rect_50_50() {
        let area = Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 100,
        };

        let centered = centered_rect(50, 50, area);

        // Should be centered
        assert_eq!(centered.width, 50);
        assert_eq!(centered.height, 50);
    }

    #[test]
    fn test_centered_rect_80_60() {
        let area = Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 100,
        };

        let centered = centered_rect(80, 60, area);

        // Should be 80% width, 60% height
        assert_eq!(centered.width, 80);
        assert_eq!(centered.height, 60);
    }

    #[test]
    fn test_centered_rect_small_area() {
        let area = Rect {
            x: 0,
            y: 0,
            width: 20,
            height: 20,
        };

        let centered = centered_rect(50, 50, area);

        // Should scale to small area
        assert_eq!(centered.width, 10);
        assert_eq!(centered.height, 10);
    }
}
