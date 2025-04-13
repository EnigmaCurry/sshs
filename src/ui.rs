use anyhow::Result;
use crossterm::{
    cursor::{Hide, Show},
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use fuzzy_matcher::{skim::SkimMatcherV2, FuzzyMatcher};
#[allow(clippy::wildcard_imports)]
use ratatui::{prelude::*, widgets::*};
use std::collections::HashMap;
use std::{
    cell::RefCell,
    cmp::{max, min},
    env, io,
    rc::Rc,
};
use style::palette::tailwind;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;
use unicode_width::UnicodeWidthStr;

use crate::{searchable::Searchable, ssh};

// Separate help messages for left and right sides.
const LEFT_HELP_MSG: &str =
    "(Esc) quit | (↑/↓) navigate table | (Enter) start SSH session | (Tab) switch to edit";
const RIGHT_HELP_MSG: &str =
    "(Esc) quit | (↑/↓) move field | (Enter) toggle edit mode | (Tab) switch to table";

// Define focus state for the app.
#[derive(PartialEq)]
enum Focus {
    Table,
    Form,
}

#[derive(Clone)]
pub struct AppConfig {
    pub config_paths: Vec<String>,

    pub search_filter: Option<String>,
    pub sort_by_name: bool,
    pub show_proxy_command: bool,

    pub command_template: String,
    pub command_template_on_session_start: Option<String>,
    pub command_template_on_session_end: Option<String>,
    pub exit_after_ssh_session_ends: bool,
}

pub struct App {
    config: AppConfig,

    search: Input,

    table_state: TableState,
    hosts: Searchable<ssh::Host>,
    table_columns_constraints: Vec<Constraint>,

    palette: tailwind::Palette,

    // New fields for editing mode.
    focus: Focus,
    /// Holds a clone of the host currently being edited.
    edited_host: Option<ssh::Host>,
    /// List of editable fields as (Field Name, Input widget).
    editing_fields: Vec<(String, Input)>,
    /// Which field is currently selected for editing.
    edit_field_index: usize,
    /// Remember the last table index we loaded into the form.
    last_selected_index: Option<usize>,
    /// Tracks whether the currently selected field is in active edit mode.
    in_field_edit: bool,
}

#[derive(PartialEq)]
enum AppKeyAction {
    Ok,
    Stop,
    Continue,
}

impl App {
    /// # Errors
    ///
    /// Will return `Err` if the SSH configuration file cannot be parsed.
    pub fn new(config: &AppConfig) -> Result<App> {
        let mut hosts = Vec::new();

        for path in &config.config_paths {
            let parsed_hosts = match ssh::parse_config(path) {
                Ok(hosts) => hosts,
                Err(err) => {
                    if path == "/etc/ssh/ssh_config" {
                        if let ssh::ParseConfigError::Io(io_err) = &err {
                            // Ignore missing system-wide SSH configuration file
                            if io_err.kind() == std::io::ErrorKind::NotFound {
                                continue;
                            }
                        }
                    }
                    anyhow::bail!("Failed to parse SSH configuration file: {err:?}");
                }
            };
            hosts.extend(parsed_hosts);
        }

        // Optionally sort hosts by name.
        if config.sort_by_name {
            hosts.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        }
        // Filter out hosts with an empty name or a name equal to ".host"
        hosts.retain(|h| !h.name.trim().is_empty() && h.name != ".host");

        let search_input = config.search_filter.clone().unwrap_or_default();
        let matcher = SkimMatcherV2::default();

        let app = App {
            config: config.clone(),

            search: search_input.clone().into(),

            table_state: TableState::default().with_selected(0),
            table_columns_constraints: Vec::new(),
            palette: tailwind::BLUE,

            hosts: Searchable::new(
                hosts,
                &search_input,
                move |host: &&ssh::Host, search_value: &str| -> bool {
                    search_value.is_empty()
                        || matcher.fuzzy_match(&host.name, search_value).is_some()
                        || matcher.fuzzy_match(&host.hostname, search_value).is_some()
                        || matcher.fuzzy_match(&host.aliases, search_value).is_some()
                },
            ),
            // Start in table (preview) mode.
            focus: Focus::Table,
            edited_host: None,
            editing_fields: Vec::new(),
            edit_field_index: 0,
            last_selected_index: None,
            in_field_edit: false,
        };

        let mut app = app;
        app.calculate_table_columns_constraints();

        Ok(app)
    }

    fn load_editing_fields(&mut self) {
        if let Some(selected) = self.table_state.selected() {
            if selected < self.hosts.len() {
                // Only reload if selection changed.
                if let Some(last) = self.last_selected_index {
                    if last == selected {
                        return;
                    }
                }
                self.last_selected_index = Some(selected);
                let host = &self.hosts[selected];
                self.edited_host = Some(host.clone());
                self.editing_fields.clear();
                self.in_field_edit = false; // start in selection mode

                if let Some(ref host) = self.edited_host {
                    // Use the host's iter_fields() method to get all (field, value) pairs.
                    let mut fields = host.iter_fields();
                    // Optionally sort the fields alphabetically by name:
                    fields.sort_by(|(a, _), (b, _)| a.cmp(b));
                    // For each field, initialize an Input widget with the current value.
                    for (key, value) in fields {
                        let input: Input = value.into();
                        self.editing_fields.push((key, input));
                    }
                }
                self.edit_field_index = 0;
            }
        }
    }

    fn commit_field(&mut self) {
        if let Some(ref mut edited_host) = self.edited_host {
            // Convert the current host into a JSON value (must derive Serialize)
            let mut host_value =
                serde_json::to_value(&mut *edited_host).expect("Failed to serialize host");
            // We need to work with the Object (map) representation
            if let serde_json::Value::Object(ref mut map) = host_value {
                for (field, input) in &self.editing_fields {
                    // If the new value is empty then store null, otherwise update with the new string.
                    // You can adjust this behavior if you prefer an empty string instead of null.
                    let new_val = if input.value().is_empty() {
                        serde_json::Value::Null
                    } else {
                        serde_json::Value::String(input.value().to_string())
                    };
                    // Insert or update the field in the map.
                    map.insert(field.clone(), new_val);
                }
            }
            // Convert the updated JSON value back into a Host.
            let updated_host: ssh::Host =
                serde_json::from_value(host_value).expect("Failed to deserialize host");
            *edited_host = updated_host;

            // Now save the updated host to disk.
            let home = env::var("HOME").expect("HOME not set");
            let config_path = format!("{}/.ssh/config", home);
            match ssh::save_config(edited_host, &config_path) {
                Ok(()) => {
                    if let Some(selected) = self.table_state.selected() {
                        if let Some(host) = self.hosts.get_mut(selected) {
                            *host = edited_host.clone();
                            self.hosts.search(self.search.value());
                        }
                    }
                }
                Err(e) => {
                    println!("Error saving host: {:?}", e);
                }
            }
        }
    }

    /// # Errors
    ///
    /// Will return `Err` if the terminal cannot be configured.
    pub fn start(&mut self) -> Result<()> {
        let stdout = io::stdout().lock();
        let backend = CrosstermBackend::new(stdout);
        let terminal = Rc::new(RefCell::new(Terminal::new(backend)?));

        setup_terminal(&terminal)?;

        // create app and run it
        let res = self.run(&terminal);

        restore_terminal(&terminal)?;

        if let Err(err) = res {
            println!("{err:?}");
        }

        Ok(())
    }

    fn run<B>(&mut self, terminal: &Rc<RefCell<Terminal<B>>>) -> Result<()>
    where
        B: Backend + io::Write,
    {
        loop {
            terminal.borrow_mut().draw(|f| ui(f, self))?;

            let ev = event::read()?;
            if let Event::Key(key) = ev {
                // Global ESC: exit regardless of focus.
                if key.code == KeyCode::Esc {
                    break;
                }
                let action = self.on_key_press(terminal, key)?;
                match action {
                    AppKeyAction::Ok => {}
                    AppKeyAction::Stop => break,
                    AppKeyAction::Continue => {}
                } // When in table mode, update the search and table.
                if self.focus == Focus::Table {
                    self.search.handle_event(&Event::Key(key));
                    self.hosts.search(self.search.value());

                    let selected = self.table_state.selected().unwrap_or(0);
                    if selected >= self.hosts.len() {
                        self.table_state.select(Some(match self.hosts.len() {
                            0 => 0,
                            _ => self.hosts.len() - 1,
                        }));
                    }
                }
            }
        }

        Ok(())
    }

    fn on_key_press<B>(
        &mut self,
        terminal: &Rc<RefCell<Terminal<B>>>,
        key: KeyEvent,
    ) -> Result<AppKeyAction>
    where
        B: Backend + io::Write,
    {
        use KeyCode::*;
        match self.focus {
            Focus::Table => {
                if key.code == Tab {
                    self.load_editing_fields();
                    self.focus = Focus::Form;
                    return Ok(AppKeyAction::Ok);
                }
                let is_ctrl_pressed = key.modifiers.contains(KeyModifiers::CONTROL);
                if is_ctrl_pressed {
                    let action = self.on_key_press_ctrl(key);
                    if action != AppKeyAction::Continue {
                        return Ok(action);
                    }
                }
                match key.code {
                    // ESC is globally handled above.
                    Down => self.next(),
                    Up => self.previous(),
                    Home => self.table_state.select(Some(0)),
                    End => self.table_state.select(Some(self.hosts.len() - 1)),
                    PageDown => {
                        let i = self.table_state.selected().unwrap_or(0);
                        let target = min(i.saturating_add(21), self.hosts.len() - 1);
                        self.table_state.select(Some(target));
                    }
                    PageUp => {
                        let i = self.table_state.selected().unwrap_or(0);
                        let target = max(i.saturating_sub(21), 0);
                        self.table_state.select(Some(target));
                    }
                    Enter => {
                        // Launch SSH command as before.
                        let selected = self.table_state.selected().unwrap_or(0);
                        if selected >= self.hosts.len() {
                            return Ok(AppKeyAction::Ok);
                        }
                        let host: &ssh::Host = &self.hosts[selected];
                        restore_terminal(terminal).expect("Failed to restore terminal");
                        if let Some(template) = &self.config.command_template_on_session_start {
                            host.run_command_template(template)?;
                        }
                        host.run_command_template(&self.config.command_template)?;
                        if let Some(template) = &self.config.command_template_on_session_end {
                            host.run_command_template(template)?;
                        }
                        setup_terminal(terminal).expect("Failed to setup terminal");
                        if self.config.exit_after_ssh_session_ends {
                            return Ok(AppKeyAction::Stop);
                        }
                    }
                    _ => return Ok(AppKeyAction::Continue),
                }
                Ok(AppKeyAction::Ok)
            }
            Focus::Form => {
                // Global ESC check already happens.
                match key.code {
                    Tab => {
                        // Switch back to table mode.
                        if self.in_field_edit {
                            self.commit_field();
                            self.in_field_edit = false;
                        }
                        self.focus = Focus::Table;
                    }
                    Up => {
                        if self.in_field_edit {
                            self.editing_fields[self.edit_field_index]
                                .1
                                .handle_event(&Event::Key(key));
                        } else {
                            if self.edit_field_index == 0 {
                                self.edit_field_index = self.editing_fields.len() - 1;
                            } else {
                                self.edit_field_index -= 1;
                            }
                        }
                    }
                    Down => {
                        if self.in_field_edit {
                            self.editing_fields[self.edit_field_index]
                                .1
                                .handle_event(&Event::Key(key));
                        } else {
                            self.edit_field_index =
                                (self.edit_field_index + 1) % self.editing_fields.len();
                        }
                    }
                    Enter => {
                        if self.in_field_edit {
                            // Exiting field edit mode commits the change.
                            self.commit_field();
                            self.in_field_edit = false;
                        } else {
                            // Enter editing mode for the current field.
                            self.in_field_edit = true;
                        }
                    }
                    _ => {
                        if self.in_field_edit {
                            self.editing_fields[self.edit_field_index]
                                .1
                                .handle_event(&Event::Key(key));
                        }
                    }
                }
                Ok(AppKeyAction::Ok)
            }
        }
    }

    fn on_key_press_ctrl(&mut self, key: KeyEvent) -> AppKeyAction {
        use KeyCode::*;
        match key.code {
            Char('c') => AppKeyAction::Stop,
            Char('j' | 'n') => {
                self.next();
                AppKeyAction::Ok
            }
            Char('k' | 'p') => {
                self.previous();
                AppKeyAction::Ok
            }
            _ => AppKeyAction::Continue,
        }
    }

    fn next(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if self.hosts.is_empty() || i >= self.hosts.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if self.hosts.is_empty() {
                    0
                } else if i == 0 {
                    self.hosts.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn calculate_table_columns_constraints(&mut self) {
        let mut lengths = Vec::new();
        let name_len = self
            .hosts
            .iter()
            .map(|d| d.name.as_str())
            .map(UnicodeWidthStr::width)
            .max()
            .unwrap_or(0);
        lengths.push(name_len);
        let aliases_len = self
            .hosts
            .non_filtered_iter()
            .map(|d| d.aliases.as_str())
            .map(UnicodeWidthStr::width)
            .max()
            .unwrap_or(0);
        lengths.push(aliases_len);
        let user_len = self
            .hosts
            .non_filtered_iter()
            .map(|d| match &d.user {
                Some(user) => user.as_str(),
                None => "",
            })
            .map(UnicodeWidthStr::width)
            .max()
            .unwrap_or(0);
        lengths.push(user_len);
        let destination_len = self
            .hosts
            .non_filtered_iter()
            .map(|d| d.hostname.as_str())
            .map(UnicodeWidthStr::width)
            .max()
            .unwrap_or(0);
        lengths.push(destination_len);
        let port_len = self
            .hosts
            .non_filtered_iter()
            .map(|d| match &d.port {
                Some(port) => port.as_str(),
                None => "",
            })
            .map(UnicodeWidthStr::width)
            .max()
            .unwrap_or(0);
        lengths.push(port_len);
        if self.config.show_proxy_command {
            let proxy_len = self
                .hosts
                .non_filtered_iter()
                .map(|d| match &d.proxy_command {
                    Some(proxy) => proxy.as_str(),
                    None => "",
                })
                .map(UnicodeWidthStr::width)
                .max()
                .unwrap_or(0);
            lengths.push(proxy_len);
        }
        let mut new_constraints = vec![Constraint::Length(
            u16::try_from(lengths[0]).unwrap_or_default() + 1,
        )];
        new_constraints.extend(
            lengths
                .iter()
                .skip(1)
                .map(|len| Constraint::Min(u16::try_from(*len).unwrap_or_default() + 1)),
        );
        self.table_columns_constraints = new_constraints;
    }
}

fn setup_terminal<B>(terminal: &Rc<RefCell<Terminal<B>>>) -> Result<()>
where
    B: Backend + io::Write,
{
    let mut terminal = terminal.borrow_mut();
    enable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        Hide,
        EnterAlternateScreen,
        EnableMouseCapture
    )?;
    Ok(())
}

fn restore_terminal<B>(terminal: &Rc<RefCell<Terminal<B>>>) -> Result<()>
where
    B: Backend + io::Write,
{
    let mut terminal = terminal.borrow_mut();
    terminal.clear()?;
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        Show,
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    Ok(())
}

fn ui(f: &mut Frame, app: &mut App) {
    // Split the screen horizontally into left and right halves.
    let horizontal_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(f.size());

    // Left side layout: searchbar, table and a left footer.
    let left_rects = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(3),
    ])
    .split(horizontal_chunks[0]);

    render_searchbar(f, app, left_rects[0]);
    render_table(f, app, left_rects[1]);
    render_left_footer(f, app, left_rects[2]);

    // Right side layout: form (edit fields) and a right footer.
    let right_rects =
        Layout::vertical([Constraint::Min(7), Constraint::Length(3)]).split(horizontal_chunks[1]);

    // In table mode, refresh the editing form on every draw.
    if app.focus == Focus::Table {
        app.load_editing_fields();
    }

    // Build list items from editable fields.
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let form_items: Vec<ListItem> = app
        .editing_fields
        .iter()
        .enumerate()
        .map(|(i, (field, input))| {
            // When not in active edit mode, highlight the selected row.
            let style = if (app.focus == Focus::Form)
                && (!app.in_field_edit)
                && (i == app.edit_field_index)
            {
                selected_style
            } else {
                Style::default()
            };
            let content = format!("{}: {}", field, input.value());
            ListItem::new(content).style(style)
        })
        .collect();

    let form_list = List::new(form_items).block(
        Block::default()
            .title("Configuration (Edit)")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded),
    );

    f.render_widget(form_list, right_rects[0]);
    render_right_footer(f, app, right_rects[1]);

    // Position the cursor when in form editing mode.
    if app.focus == Focus::Form && app.in_field_edit {
        // Use the inner area of the form block.
        let form_area = right_rects[0];
        let inner_x = form_area.x + 1;
        let inner_y = form_area.y + 1;
        let (label, input) = &app.editing_fields[app.edit_field_index];
        let label_text = format!("{}: ", label);
        let cursor_offset = input.cursor();
        let x = inner_x + label_text.len() as u16 + cursor_offset as u16;
        let y = inner_y + app.edit_field_index as u16;
        f.set_cursor(x, y);
    }

    // Position the cursor for the searchbar when in table mode.
    if app.focus == Focus::Table {
        f.set_cursor(
            left_rects[0].x + u16::try_from(app.search.cursor()).unwrap_or_default() + 4,
            left_rects[0].y + 1,
        );
    }
}

fn render_searchbar(f: &mut Frame, app: &App, area: Rect) {
    let info = Paragraph::new(app.search.value()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(app.palette.c400))
            .border_type(BorderType::Rounded)
            .padding(Padding::horizontal(3)),
    );
    f.render_widget(info, area);
}

fn render_table(f: &mut Frame, app: &mut App, area: Rect) {
    let header_style = Style::default().fg(tailwind::CYAN.c500);
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let mut header_names = vec!["Name", "Aliases", "User", "Destination", "Port"];
    if app.config.show_proxy_command {
        header_names.push("Proxy");
    }

    let header = header_names
        .iter()
        .copied()
        .map(Cell::from)
        .collect::<Row>()
        .style(header_style)
        .height(1);

    let rows = app.hosts.iter().map(|host| {
        let mut content = vec![
            host.name.clone(),
            host.aliases.clone(),
            host.user.clone().unwrap_or_default(),
            host.hostname.clone(),
            host.port.clone().unwrap_or_default(),
        ];
        if app.config.show_proxy_command {
            content.push(host.proxy_command.clone().unwrap_or_default());
        }
        content
            .iter()
            .map(|c| Cell::from(c.to_string()))
            .collect::<Row>()
    });

    let bar = " █ ";
    let table = Table::new(rows, app.table_columns_constraints.clone())
        .header(header)
        .highlight_style(selected_style)
        .highlight_symbol(Text::from(vec![
            "".into(),
            bar.into(),
            bar.into(),
            "".into(),
        ]))
        .highlight_spacing(HighlightSpacing::Always)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(app.palette.c400))
                .border_type(BorderType::Rounded),
        );

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_left_footer(f: &mut Frame, app: &App, area: Rect) {
    let left_help = Paragraph::new(LEFT_HELP_MSG).centered().block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(app.palette.c400))
            .border_type(BorderType::Rounded),
    );
    f.render_widget(left_help, area);
}

fn render_right_footer(f: &mut Frame, app: &App, area: Rect) {
    let right_help = Paragraph::new(RIGHT_HELP_MSG).centered().block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(app.palette.c400))
            .border_type(BorderType::Rounded),
    );
    f.render_widget(right_help, area);
}
