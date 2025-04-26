use crate::log::log_error;
use crate::ssh::ensure_user_ssh_config;
use crate::{searchable::Searchable, ssh};
use anyhow::Result;
use crossterm::{
    cursor::{Hide, Show},
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use fuzzy_matcher::{skim::SkimMatcherV2, FuzzyMatcher};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Clear;
#[allow(clippy::wildcard_imports)]
use ratatui::{prelude::*, widgets::*};
use std::collections::HashSet;
use std::{
    cell::RefCell,
    cmp::{max, min},
    io,
    rc::Rc,
};
use style::palette::tailwind;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;
use unicode_width::UnicodeWidthStr;

// Separate help messages for left and right sides.
const LEFT_HELP_MSG: &str =
    "(Esc) quit | (↑/↓) select host | (type) filter list of hosts | (Enter) start SSH session | (Tab) switch to configs";
const RIGHT_HELP_MSG: &str =
    "(Esc) quit | (↑/↓) select field | (Enter) toggle field edit mode | (a) add new field | (Tab) switch to hosts";

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
    add_field_modal: Option<AddFieldModal>,
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

    /// Stores the original name of the host being edited
    original_host_name: Option<String>,

    new_fields: Vec<String>,
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

        let search_input = config.search_filter.clone().unwrap_or_default();
        let matcher = SkimMatcherV2::default();

        let app = App {
            config: config.clone(),

            search: search_input.clone().into(),
            add_field_modal: None,
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
            original_host_name: None,
            new_fields: Vec::new(),
        };

        let mut app = app;
        app.calculate_table_columns_constraints();

        Ok(app)
    }

    fn load_editing_fields(&mut self) {
        if let Some(selected) = self.table_state.selected() {
            if selected < self.hosts.len() {
                self.last_selected_index = Some(selected);
                let host = self.hosts[selected].clone();
                self.original_host_name = Some(host.name.clone());
                self.edited_host = Some(host);
                self.in_field_edit = false;
                self.edit_field_index = 0;
                self.refresh_editing_fields();
            }
        }
    }

    fn commit_field(&mut self) {
        // Step 1: Extract all the data we need before any modifications
        let (edited_host_opt, current_field_name, original_name_opt, selected) = {
            // Get the edited host and clone it to avoid borrow issues
            let edited_host = match &self.edited_host {
                Some(host) => host.clone(),
                None => return,
            };

            // Store the current field name
            let current_field_name = if !self.editing_fields.is_empty()
                && self.edit_field_index < self.editing_fields.len()
            {
                Some(self.editing_fields[self.edit_field_index].0.clone())
            } else {
                None
            };

            // Get the original name
            let original_name = self.original_host_name.clone();

            // Get the selected index
            let selected = self.table_state.selected();

            (
                Some(edited_host),
                current_field_name,
                original_name,
                selected,
            )
        };

        // Get a mutable reference to our edited host
        let edited_host = match edited_host_opt {
            Some(host) => host,
            None => return,
        };

        // Step 2: Update the host with values from the form
        // We need to serialize and update the edited_host
        let mut host_value = match serde_json::to_value(&edited_host) {
            Ok(value) => value,
            Err(e) => {
                log_error(&format!("Failed to serialize host: {}", e));
                return;
            }
        };

        if let serde_json::Value::Object(ref mut map) = host_value {
            // Temp map to collect Vec fields before inserting into the real map
            let mut temp_vec_fields: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();

            for (field_name, input) in &self.editing_fields {
                let snake_case_field = to_snake_case(field_name);
                let value = input.value().to_string();

                if value.is_empty() {
                    // if it's one of the Vec<String> fields, use an empty array
                    if ssh::Host::vec_fields().contains(&snake_case_field.as_str()) {
                        map.insert(
                            snake_case_field.clone(),
                            serde_json::Value::Array(Vec::new()),
                        );
                    } else if snake_case_field == "aliases" {
                        map.insert(snake_case_field, serde_json::Value::String(String::new()));
                    } else {
                        map.insert(snake_case_field, serde_json::Value::Null);
                    }
                } else if ssh::Host::vec_fields().contains(&snake_case_field.as_str()) {
                    // Collect into temp Vec
                    temp_vec_fields
                        .entry(snake_case_field)
                        .or_default()
                        .push(value);
                } else {
                    // Normal string field: just set directly
                    map.insert(snake_case_field, serde_json::Value::String(value));
                }
            }

            // After processing all inputs, insert Vec fields into the map
            for (field, values) in temp_vec_fields {
                let array = values.into_iter().map(serde_json::Value::String).collect();
                map.insert(field, serde_json::Value::Array(array));
            }
        } else {
            return;
        }

        // Deserialize back to a Host struct
        log_error(&host_value.to_string());
        let updated_host = match serde_json::from_value::<ssh::Host>(host_value) {
            Ok(host) => host,
            Err(e) => {
                log_error(&format!("Failed to update host: {}", e));
                return;
            }
        };

        // Step 3: Check if name has changed
        let name_changed = match &original_name_opt {
            Some(original_name) => original_name != &updated_host.name,
            None => false,
        };

        // Step 4: Check if there are any actual changes by comparing with the original
        let has_changes = if let Some(idx) = selected {
            if idx < self.hosts.len() {
                let original_json = serde_json::to_value(&self.hosts[idx]).unwrap_or_default();
                let updated_json = serde_json::to_value(&updated_host).unwrap_or_default();
                original_json != updated_json
            } else {
                false
            }
        } else {
            false
        };

        // Only continue if there are changes to save
        if !has_changes && !name_changed {
            // Still update our edited host copy
            self.edited_host = Some(updated_host);

            // Stay on same field line
            if let Some(field_name) = current_field_name {
                if let Some(index) = self
                    .editing_fields
                    .iter()
                    .position(|(name, _)| *name == field_name)
                {
                    self.edit_field_index = index;
                }
            }
            return;
        }

        // Step 5: Save the changes
        let user_config = ensure_user_ssh_config();

        // Handle name changes first
        if name_changed {
            if let Some(original_name) = original_name_opt {
                // Remove the old host entry
                if let Err(e) = ssh::remove_host(&original_name, &user_config) {
                    log_error(&format!("Failed to remove old host entry: {}", e));
                }

                // Update our tracking of the original name
                self.original_host_name = Some(updated_host.name.clone());
            }
        }

        // Save the config
        if let Err(e) = ssh::save_config(&updated_host, &user_config) {
            log_error(&format!("Failed to save config: {}", e));
        } else {
            self.new_fields.clear();
        }

        // Step 6: Update in-memory host list
        if let Some(idx) = selected {
            if idx < self.hosts.len() {
                // Update the entry
                if let Some(host_entry) = self.hosts.get_mut(idx) {
                    *host_entry = updated_host.clone();
                } else {
                    log_error(&format!("Failed to update host at index {}", idx));
                }

                // Update our edited_host with the changes
                self.edited_host = Some(updated_host);

                // Reload the search to update filtered views
                self.hosts.search(self.search.value());

                // Reset last_selected_index to ensure form reloading
                self.last_selected_index = None;

                // Reload form fields
                self.load_editing_fields();
            }
        }

        // Step 7: Restore cursor position
        if let Some(field_name) = current_field_name {
            if let Some(index) = self
                .editing_fields
                .iter()
                .position(|(name, _)| *name == field_name)
            {
                self.edit_field_index = index;
            }
        }
    }

    /// Rebuild the list of editing fields from the current `edited_host`.
    /// This automatically excludes any fields that are now blank or set to null.
    fn refresh_editing_fields(&mut self) {
        if let Some(ref host) = self.edited_host {
            // pull every (key, value) pair directly
            let mut fields: Vec<(String, String)> = host.iter_fields();
            // also keep any user‑added but still‑empty fields visible
            for k in &self.new_fields {
                fields.push((k.clone(), String::new()));
            }

            // Sort fields for consistent ordering.
            fields.sort_by(|(a, _), (b, _)| a.cmp(b));

            // Convert into editing_fields with explicit sizing.
            let mut edits: Vec<(String, Input)> = fields
                .into_iter()
                .map(|(field, value)| (to_pascal_case(&field), Input::from(value)))
                .collect();

            edits.sort_by(|(a, _), (b, _)| a.to_lowercase().cmp(&b.to_lowercase()));

            self.editing_fields = edits;

            if self.edit_field_index >= self.editing_fields.len() {
                self.edit_field_index = 0;
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
                }
                // Only update search if no modal is active.
                if self.focus == Focus::Table && self.add_field_modal.is_none() {
                    self.search.handle_event(&Event::Key(key));
                    self.hosts.search(self.search.value());

                    // clamp selection into new bounds
                    let old_sel = self.table_state.selected().unwrap_or(0);
                    let new_sel = if self.hosts.is_empty() {
                        0
                    } else {
                        old_sel.min(self.hosts.len() - 1)
                    };
                    self.table_state.select(Some(new_sel));

                    // *always* reload the right‑pane for the newly‑selected host
                    self.load_editing_fields();
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

        // If the modal is active, handle its keys and return.
        // If the modal is active, handle its keys and return.
        if let Some(ref mut modal) = self.add_field_modal {
            match key.code {
                Enter => {
                    if !modal.filtered_fields.is_empty() {
                        // Grab the chosen field (in snake_case).
                        let chosen_field = modal.filtered_fields[modal.selected_index].clone();

                        // Record that this field was explicitly added.
                        self.new_fields.push(chosen_field.clone());

                        // Update the host: insert the new field with an empty value.
                        if let Some(ref mut host) = self.edited_host {
                            let mut host_value =
                                serde_json::to_value(&mut *host).expect("Failed to serialize host");
                            if let serde_json::Value::Object(ref mut map) = host_value {
                                // Only insert if not already present.
                                // figure out which fields are your multi-valued ones
                                let vec_fields = ssh::Host::vec_fields();
                                if vec_fields.contains(&chosen_field.as_str()) {
                                    // for a Vec<String> field, make sure it’s an Array and push one more empty string
                                    let entry = map
                                        .entry(chosen_field.clone())
                                        .or_insert(serde_json::Value::Array(vec![]));
                                    if let serde_json::Value::Array(ref mut arr) = entry {
                                        arr.push(serde_json::Value::String(String::new()));
                                    }
                                } else {
                                    // single-valued fields still get the old behavior
                                    map.entry(chosen_field.clone())
                                        .or_insert(serde_json::Value::String(String::new()));
                                }
                            }
                            *host =
                                serde_json::from_value(host_value).expect("Failed to update host");
                        }
                        // Refresh the editing fields list.
                        self.refresh_editing_fields();
                        self.load_editing_fields();
                        // Set the edit_field_index to the newly added field.
                        if let Some(idx) = self
                            .editing_fields
                            .iter()
                            .rposition(|(f, _)| f == &to_pascal_case(&chosen_field))
                        {
                            self.edit_field_index = idx;
                        }
                        // Switch focus to the form editing side.
                        self.focus = Focus::Form;
                        self.in_field_edit = true;
                    }
                    self.add_field_modal = None;
                    return Ok(AppKeyAction::Ok);
                }
                Esc => {
                    // Cancel the modal.
                    self.add_field_modal = None;
                    return Ok(AppKeyAction::Ok);
                }
                _ => {
                    // Delegate all other keys to the modal.
                    modal.handle_event(key);
                    return Ok(AppKeyAction::Ok);
                }
            }
        }

        // No modal active—continue with the normal event handling:
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
                match key.code {
                    Tab => {
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
                            self.commit_field();
                            self.in_field_edit = false;
                        } else {
                            self.in_field_edit = true;
                        }
                    }
                    // Open modal with 'a' when not editing:
                    KeyCode::Char('a') if !self.in_field_edit => {
                        let existing_fields: Vec<String> = if let Some(ref host) = self.edited_host
                        {
                            host.iter_fields().into_iter().map(|(et, _)| et).collect()
                        } else {
                            Vec::new()
                        };
                        self.add_field_modal = Some(AddFieldModal::new(&existing_fields));
                        return Ok(AppKeyAction::Ok);
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

// Helper function to style help messages.
// It splits each section on " | " and applies bold to the key inside parentheses.
fn styled_help(msg: &str) -> Vec<Span<'static>> {
    // Split the message into parts
    let parts: Vec<&str> = msg.split(" | ").collect();
    let mut spans: Vec<Span> = Vec::new();

    for (i, part) in parts.iter().enumerate() {
        let part = part.trim();
        if let Some(end) = part.find(")") {
            // Split into key (inside parentheses) and description.
            let (key_part, description_part) = part.split_at(end + 1);
            spans.push(Span::styled(
                key_part.to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ));
            let desc = description_part.trim_start();
            if !desc.is_empty() {
                spans.push(Span::raw(format!(" {}", desc)));
            }
        } else {
            spans.push(Span::raw(part.to_string()));
        }
        // Add a separator between parts except for the last one.
        if i != parts.len() - 1 {
            spans.push(Span::raw(" | "));
        }
    }
    spans
}

fn ui(f: &mut Frame, app: &mut App) {
    // Split the screen vertically into main content and a full-width help footer.
    let vertical_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)].as_ref())
        .split(f.size());
    let main_area = vertical_chunks[0];
    let help_area = vertical_chunks[1];

    // Split the main area horizontally into left and right halves.
    let horizontal_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(main_area);

    // Left side: searchbar and table.
    let left_rects =
        Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).split(horizontal_chunks[0]);
    render_searchbar(f, app, left_rects[0]);
    render_table(f, app, left_rects[1]);

    // Right side: form (edit fields).
    let right_rects = Layout::vertical([Constraint::Min(7)]).split(horizontal_chunks[1]);
    if app.focus == Focus::Table {
        app.load_editing_fields();
    }
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let form_items: Vec<ListItem> = app
        .editing_fields
        .iter()
        .enumerate()
        .map(|(i, (field, input))| {
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
            // .title("Configuration (Edit)")
            .borders(Borders::ALL)
            .border_style(Style::new().fg(app.palette.c400))
            .border_type(BorderType::Rounded),
    );
    f.render_widget(form_list, right_rects[0]);

    // Build and render the full-width help footer with styled keys.
    let help_spans = if app.focus == Focus::Table {
        styled_help(LEFT_HELP_MSG)
    } else {
        styled_help(RIGHT_HELP_MSG)
    };
    // Wrap the spans into a Line, then create a Text from a vector of Lines.
    let help_text = Text::from(vec![Line::from(help_spans)]);
    let help_paragraph = Paragraph::new(help_text).centered().block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(app.palette.c400))
            .border_type(BorderType::Rounded),
    );
    f.render_widget(help_paragraph, help_area);

    // Set the cursor for form editing.
    if app.focus == Focus::Form && app.in_field_edit {
        let form_area = right_rects[0];
        let inner_x = form_area.x + 1;
        let inner_y = form_area.y + 1;
        let (label, input) = &app.editing_fields[app.edit_field_index];
        let label_text = format!("{}: ", label);
        let x = inner_x + label_text.len() as u16 + input.cursor() as u16;
        let y = inner_y + app.edit_field_index as u16;
        f.set_cursor(x, y);
    }
    // Set the cursor for the searchbar.
    if app.focus == Focus::Table {
        f.set_cursor(
            left_rects[0].x + u16::try_from(app.search.cursor()).unwrap_or_default() + 4,
            left_rects[0].y + 1,
        );
    }

    // Render the modal if active.
    if let Some(modal) = &app.add_field_modal {
        // carve out a 2-line filter input above the list
        let modal_area = centered_rect(15, 60, f.size());
        f.render_widget(Clear, modal_area);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
            .split(modal_area);

        // 1) show what the user is typing
        let filter_block = Paragraph::new(modal.filter.value())
            .block(Block::default().title("Filter").borders(Borders::ALL));
        f.render_widget(filter_block, chunks[0]);

        // 2) then the list of completions
        let list_area = chunks[1];
        let available_height = list_area.height.saturating_sub(2) as usize;
        let total_items = modal.filtered_fields.len();
        let scroll_offset =
            if total_items > available_height && modal.selected_index >= available_height {
                modal.selected_index - available_height + 1
            } else {
                0
            };
        let end_index = (scroll_offset + available_height).min(total_items);
        let visible_fields = &modal.filtered_fields[scroll_offset..end_index];
        let modal_items: Vec<ListItem> = visible_fields
            .iter()
            .enumerate()
            .map(|(i, field)| {
                let abs_index = i + scroll_offset;
                let style = if abs_index == modal.selected_index {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };
                ListItem::new(field.clone()).style(style)
            })
            .collect();
        let modal_list = List::new(modal_items)
            .block(
                Block::default()
                    .title("Add Field (Enter to select, Esc to cancel)")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded),
            )
            .highlight_symbol(">> ");
        f.render_widget(modal_list, list_area);
    }
}

/// Helper function to create a centered rectangle with the given width and height percentages.
fn centered_rect(desired_height: u16, percent_x: u16, r: Rect) -> Rect {
    use std::cmp::min;
    let modal_height = min(desired_height, r.height);
    let vertical_gap = (r.height.saturating_sub(modal_height)) / 2;
    let modal_width = r.width * percent_x / 100;
    let horizontal_gap = (r.width.saturating_sub(modal_width)) / 2;
    Rect {
        x: r.x + horizontal_gap,
        y: r.y + vertical_gap,
        width: modal_width,
        height: modal_height,
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

fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            // Capitalize the first character and leave the rest unchanged.
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(c.to_lowercase().next().unwrap());
        } else {
            result.push(c);
        }
    }
    result
}

pub struct AddFieldModal {
    /// Filter string input for the modal.
    pub filter: Input,
    /// Fields available for addition (derived from the Host struct).
    pub available_fields: Vec<String>,
    /// Filtered list based on the current filter value.
    pub filtered_fields: Vec<String>,
    /// The current selected index from the filtered list.
    pub selected_index: usize,
}

impl AddFieldModal {
    /// Create a new modal based on the list of existing fields already in the host.
    pub fn new(existing_fields: &[String]) -> Self {
        // Get all field names from the Host struct dynamically.
        let all_fields = ssh::get_all_host_fields();
        // after
        let vec_fields = ssh::Host::vec_fields();
        let available_fields: Vec<String> = all_fields
            .into_iter()
            .filter(|field| {
                // we never want to add name or aliases
                if field == "name" || field == "aliases" {
                    return false;
                }
                // if it's a Vec<String> field, always keep it in the list
                if vec_fields.contains(&field.as_str()) {
                    return true;
                }
                // otherwise (String fields), only keep it if it's not already present
                !existing_fields.contains(field)
            })
            .collect();

        let mut modal = Self {
            filter: "".into(),
            available_fields,
            filtered_fields: Vec::new(),
            selected_index: 0,
        };
        modal.update_filtered();
        modal
    }

    /// Update the filtered list using the current filter input.
    pub fn update_filtered(&mut self) {
        let filter_value = self.filter.value();
        self.filtered_fields = self
            .available_fields
            .iter()
            .filter(|f| filter_value.is_empty() || f.contains(filter_value))
            .cloned()
            .collect();

        if self.selected_index >= self.filtered_fields.len() && !self.filtered_fields.is_empty() {
            self.selected_index = 0;
        }
    }

    /// Handle key events (up/down arrows for navigation and other keys for editing the filter).
    pub fn handle_event(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Down => {
                if !self.filtered_fields.is_empty() {
                    self.selected_index = (self.selected_index + 1) % self.filtered_fields.len();
                }
                true
            }
            KeyCode::Up => {
                if !self.filtered_fields.is_empty() {
                    if self.selected_index == 0 {
                        self.selected_index = self.filtered_fields.len() - 1;
                    } else {
                        self.selected_index -= 1;
                    }
                }
                true
            }
            _ => {
                // Pass other keys to the filter input.
                self.filter.handle_event(&crossterm::event::Event::Key(key));
                self.update_filtered();
                true
            }
        }
    }
}
