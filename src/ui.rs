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

const INFO_TEXT: &str = "(Esc) quit | (↑/↓) move | (Tab) toggle focus | (enter) act";

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
    /// Remember the last table index we loaded into the form
    last_selected_index: Option<usize>,
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

        if config.sort_by_name {
            hosts.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        }

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
            // Start in table focus
            focus: Focus::Table,
            edited_host: None,
            editing_fields: Vec::new(),
            edit_field_index: 0,
            last_selected_index: None,
        };

        let mut app = app;
        app.calculate_table_columns_constraints();

        Ok(app)
    }

    /// Helper to load the current selected host into the editing form.
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

                // Here we choose a subset of editable fields.
                // You can expand this list as needed.
                if let Some(ref host) = self.edited_host {
                    let name_input: Input = host.name.clone().into();
                    self.editing_fields.push(("Name".to_string(), name_input));

                    let aliases_input: Input = host.aliases.clone().into();
                    self.editing_fields
                        .push(("Aliases".to_string(), aliases_input));

                    let user_input: Input = host.user.clone().unwrap_or_default().into();
                    self.editing_fields.push(("User".to_string(), user_input));

                    let hostname_input: Input = host.hostname.clone().into();
                    self.editing_fields
                        .push(("Hostname".to_string(), hostname_input));

                    let port_input: Input = host.port.clone().unwrap_or_default().into();
                    self.editing_fields.push(("Port".to_string(), port_input));

                    let proxy_input: Input = host.proxy_command.clone().unwrap_or_default().into();
                    self.editing_fields
                        .push(("ProxyCommand".to_string(), proxy_input));
                }
                // Append a "Save" button entry.
                self.editing_fields
                    .push(("Save".to_string(), Input::default()));
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
        B: Backend + std::io::Write,
    {
        loop {
            terminal.borrow_mut().draw(|f| ui(f, self))?;

            let ev = event::read()?;

            if let Event::Key(key) = ev {
                let action = self.on_key_press(terminal, key)?;
                match action {
                    AppKeyAction::Ok => {}
                    AppKeyAction::Stop => break,
                    AppKeyAction::Continue => {}
                }
                // When in table mode, update the search and table.
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
        B: Backend + std::io::Write,
    {
        #[allow(clippy::enum_glob_use)]
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
                    Esc => return Ok(AppKeyAction::Stop),
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
                        // Switch back to table focus.
                        self.focus = Focus::Table;
                    }
                    Up => {
                        if self.edit_field_index == 0 {
                            self.edit_field_index = self.editing_fields.len() - 1;
                        } else {
                            self.edit_field_index -= 1;
                        }
                    }
                    Down => {
                        self.edit_field_index =
                            (self.edit_field_index + 1) % self.editing_fields.len();
                    }
                    Enter => {
                        // If the current field is "Save", then commit the changes.
                        if self.editing_fields[self.edit_field_index].0 == "Save" {
                            if let Some(ref mut edited_host) = self.edited_host {
                                // Update the edited_host with values from the input widgets.
                                for (field, input) in &self.editing_fields {
                                    let val = input.value();
                                    match field.as_str() {
                                        "Name" => edited_host.name = val.to_string(),
                                        "Aliases" => edited_host.aliases = val.to_string(),
                                        "User" => {
                                            edited_host.user = if val.is_empty() {
                                                None
                                            } else {
                                                Some(val.to_string())
                                            }
                                        }
                                        "Hostname" => edited_host.hostname = val.to_string(),
                                        "Port" => {
                                            edited_host.port = if val.is_empty() {
                                                None
                                            } else {
                                                Some(val.to_string())
                                            }
                                        }
                                        "ProxyCommand" => {
                                            edited_host.proxy_command = if val.is_empty() {
                                                None
                                            } else {
                                                Some(val.to_string())
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                // Save the updated host back to disk.
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
                            // Switch focus back to table after saving.
                            self.focus = Focus::Table;
                        } else {
                            // For normal text fields, let the input widget process the event.
                            self.editing_fields[self.edit_field_index]
                                .1
                                .handle_event(&Event::Key(key));
                        }
                    }
                    _ => {
                        // For all other keys, pass the event to the current input widget.
                        self.editing_fields[self.edit_field_index]
                            .1
                            .handle_event(&Event::Key(key));
                    }
                }
                Ok(AppKeyAction::Ok)
            }
        }
    }

    fn on_key_press_ctrl(&mut self, key: KeyEvent) -> AppKeyAction {
        #[allow(clippy::enum_glob_use)]
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

        let mut new_constraints = vec![
            // +1 for padding
            Constraint::Length(u16::try_from(lengths[0]).unwrap_or_default() + 1),
        ];
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
    B: Backend + std::io::Write,
{
    let mut terminal = terminal.borrow_mut();

    // setup terminal
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
    B: Backend + std::io::Write,
{
    let mut terminal = terminal.borrow_mut();
    terminal.clear()?;

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        Show,
        LeaveAlternateScreen,
        DisableMouseCapture,
    )?;

    Ok(())
}

fn ui(f: &mut Frame, app: &mut App) {
    // Left side remains the same.
    let horizontal_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(f.size());

    let left_rects = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(3),
    ])
    .split(horizontal_chunks[0]);

    render_searchbar(f, app, left_rects[0]);
    render_table(f, app, left_rects[1]);
    render_footer(f, app, left_rects[2]);

    // On the right, display the editable configuration form.
    // Now, update the form whenever we're in table (preview) mode so that up/down navigation changes the form.
    if app.focus == Focus::Table {
        app.load_editing_fields();
    }

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let form_items: Vec<ListItem> = app
        .editing_fields
        .iter()
        .enumerate()
        .map(|(i, (field, input))| {
            let content = if field == "Save" {
                format!("[ Save ]")
            } else {
                format!("{}: {}", field, input.value())
            };
            let style = if app.focus == Focus::Form && i == app.edit_field_index {
                selected_style
            } else {
                Style::default()
            };
            ListItem::new(content).style(style)
        })
        .collect();

    let form_list = List::new(form_items).block(
        Block::default()
            .title("Configuration (Edit)")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded),
    );
    f.render_widget(form_list, horizontal_chunks[1]);

    // When the focus is on the table, set the cursor in the searchbar as before.
    if app.focus == Focus::Table {
        f.set_cursor(
            left_rects[0].x + u16::try_from(app.search.cursor()).unwrap_or_default() + 4,
            left_rects[0].y + 1,
        );
    }
}

fn render_searchbar(f: &mut Frame, app: &mut App, area: Rect) {
    let info_footer = Paragraph::new(Line::from(app.search.value())).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(app.palette.c400))
            .border_type(BorderType::Rounded)
            .padding(Padding::horizontal(3)),
    );
    f.render_widget(info_footer, area);
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
            .map(|content| Cell::from(Text::from(content.to_string())))
            .collect::<Row>()
    });

    let bar = " █ ";
    let t = Table::new(rows, app.table_columns_constraints.clone())
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

    f.render_stateful_widget(t, area, &mut app.table_state);
}

fn render_footer(f: &mut Frame, app: &mut App, area: Rect) {
    let info_footer = Paragraph::new(Line::from(INFO_TEXT)).centered().block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(app.palette.c400))
            .border_type(BorderType::Rounded),
    );
    f.render_widget(info_footer, area);
}
