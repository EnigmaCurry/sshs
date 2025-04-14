use anyhow::anyhow;
use handlebars::Handlebars;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;

use crate::ssh_config::{self, parser_error::ParseError, HostVecExt};
#[derive(Debug, Default, Serialize, Clone, PartialEq, Deserialize)]
pub struct Host {
    pub add_keys_to_agent: Option<String>,
    pub address_family: Option<String>,
    pub aliases: String,
    pub batch_mode: Option<String>,
    pub bind_address: Option<String>,
    pub bind_interface: Option<String>,
    pub ca_signature_algorithms: Option<String>,
    pub canonical_domains: Option<String>,
    pub canonicalize_fallback_local: Option<String>,
    pub canonicalize_hostname: Option<String>,
    pub canonicalize_max_dots: Option<String>,
    pub canonicalize_permitted_cnames: Option<String>,
    pub certificate_file: Option<String>,
    pub channel_timeout: Option<String>,
    pub check_host_ip: Option<String>,
    pub ciphers: Option<String>,
    pub clear_all_forwardings: Option<String>,
    pub compression: Option<String>,
    pub connect_timeout: Option<String>,
    pub connection_attempts: Option<String>,
    pub control_master: Option<String>,
    pub control_path: Option<String>,
    pub control_persist: Option<String>,
    pub dynamic_forward: Option<String>,
    pub enable_escape_commandline: Option<String>,
    pub enable_ssh_keysign: Option<String>,
    pub escape_char: Option<String>,
    pub exit_on_forward_failure: Option<String>,
    pub fingerprint_hash: Option<String>,
    pub fork_after_authentication: Option<String>,
    pub forward_agent: Option<String>,
    pub forward_x11: Option<String>,
    pub forward_x11_timeout: Option<String>,
    pub forward_x11_trusted: Option<String>,
    pub gateway_ports: Option<String>,
    pub global_known_hosts_file: Option<String>,
    pub gssapi_authentication: Option<String>,
    pub gssapi_delegate_credentials: Option<String>,
    pub hash_known_hosts: Option<String>,
    pub host_key_algorithms: Option<String>,
    pub host_key_alias: Option<String>,
    pub hostbased_accepted_algorithms: Option<String>,
    pub hostbased_authentication: Option<String>,
    pub hostname: String,
    pub identities_only: Option<String>,
    pub identity_agent: Option<String>,
    pub identity_file: Option<String>,
    pub ignore_unknown: Option<String>,
    pub include: Option<String>,
    pub ipqos: Option<String>,
    pub kbd_interactive_authentication: Option<String>,
    pub kbd_interactive_devices: Option<String>,
    pub kex_algorithms: Option<String>,
    pub known_hosts_command: Option<String>,
    pub local_command: Option<String>,
    pub local_forward: Option<String>,
    pub log_level: Option<String>,
    pub log_verbose: Option<String>,
    pub macs: Option<String>,
    pub match_field: Option<String>,
    pub name: String,
    pub no_host_authentication_for_localhost: Option<String>,
    pub number_of_password_prompts: Option<String>,
    pub obscure_keystroke_timing: Option<String>,
    pub password_authentication: Option<String>,
    pub permit_local_command: Option<String>,
    pub permit_remote_open: Option<String>,
    pub pkcs11_provider: Option<String>,
    pub port: Option<String>,
    pub preferred_authentications: Option<String>,
    pub proxy_command: Option<String>,
    pub proxy_jump: Option<String>,
    pub proxy_use_fdpass: Option<String>,
    pub pubkey_accepted_algorithms: Option<String>,
    pub pubkey_authentication: Option<String>,
    pub rekey_limit: Option<String>,
    pub remote_command: Option<String>,
    pub remote_forward: Option<String>,
    pub request_tty: Option<String>,
    pub required_rsa_size: Option<String>,
    pub revoked_host_keys: Option<String>,
    pub security_key_provider: Option<String>,
    pub send_env: Option<String>,
    pub server_alive_count_max: Option<String>,
    pub server_alive_interval: Option<String>,
    pub session_type: Option<String>,
    pub set_env: Option<String>,
    pub stdin_null: Option<String>,
    pub stream_local_bind_mask: Option<String>,
    pub stream_local_bind_unlink: Option<String>,
    pub strict_host_key_checking: Option<String>,
    pub syslog_facility: Option<String>,
    pub tag: Option<String>,
    pub tcp_keep_alive: Option<String>,
    pub tunnel: Option<String>,
    pub tunnel_device: Option<String>,
    pub update_host_keys: Option<String>,
    pub user: Option<String>,
    pub user_known_hosts_file: Option<String>,
    pub verify_host_key_dns: Option<String>,
    pub visual_host_key: Option<String>,
    pub x_auth_location: Option<String>,
}

impl Host {
    /// Uses the provided Handlebars template to run a command.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the command cannot be executed.
    ///
    /// # Panics
    ///
    /// Will panic if the regex cannot be compiled.
    pub fn run_command_template(&self, pattern: &str) -> anyhow::Result<()> {
        let handlebars = Handlebars::new();
        let rendered_command = handlebars.render_template(pattern, &self)?;

        println!("Running command: {rendered_command}");

        let mut args = shlex::split(&rendered_command)
            .ok_or(anyhow!("Failed to parse command: {rendered_command}"))?
            .into_iter()
            .collect::<VecDeque<String>>();
        let command = args.pop_front().ok_or(anyhow!("Failed to get command"))?;

        let status = Command::new(command).args(args).spawn()?.wait()?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }

        Ok(())
    }

    /// Return all fields as (key, value) pairs where the value is a nonblank string.
    pub fn iter_fields(&self) -> Vec<(String, String)> {
        let mut fields = Vec::new();

        // Convert the struct to a JSON value.
        // NOTE: This assumes all fields serialize as either strings or null.
        if let Ok(serde_json::Value::Object(map)) = serde_json::to_value(self) {
            for (key, value) in map {
                // Only add non-null, nonblank string values.
                if let serde_json::Value::String(s) = value {
                    if !s.trim().is_empty() {
                        fields.push((key, s));
                    }
                }
            }
        }
        fields
    }
}

#[derive(Debug)]
pub enum ParseConfigError {
    Io(std::io::Error),
    SshConfig(ParseError),
}

impl From<std::io::Error> for ParseConfigError {
    fn from(e: std::io::Error) -> Self {
        ParseConfigError::Io(e)
    }
}

impl From<ParseError> for ParseConfigError {
    fn from(e: ParseError) -> Self {
        ParseConfigError::SshConfig(e)
    }
}

/// # Errors
///
/// Will return `Err` if the SSH configuration file cannot be parsed.
pub fn parse_config(raw_path: &String) -> Result<Vec<Host>, ParseConfigError> {
    let normalized_path = shellexpand::tilde(&raw_path).to_string();
    let path = std::fs::canonicalize(normalized_path)?;

    let hosts = ssh_config::Parser::new()
        .parse_file(&path)?
        .apply_patterns()
        .apply_name_to_empty_hostname()
        .merge_same_hosts()
        .iter()
        .map(|host| Host {
            name: host
                .get_patterns()
                .first()
                .unwrap_or(&String::new())
                .clone(),
            aliases: host.get_patterns().iter().skip(1).join(" "),
            user: host.get(&ssh_config::EntryType::User),
            hostname: host
                .get(&ssh_config::EntryType::Hostname)
                .unwrap_or_default(),
            port: host.get(&ssh_config::EntryType::Port),
            proxy_command: host.get(&ssh_config::EntryType::ProxyCommand),
            identities_only: host.get(&ssh_config::EntryType::IdentitiesOnly),
            match_field: host.get(&ssh_config::EntryType::Match),
            add_keys_to_agent: host.get(&ssh_config::EntryType::AddKeysToAgent),
            address_family: host.get(&ssh_config::EntryType::AddressFamily),
            batch_mode: host.get(&ssh_config::EntryType::BatchMode),
            bind_address: host.get(&ssh_config::EntryType::BindAddress),
            bind_interface: host.get(&ssh_config::EntryType::BindInterface),
            canonical_domains: host.get(&ssh_config::EntryType::CanonicalDomains),
            canonicalize_fallback_local: host
                .get(&ssh_config::EntryType::CanonicalizeFallbackLocal),
            canonicalize_hostname: host.get(&ssh_config::EntryType::CanonicalizeHostname),
            canonicalize_max_dots: host.get(&ssh_config::EntryType::CanonicalizeMaxDots),
            canonicalize_permitted_cnames: host
                .get(&ssh_config::EntryType::CanonicalizePermittedCNAMEs),
            ca_signature_algorithms: host.get(&ssh_config::EntryType::CASignatureAlgorithms),
            certificate_file: host.get(&ssh_config::EntryType::CertificateFile),
            channel_timeout: host.get(&ssh_config::EntryType::ChannelTimeout),
            check_host_ip: host.get(&ssh_config::EntryType::CheckHostIP),
            ciphers: host.get(&ssh_config::EntryType::Ciphers),
            clear_all_forwardings: host.get(&ssh_config::EntryType::ClearAllForwardings),
            compression: host.get(&ssh_config::EntryType::Compression),
            connection_attempts: host.get(&ssh_config::EntryType::ConnectionAttempts),
            connect_timeout: host.get(&ssh_config::EntryType::ConnectTimeout),
            control_master: host.get(&ssh_config::EntryType::ControlMaster),
            control_path: host.get(&ssh_config::EntryType::ControlPath),
            control_persist: host.get(&ssh_config::EntryType::ControlPersist),
            dynamic_forward: host.get(&ssh_config::EntryType::DynamicForward),
            enable_escape_commandline: host.get(&ssh_config::EntryType::EnableEscapeCommandline),
            enable_ssh_keysign: host.get(&ssh_config::EntryType::EnableSSHKeysign),
            escape_char: host.get(&ssh_config::EntryType::EscapeChar),
            exit_on_forward_failure: host.get(&ssh_config::EntryType::ExitOnForwardFailure),
            fingerprint_hash: host.get(&ssh_config::EntryType::FingerprintHash),
            fork_after_authentication: host.get(&ssh_config::EntryType::ForkAfterAuthentication),
            forward_agent: host.get(&ssh_config::EntryType::ForwardAgent),
            forward_x11: host.get(&ssh_config::EntryType::ForwardX11),
            forward_x11_timeout: host.get(&ssh_config::EntryType::ForwardX11Timeout),
            forward_x11_trusted: host.get(&ssh_config::EntryType::ForwardX11Trusted),
            gateway_ports: host.get(&ssh_config::EntryType::GatewayPorts),
            global_known_hosts_file: host.get(&ssh_config::EntryType::GlobalKnownHostsFile),
            gssapi_authentication: host.get(&ssh_config::EntryType::GSSAPIAuthentication),
            gssapi_delegate_credentials: host
                .get(&ssh_config::EntryType::GSSAPIDelegateCredentials),
            hash_known_hosts: host.get(&ssh_config::EntryType::HashKnownHosts),
            hostbased_accepted_algorithms: host
                .get(&ssh_config::EntryType::HostbasedAcceptedAlgorithms),
            hostbased_authentication: host.get(&ssh_config::EntryType::HostbasedAuthentication),
            host_key_algorithms: host.get(&ssh_config::EntryType::HostKeyAlgorithms),
            host_key_alias: host.get(&ssh_config::EntryType::HostKeyAlias),
            identity_agent: host.get(&ssh_config::EntryType::IdentityAgent),
            identity_file: host.get(&ssh_config::EntryType::IdentityFile),
            ignore_unknown: host.get(&ssh_config::EntryType::IgnoreUnknown),
            include: host.get(&ssh_config::EntryType::Include),
            ipqos: host.get(&ssh_config::EntryType::IPQoS),
            kbd_interactive_authentication: host
                .get(&ssh_config::EntryType::KbdInteractiveAuthentication),
            kbd_interactive_devices: host.get(&ssh_config::EntryType::KbdInteractiveDevices),
            kex_algorithms: host.get(&ssh_config::EntryType::KexAlgorithms),
            known_hosts_command: host.get(&ssh_config::EntryType::KnownHostsCommand),
            local_command: host.get(&ssh_config::EntryType::LocalCommand),
            local_forward: host.get(&ssh_config::EntryType::LocalForward),
            log_level: host.get(&ssh_config::EntryType::LogLevel),
            log_verbose: host.get(&ssh_config::EntryType::LogVerbose),
            macs: host.get(&ssh_config::EntryType::MACs),
            no_host_authentication_for_localhost: host
                .get(&ssh_config::EntryType::NoHostAuthenticationForLocalhost),
            number_of_password_prompts: host.get(&ssh_config::EntryType::NumberOfPasswordPrompts),
            obscure_keystroke_timing: host.get(&ssh_config::EntryType::ObscureKeystrokeTiming),
            password_authentication: host.get(&ssh_config::EntryType::PasswordAuthentication),
            permit_local_command: host.get(&ssh_config::EntryType::PermitLocalCommand),
            permit_remote_open: host.get(&ssh_config::EntryType::PermitRemoteOpen),
            pkcs11_provider: host.get(&ssh_config::EntryType::PKCS11Provider),
            preferred_authentications: host.get(&ssh_config::EntryType::PreferredAuthentications),
            proxy_jump: host.get(&ssh_config::EntryType::ProxyJump),
            proxy_use_fdpass: host.get(&ssh_config::EntryType::ProxyUseFdpass),
            pubkey_accepted_algorithms: host.get(&ssh_config::EntryType::PubkeyAcceptedAlgorithms),
            pubkey_authentication: host.get(&ssh_config::EntryType::PubkeyAuthentication),
            rekey_limit: host.get(&ssh_config::EntryType::RekeyLimit),
            remote_command: host.get(&ssh_config::EntryType::RemoteCommand),
            remote_forward: host.get(&ssh_config::EntryType::RemoteForward),
            request_tty: host.get(&ssh_config::EntryType::RequestTTY),
            required_rsa_size: host.get(&ssh_config::EntryType::RequiredRSASize),
            revoked_host_keys: host.get(&ssh_config::EntryType::RevokedHostKeys),
            security_key_provider: host.get(&ssh_config::EntryType::SecurityKeyProvider),
            send_env: host.get(&ssh_config::EntryType::SendEnv),
            server_alive_count_max: host.get(&ssh_config::EntryType::ServerAliveCountMax),
            server_alive_interval: host.get(&ssh_config::EntryType::ServerAliveInterval),
            session_type: host.get(&ssh_config::EntryType::SessionType),
            set_env: host.get(&ssh_config::EntryType::SetEnv),
            stdin_null: host.get(&ssh_config::EntryType::StdinNull),
            stream_local_bind_mask: host.get(&ssh_config::EntryType::StreamLocalBindMask),
            stream_local_bind_unlink: host.get(&ssh_config::EntryType::StreamLocalBindUnlink),
            strict_host_key_checking: host.get(&ssh_config::EntryType::StrictHostKeyChecking),
            syslog_facility: host.get(&ssh_config::EntryType::SyslogFacility),
            tcp_keep_alive: host.get(&ssh_config::EntryType::TCPKeepAlive),
            tag: host.get(&ssh_config::EntryType::Tag),
            tunnel: host.get(&ssh_config::EntryType::Tunnel),
            tunnel_device: host.get(&ssh_config::EntryType::TunnelDevice),
            update_host_keys: host.get(&ssh_config::EntryType::UpdateHostKeys),
            user_known_hosts_file: host.get(&ssh_config::EntryType::UserKnownHostsFile),
            verify_host_key_dns: host.get(&ssh_config::EntryType::VerifyHostKeyDNS),
            visual_host_key: host.get(&ssh_config::EntryType::VisualHostKey),
            x_auth_location: host.get(&ssh_config::EntryType::XAuthLocation),
        })
        .filter(|h| h.name != ".host")
        .collect::<Vec<Host>>();

    Ok(hosts)
}

/// Save or update a Host config entry in the given SSH config file.
///
/// # Arguments
///
/// * `host` - The host entry to save.
/// * `config_path` - The path to the SSH config file.
///
/// # Errors
///
/// Returns an error if the config file cannot be read or written.
pub fn save_config(host: &Host, config_path: &str) -> anyhow::Result<()> {
    let path = Path::new(config_path);
    let mut existing_blocks: Vec<Vec<String>> = Vec::new();
    let mut current_block: Vec<String> = Vec::new();

    // Read the file and accumulate blocks.
    if path.exists() {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            // A new block starts when a line starts with "host " (case-insensitive).
            if line.trim_start().to_lowercase().starts_with("host ") {
                if !current_block.is_empty() {
                    existing_blocks.push(current_block);
                    current_block = Vec::new();
                }
            }
            // Only include nonblank lines.
            if !line.trim().is_empty() {
                current_block.push(line);
            }
        }
        if !current_block.is_empty() {
            existing_blocks.push(current_block);
        }
    }

    // Look for an existing block that matches the host name.
    let mut target_index: Option<usize> = None;
    for (i, block) in existing_blocks.iter().enumerate() {
        if let Some(first_line) = block.get(0) {
            if first_line.trim_start().to_lowercase().starts_with("host ") {
                let tokens: Vec<&str> = first_line.split_whitespace().collect();
                // Assume the first token is "Host" and the second is the primary name.
                if tokens.len() > 1 && tokens[1] == host.name {
                    target_index = Some(i);
                    break;
                }
            }
        }
    }

    let new_block = format_host_block(host);
    if let Some(i) = target_index {
        existing_blocks[i] = new_block;
    } else {
        existing_blocks.push(new_block);
    }

    // Write back all blocks with exactly one blank line in between.
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    for (i, block) in existing_blocks.iter().enumerate() {
        for line in block {
            writeln!(file, "{}", line)?;
        }
        if i < existing_blocks.len() - 1 {
            writeln!(file)?;
        }
    }

    Ok(())
}

/// Convert a Host into lines of SSH config (Vec<String>).
fn format_host_block(host: &Host) -> Vec<String> {
    // Process the aliases field: split by comma, trim any whitespace,
    // and collect non-empty entries.
    let aliases = if !host.aliases.trim().is_empty() {
        host.aliases
            .split(',')
            .map(|a| a.trim())
            .filter(|a| !a.is_empty())
            .collect::<Vec<&str>>()
            .join(" ")
    } else {
        String::new()
    };

    // Construct the Host header line.
    // If there are aliases, append them after the primary host name.
    let host_line = if aliases.is_empty() {
        format!("Host {}", host.name)
    } else {
        format!("Host {} {}", host.name, aliases)
    };

    let mut lines = vec![host_line];

    // Now output the rest of the fields.
    // Exclude "name" and "aliases" from individual entries.
    for (key, value) in host.iter_fields() {
        if key != "name" && key != "aliases" {
            let ssh_key = format_ssh_key(&key);
            // Use exactly four spaces for indentation.
            lines.push(format!("    {} {}", ssh_key, value));
        }
    }
    lines
}

/// Convert snake_case field names into SSH config-style names.
fn format_ssh_key(field: &str) -> String {
    field
        .split('_')
        .map(|s| {
            let mut chars = s.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

pub fn get_all_host_fields() -> Vec<String> {
    let dummy_host = Host::default();
    let json_val = serde_json::to_value(dummy_host).unwrap();
    if let serde_json::Value::Object(map) = json_val {
        map.keys().cloned().collect()
    } else {
        vec![]
    }
}
