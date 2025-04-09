use anyhow::anyhow;
use handlebars::Handlebars;
use itertools::Itertools;
use serde::Serialize;
use std::collections::VecDeque;
use std::process::Command;

use crate::ssh_config::{self, parser_error::ParseError, HostVecExt};
#[derive(Debug, Serialize, Clone)]
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

    /// Returns a vector of (display name, value) pairs for every non‑empty field.
    pub fn iter_fields(&self) -> Vec<(String, String)> {
        let mut fields = Vec::new();

        // Mandatory fields (always present as String)
        if !self.name.trim().is_empty() {
            fields.push(("Name".to_string(), self.name.clone()));
        }
        if !self.aliases.trim().is_empty() {
            fields.push(("Aliases".to_string(), self.aliases.clone()));
        }
        if !self.hostname.trim().is_empty() {
            fields.push(("Hostname".to_string(), self.hostname.clone()));
        }

        // Optional fields (Option<String>)
        if let Some(ref user) = self.user {
            if !user.trim().is_empty() {
                fields.push(("User".to_string(), user.clone()));
            }
        }
        if let Some(ref port) = self.port {
            if !port.trim().is_empty() {
                fields.push(("Port".to_string(), port.clone()));
            }
        }
        if let Some(ref proxy_command) = self.proxy_command {
            if !proxy_command.trim().is_empty() {
                fields.push(("ProxyCommand".to_string(), proxy_command.clone()));
            }
        }
        if let Some(ref identities_only) = self.identities_only {
            if !identities_only.trim().is_empty() {
                fields.push(("IdentitiesOnly".to_string(), identities_only.clone()));
            }
        }

        // Additional fields from EntryType
        if let Some(ref match_field) = self.match_field {
            if !match_field.trim().is_empty() {
                fields.push(("Match".to_string(), match_field.clone()));
            }
        }
        if let Some(ref add_keys_to_agent) = self.add_keys_to_agent {
            if !add_keys_to_agent.trim().is_empty() {
                fields.push(("AddKeysToAgent".to_string(), add_keys_to_agent.clone()));
            }
        }
        if let Some(ref address_family) = self.address_family {
            if !address_family.trim().is_empty() {
                fields.push(("AddressFamily".to_string(), address_family.clone()));
            }
        }
        if let Some(ref batch_mode) = self.batch_mode {
            if !batch_mode.trim().is_empty() {
                fields.push(("BatchMode".to_string(), batch_mode.clone()));
            }
        }
        if let Some(ref bind_address) = self.bind_address {
            if !bind_address.trim().is_empty() {
                fields.push(("BindAddress".to_string(), bind_address.clone()));
            }
        }
        if let Some(ref bind_interface) = self.bind_interface {
            if !bind_interface.trim().is_empty() {
                fields.push(("BindInterface".to_string(), bind_interface.clone()));
            }
        }
        if let Some(ref canonical_domains) = self.canonical_domains {
            if !canonical_domains.trim().is_empty() {
                fields.push(("CanonicalDomains".to_string(), canonical_domains.clone()));
            }
        }
        if let Some(ref canonicalize_fallback_local) = self.canonicalize_fallback_local {
            if !canonicalize_fallback_local.trim().is_empty() {
                fields.push((
                    "CanonicalizeFallbackLocal".to_string(),
                    canonicalize_fallback_local.clone(),
                ));
            }
        }
        if let Some(ref canonicalize_hostname) = self.canonicalize_hostname {
            if !canonicalize_hostname.trim().is_empty() {
                fields.push((
                    "CanonicalizeHostname".to_string(),
                    canonicalize_hostname.clone(),
                ));
            }
        }
        if let Some(ref canonicalize_max_dots) = self.canonicalize_max_dots {
            if !canonicalize_max_dots.trim().is_empty() {
                fields.push((
                    "CanonicalizeMaxDots".to_string(),
                    canonicalize_max_dots.clone(),
                ));
            }
        }
        if let Some(ref canonicalize_permitted_cnames) = self.canonicalize_permitted_cnames {
            if !canonicalize_permitted_cnames.trim().is_empty() {
                fields.push((
                    "CanonicalizePermittedCNAMEs".to_string(),
                    canonicalize_permitted_cnames.clone(),
                ));
            }
        }
        if let Some(ref ca_signature_algorithms) = self.ca_signature_algorithms {
            if !ca_signature_algorithms.trim().is_empty() {
                fields.push((
                    "CASignatureAlgorithms".to_string(),
                    ca_signature_algorithms.clone(),
                ));
            }
        }
        if let Some(ref certificate_file) = self.certificate_file {
            if !certificate_file.trim().is_empty() {
                fields.push(("CertificateFile".to_string(), certificate_file.clone()));
            }
        }
        if let Some(ref channel_timeout) = self.channel_timeout {
            if !channel_timeout.trim().is_empty() {
                fields.push(("ChannelTimeout".to_string(), channel_timeout.clone()));
            }
        }
        if let Some(ref check_host_ip) = self.check_host_ip {
            if !check_host_ip.trim().is_empty() {
                fields.push(("CheckHostIP".to_string(), check_host_ip.clone()));
            }
        }
        if let Some(ref ciphers) = self.ciphers {
            if !ciphers.trim().is_empty() {
                fields.push(("Ciphers".to_string(), ciphers.clone()));
            }
        }
        if let Some(ref clear_all_forwardings) = self.clear_all_forwardings {
            if !clear_all_forwardings.trim().is_empty() {
                fields.push((
                    "ClearAllForwardings".to_string(),
                    clear_all_forwardings.clone(),
                ));
            }
        }
        if let Some(ref compression) = self.compression {
            if !compression.trim().is_empty() {
                fields.push(("Compression".to_string(), compression.clone()));
            }
        }
        if let Some(ref connection_attempts) = self.connection_attempts {
            if !connection_attempts.trim().is_empty() {
                fields.push((
                    "ConnectionAttempts".to_string(),
                    connection_attempts.clone(),
                ));
            }
        }
        if let Some(ref connect_timeout) = self.connect_timeout {
            if !connect_timeout.trim().is_empty() {
                fields.push(("ConnectTimeout".to_string(), connect_timeout.clone()));
            }
        }
        if let Some(ref control_master) = self.control_master {
            if !control_master.trim().is_empty() {
                fields.push(("ControlMaster".to_string(), control_master.clone()));
            }
        }
        if let Some(ref control_path) = self.control_path {
            if !control_path.trim().is_empty() {
                fields.push(("ControlPath".to_string(), control_path.clone()));
            }
        }
        if let Some(ref control_persist) = self.control_persist {
            if !control_persist.trim().is_empty() {
                fields.push(("ControlPersist".to_string(), control_persist.clone()));
            }
        }
        if let Some(ref dynamic_forward) = self.dynamic_forward {
            if !dynamic_forward.trim().is_empty() {
                fields.push(("DynamicForward".to_string(), dynamic_forward.clone()));
            }
        }
        if let Some(ref enable_escape_commandline) = self.enable_escape_commandline {
            if !enable_escape_commandline.trim().is_empty() {
                fields.push((
                    "EnableEscapeCommandline".to_string(),
                    enable_escape_commandline.clone(),
                ));
            }
        }
        if let Some(ref enable_ssh_keysign) = self.enable_ssh_keysign {
            if !enable_ssh_keysign.trim().is_empty() {
                fields.push(("EnableSSHKeysign".to_string(), enable_ssh_keysign.clone()));
            }
        }
        if let Some(ref escape_char) = self.escape_char {
            if !escape_char.trim().is_empty() {
                fields.push(("EscapeChar".to_string(), escape_char.clone()));
            }
        }
        if let Some(ref exit_on_forward_failure) = self.exit_on_forward_failure {
            if !exit_on_forward_failure.trim().is_empty() {
                fields.push((
                    "ExitOnForwardFailure".to_string(),
                    exit_on_forward_failure.clone(),
                ));
            }
        }
        if let Some(ref fingerprint_hash) = self.fingerprint_hash {
            if !fingerprint_hash.trim().is_empty() {
                fields.push(("FingerprintHash".to_string(), fingerprint_hash.clone()));
            }
        }
        if let Some(ref fork_after_authentication) = self.fork_after_authentication {
            if !fork_after_authentication.trim().is_empty() {
                fields.push((
                    "ForkAfterAuthentication".to_string(),
                    fork_after_authentication.clone(),
                ));
            }
        }
        if let Some(ref forward_agent) = self.forward_agent {
            if !forward_agent.trim().is_empty() {
                fields.push(("ForwardAgent".to_string(), forward_agent.clone()));
            }
        }
        if let Some(ref forward_x11) = self.forward_x11 {
            if !forward_x11.trim().is_empty() {
                fields.push(("ForwardX11".to_string(), forward_x11.clone()));
            }
        }
        if let Some(ref forward_x11_timeout) = self.forward_x11_timeout {
            if !forward_x11_timeout.trim().is_empty() {
                fields.push(("ForwardX11Timeout".to_string(), forward_x11_timeout.clone()));
            }
        }
        if let Some(ref forward_x11_trusted) = self.forward_x11_trusted {
            if !forward_x11_trusted.trim().is_empty() {
                fields.push(("ForwardX11Trusted".to_string(), forward_x11_trusted.clone()));
            }
        }
        if let Some(ref gateway_ports) = self.gateway_ports {
            if !gateway_ports.trim().is_empty() {
                fields.push(("GatewayPorts".to_string(), gateway_ports.clone()));
            }
        }
        if let Some(ref global_known_hosts_file) = self.global_known_hosts_file {
            if !global_known_hosts_file.trim().is_empty() {
                fields.push((
                    "GlobalKnownHostsFile".to_string(),
                    global_known_hosts_file.clone(),
                ));
            }
        }
        if let Some(ref gssapi_authentication) = self.gssapi_authentication {
            if !gssapi_authentication.trim().is_empty() {
                fields.push((
                    "GSSAPIAuthentication".to_string(),
                    gssapi_authentication.clone(),
                ));
            }
        }
        if let Some(ref gssapi_delegate_credentials) = self.gssapi_delegate_credentials {
            if !gssapi_delegate_credentials.trim().is_empty() {
                fields.push((
                    "GSSAPIDelegateCredentials".to_string(),
                    gssapi_delegate_credentials.clone(),
                ));
            }
        }
        if let Some(ref hash_known_hosts) = self.hash_known_hosts {
            if !hash_known_hosts.trim().is_empty() {
                fields.push(("HashKnownHosts".to_string(), hash_known_hosts.clone()));
            }
        }
        if let Some(ref hostbased_accepted_algorithms) = self.hostbased_accepted_algorithms {
            if !hostbased_accepted_algorithms.trim().is_empty() {
                fields.push((
                    "HostbasedAcceptedAlgorithms".to_string(),
                    hostbased_accepted_algorithms.clone(),
                ));
            }
        }
        if let Some(ref hostbased_authentication) = self.hostbased_authentication {
            if !hostbased_authentication.trim().is_empty() {
                fields.push((
                    "HostbasedAuthentication".to_string(),
                    hostbased_authentication.clone(),
                ));
            }
        }
        if let Some(ref host_key_algorithms) = self.host_key_algorithms {
            if !host_key_algorithms.trim().is_empty() {
                fields.push(("HostKeyAlgorithms".to_string(), host_key_algorithms.clone()));
            }
        }
        if let Some(ref host_key_alias) = self.host_key_alias {
            if !host_key_alias.trim().is_empty() {
                fields.push(("HostKeyAlias".to_string(), host_key_alias.clone()));
            }
        }
        if let Some(ref identity_agent) = self.identity_agent {
            if !identity_agent.trim().is_empty() {
                fields.push(("IdentityAgent".to_string(), identity_agent.clone()));
            }
        }
        if let Some(ref identity_file) = self.identity_file {
            if !identity_file.trim().is_empty() {
                fields.push(("IdentityFile".to_string(), identity_file.clone()));
            }
        }
        if let Some(ref ignore_unknown) = self.ignore_unknown {
            if !ignore_unknown.trim().is_empty() {
                fields.push(("IgnoreUnknown".to_string(), ignore_unknown.clone()));
            }
        }
        if let Some(ref include) = self.include {
            if !include.trim().is_empty() {
                fields.push(("Include".to_string(), include.clone()));
            }
        }
        if let Some(ref ipqos) = self.ipqos {
            if !ipqos.trim().is_empty() {
                fields.push(("IPQoS".to_string(), ipqos.clone()));
            }
        }
        if let Some(ref kbd_interactive_authentication) = self.kbd_interactive_authentication {
            if !kbd_interactive_authentication.trim().is_empty() {
                fields.push((
                    "KbdInteractiveAuthentication".to_string(),
                    kbd_interactive_authentication.clone(),
                ));
            }
        }
        if let Some(ref kbd_interactive_devices) = self.kbd_interactive_devices {
            if !kbd_interactive_devices.trim().is_empty() {
                fields.push((
                    "KbdInteractiveDevices".to_string(),
                    kbd_interactive_devices.clone(),
                ));
            }
        }
        if let Some(ref kex_algorithms) = self.kex_algorithms {
            if !kex_algorithms.trim().is_empty() {
                fields.push(("KexAlgorithms".to_string(), kex_algorithms.clone()));
            }
        }
        if let Some(ref known_hosts_command) = self.known_hosts_command {
            if !known_hosts_command.trim().is_empty() {
                fields.push(("KnownHostsCommand".to_string(), known_hosts_command.clone()));
            }
        }
        if let Some(ref local_command) = self.local_command {
            if !local_command.trim().is_empty() {
                fields.push(("LocalCommand".to_string(), local_command.clone()));
            }
        }
        if let Some(ref local_forward) = self.local_forward {
            if !local_forward.trim().is_empty() {
                fields.push(("LocalForward".to_string(), local_forward.clone()));
            }
        }
        if let Some(ref log_level) = self.log_level {
            if !log_level.trim().is_empty() {
                fields.push(("LogLevel".to_string(), log_level.clone()));
            }
        }
        if let Some(ref log_verbose) = self.log_verbose {
            if !log_verbose.trim().is_empty() {
                fields.push(("LogVerbose".to_string(), log_verbose.clone()));
            }
        }
        if let Some(ref macs) = self.macs {
            if !macs.trim().is_empty() {
                fields.push(("MACs".to_string(), macs.clone()));
            }
        }
        if let Some(ref no_host_authentication_for_localhost) =
            self.no_host_authentication_for_localhost
        {
            if !no_host_authentication_for_localhost.trim().is_empty() {
                fields.push((
                    "NoHostAuthenticationForLocalhost".to_string(),
                    no_host_authentication_for_localhost.clone(),
                ));
            }
        }
        if let Some(ref number_of_password_prompts) = self.number_of_password_prompts {
            if !number_of_password_prompts.trim().is_empty() {
                fields.push((
                    "NumberOfPasswordPrompts".to_string(),
                    number_of_password_prompts.clone(),
                ));
            }
        }
        if let Some(ref obscure_keystroke_timing) = self.obscure_keystroke_timing {
            if !obscure_keystroke_timing.trim().is_empty() {
                fields.push((
                    "ObscureKeystrokeTiming".to_string(),
                    obscure_keystroke_timing.clone(),
                ));
            }
        }
        if let Some(ref password_authentication) = self.password_authentication {
            if !password_authentication.trim().is_empty() {
                fields.push((
                    "PasswordAuthentication".to_string(),
                    password_authentication.clone(),
                ));
            }
        }
        if let Some(ref permit_local_command) = self.permit_local_command {
            if !permit_local_command.trim().is_empty() {
                fields.push((
                    "PermitLocalCommand".to_string(),
                    permit_local_command.clone(),
                ));
            }
        }
        if let Some(ref permit_remote_open) = self.permit_remote_open {
            if !permit_remote_open.trim().is_empty() {
                fields.push(("PermitRemoteOpen".to_string(), permit_remote_open.clone()));
            }
        }
        if let Some(ref pkcs11_provider) = self.pkcs11_provider {
            if !pkcs11_provider.trim().is_empty() {
                fields.push(("PKCS11Provider".to_string(), pkcs11_provider.clone()));
            }
        }
        if let Some(ref preferred_authentications) = self.preferred_authentications {
            if !preferred_authentications.trim().is_empty() {
                fields.push((
                    "PreferredAuthentications".to_string(),
                    preferred_authentications.clone(),
                ));
            }
        }
        if let Some(ref proxy_jump) = self.proxy_jump {
            if !proxy_jump.trim().is_empty() {
                fields.push(("ProxyJump".to_string(), proxy_jump.clone()));
            }
        }
        if let Some(ref proxy_use_fdpass) = self.proxy_use_fdpass {
            if !proxy_use_fdpass.trim().is_empty() {
                fields.push(("ProxyUseFdpass".to_string(), proxy_use_fdpass.clone()));
            }
        }
        if let Some(ref pubkey_accepted_algorithms) = self.pubkey_accepted_algorithms {
            if !pubkey_accepted_algorithms.trim().is_empty() {
                fields.push((
                    "PubkeyAcceptedAlgorithms".to_string(),
                    pubkey_accepted_algorithms.clone(),
                ));
            }
        }
        if let Some(ref pubkey_authentication) = self.pubkey_authentication {
            if !pubkey_authentication.trim().is_empty() {
                fields.push((
                    "PubkeyAuthentication".to_string(),
                    pubkey_authentication.clone(),
                ));
            }
        }
        if let Some(ref rekey_limit) = self.rekey_limit {
            if !rekey_limit.trim().is_empty() {
                fields.push(("RekeyLimit".to_string(), rekey_limit.clone()));
            }
        }
        if let Some(ref remote_command) = self.remote_command {
            if !remote_command.trim().is_empty() {
                fields.push(("RemoteCommand".to_string(), remote_command.clone()));
            }
        }
        if let Some(ref remote_forward) = self.remote_forward {
            if !remote_forward.trim().is_empty() {
                fields.push(("RemoteForward".to_string(), remote_forward.clone()));
            }
        }
        if let Some(ref request_tty) = self.request_tty {
            if !request_tty.trim().is_empty() {
                fields.push(("RequestTTY".to_string(), request_tty.clone()));
            }
        }
        if let Some(ref required_rsa_size) = self.required_rsa_size {
            if !required_rsa_size.trim().is_empty() {
                fields.push(("RequiredRSASize".to_string(), required_rsa_size.clone()));
            }
        }
        if let Some(ref revoked_host_keys) = self.revoked_host_keys {
            if !revoked_host_keys.trim().is_empty() {
                fields.push(("RevokedHostKeys".to_string(), revoked_host_keys.clone()));
            }
        }
        if let Some(ref security_key_provider) = self.security_key_provider {
            if !security_key_provider.trim().is_empty() {
                fields.push((
                    "SecurityKeyProvider".to_string(),
                    security_key_provider.clone(),
                ));
            }
        }
        if let Some(ref send_env) = self.send_env {
            if !send_env.trim().is_empty() {
                fields.push(("SendEnv".to_string(), send_env.clone()));
            }
        }
        if let Some(ref server_alive_count_max) = self.server_alive_count_max {
            if !server_alive_count_max.trim().is_empty() {
                fields.push((
                    "ServerAliveCountMax".to_string(),
                    server_alive_count_max.clone(),
                ));
            }
        }
        if let Some(ref server_alive_interval) = self.server_alive_interval {
            if !server_alive_interval.trim().is_empty() {
                fields.push((
                    "ServerAliveInterval".to_string(),
                    server_alive_interval.clone(),
                ));
            }
        }
        if let Some(ref session_type) = self.session_type {
            if !session_type.trim().is_empty() {
                fields.push(("SessionType".to_string(), session_type.clone()));
            }
        }
        if let Some(ref set_env) = self.set_env {
            if !set_env.trim().is_empty() {
                fields.push(("SetEnv".to_string(), set_env.clone()));
            }
        }
        if let Some(ref stdin_null) = self.stdin_null {
            if !stdin_null.trim().is_empty() {
                fields.push(("StdinNull".to_string(), stdin_null.clone()));
            }
        }
        if let Some(ref stream_local_bind_mask) = self.stream_local_bind_mask {
            if !stream_local_bind_mask.trim().is_empty() {
                fields.push((
                    "StreamLocalBindMask".to_string(),
                    stream_local_bind_mask.clone(),
                ));
            }
        }
        if let Some(ref stream_local_bind_unlink) = self.stream_local_bind_unlink {
            if !stream_local_bind_unlink.trim().is_empty() {
                fields.push((
                    "StreamLocalBindUnlink".to_string(),
                    stream_local_bind_unlink.clone(),
                ));
            }
        }
        if let Some(ref strict_host_key_checking) = self.strict_host_key_checking {
            if !strict_host_key_checking.trim().is_empty() {
                fields.push((
                    "StrictHostKeyChecking".to_string(),
                    strict_host_key_checking.clone(),
                ));
            }
        }
        if let Some(ref syslog_facility) = self.syslog_facility {
            if !syslog_facility.trim().is_empty() {
                fields.push(("SyslogFacility".to_string(), syslog_facility.clone()));
            }
        }
        if let Some(ref tcp_keep_alive) = self.tcp_keep_alive {
            if !tcp_keep_alive.trim().is_empty() {
                fields.push(("TCPKeepAlive".to_string(), tcp_keep_alive.clone()));
            }
        }
        if let Some(ref tag) = self.tag {
            if !tag.trim().is_empty() {
                fields.push(("Tag".to_string(), tag.clone()));
            }
        }
        if let Some(ref tunnel) = self.tunnel {
            if !tunnel.trim().is_empty() {
                fields.push(("Tunnel".to_string(), tunnel.clone()));
            }
        }
        if let Some(ref tunnel_device) = self.tunnel_device {
            if !tunnel_device.trim().is_empty() {
                fields.push(("TunnelDevice".to_string(), tunnel_device.clone()));
            }
        }
        if let Some(ref update_host_keys) = self.update_host_keys {
            if !update_host_keys.trim().is_empty() {
                fields.push(("UpdateHostKeys".to_string(), update_host_keys.clone()));
            }
        }
        if let Some(ref user_known_hosts_file) = self.user_known_hosts_file {
            if !user_known_hosts_file.trim().is_empty() {
                fields.push((
                    "UserKnownHostsFile".to_string(),
                    user_known_hosts_file.clone(),
                ));
            }
        }
        if let Some(ref verify_host_key_dns) = self.verify_host_key_dns {
            if !verify_host_key_dns.trim().is_empty() {
                fields.push(("VerifyHostKeyDNS".to_string(), verify_host_key_dns.clone()));
            }
        }
        if let Some(ref visual_host_key) = self.visual_host_key {
            if !visual_host_key.trim().is_empty() {
                fields.push(("VisualHostKey".to_string(), visual_host_key.clone()));
            }
        }
        if let Some(ref x_auth_location) = self.x_auth_location {
            if !x_auth_location.trim().is_empty() {
                fields.push(("XAuthLocation".to_string(), x_auth_location.clone()));
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
            aliases: host.get_patterns().iter().skip(1).join(", "),
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
        .collect::<Vec<Host>>();

    Ok(hosts)
}
