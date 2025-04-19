use regex::Regex;
use std::collections::HashMap;

use super::EntryType;

pub(crate) type Entry = (EntryType, String);

#[derive(Debug, Clone)]
pub struct ConfigHost {
    patterns: Vec<String>,
    entries: HashMap<EntryType, String>,
    pub(crate) multi_entries: HashMap<EntryType, Vec<String>>,
}

impl ConfigHost {
    #[must_use]
    pub fn new(patterns: Vec<String>) -> ConfigHost {
        ConfigHost {
            patterns,
            entries: HashMap::new(),
            multi_entries: HashMap::new(),
        }
    }

    /// Inserts or appends an entry. Single-value keywords override; multi-value keywords append.
    pub fn update(&mut self, entry: Entry) {
        match entry.0 {
            EntryType::IdentityFile
            | EntryType::LocalForward
            | EntryType::RemoteForward
            | EntryType::SendEnv
            | EntryType::SetEnv
            | EntryType::CertificateFile
            | EntryType::CanonicalDomains
            | EntryType::GlobalKnownHostsFile
            | EntryType::HostKeyAlias
            | EntryType::Match => {
                self.multi_entries
                    .entry(entry.0)
                    .or_insert_with(Vec::new)
                    .push(entry.1);
            }
            _ => {
                self.entries.insert(entry.0, entry.1);
            }
        }
    }

    pub(crate) fn extend_patterns(&mut self, host: &ConfigHost) {
        self.patterns.extend(host.patterns.clone());
    }

    pub(crate) fn extend_entries(&mut self, host: &ConfigHost) {
        self.entries.extend(host.entries.clone());
        for (key, vals) in &host.multi_entries {
            self.multi_entries
                .entry(key.clone())
                .or_insert_with(Vec::new)
                .extend(vals.clone());
        }
    }

    pub(crate) fn extend_if_not_contained(&mut self, host: &ConfigHost) {
        for (key, value) in &host.entries {
            if !self.entries.contains_key(key) {
                self.entries.insert(key.clone(), value.clone());
            }
        }
        for (key, vals) in &host.multi_entries {
            if !self.multi_entries.contains_key(key) {
                self.multi_entries.insert(key.clone(), vals.clone());
            }
        }
    }

    #[allow(clippy::must_use_candidate)]
    pub fn get_patterns(&self) -> &Vec<String> {
        &self.patterns
    }

    /// # Panics
    ///
    /// Will panic if the regex cannot be compiled.
    #[allow(clippy::must_use_candidate)]
    pub fn matching_pattern_regexes(&self) -> Vec<(Regex, bool)> {
        if self.patterns.is_empty() {
            return Vec::new();
        }

        self.patterns
            .iter()
            .filter_map(|pattern| {
                let contains_wildcard =
                    pattern.contains('*') || pattern.contains('?') || pattern.contains('!');
                if !contains_wildcard {
                    return None;
                }

                let mut pat = pattern
                    .replace('.', r"\.")
                    .replace('*', ".*")
                    .replace('?', ".");

                let is_negated = pat.starts_with('!');
                if is_negated {
                    pat.remove(0);
                }

                pat = format!("^{pat}$");
                Some((Regex::new(&pat).unwrap(), is_negated))
            })
            .collect()
    }

    #[allow(clippy::must_use_candidate)]
    pub fn get(&self, entry: &EntryType) -> Option<String> {
        self.entries.get(entry).cloned()
    }

    /// Returns all values for a keyword, single or multi-value.
    #[allow(clippy::must_use_candidate)]
    pub fn get_all(&self, entry: &EntryType) -> Vec<String> {
        if let Some(vals) = self.multi_entries.get(entry) {
            vals.clone()
        } else if let Some(val) = self.entries.get(entry) {
            vec![val.clone()]
        } else {
            Vec::new()
        }
    }

    /// Returns all entries, including multi-entry values.
    #[allow(clippy::must_use_candidate)]
    /// Return every (EntryType, value), including repeated ones.
    pub fn all_entries(&self) -> Vec<(EntryType, String)> {
        let mut v = Vec::new();
        // first all the multi‑valued keywords
        for (k, vals) in &self.multi_entries {
            for val in vals {
                v.push((k.clone(), val.clone()));
            }
        }
        // then the ordinary single‑valued ones
        for (k, val) in &self.entries {
            v.push((k.clone(), val.clone()));
        }
        v
    }

    #[allow(clippy::must_use_candidate)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.multi_entries.is_empty()
    }
}

#[allow(clippy::module_name_repetitions)]
pub trait HostVecExt {
    fn apply_name_to_empty_hostname(&mut self) -> &mut Self;
    fn merge_same_hosts(&mut self) -> &mut Self;
    fn spread(&mut self) -> &mut Self;
    fn apply_patterns(&mut self) -> &mut Self;
}

impl HostVecExt for Vec<ConfigHost> {
    fn apply_name_to_empty_hostname(&mut self) -> &mut Self {
        for host in self.iter_mut() {
            if host.get(&EntryType::Hostname).is_none() {
                let name = host.patterns.first().unwrap().clone();
                host.update((EntryType::Hostname, name));
            }
        }
        self
    }

    fn merge_same_hosts(&mut self) -> &mut Self {
        for i in (0..self.len()).rev() {
            for j in (0..i).rev() {
                if self[i].entries != self[j].entries
                    || self[i].multi_entries != self[j].multi_entries
                {
                    continue;
                }
                let host = self[i].clone();
                self[j].extend_patterns(&host);
                self[j].extend_entries(&host);
                self.remove(i);
                break;
            }
        }
        self
    }

    fn spread(&mut self) -> &mut Self {
        let mut hosts = Vec::new();
        for host in self.iter_mut() {
            let patterns = host.get_patterns();
            if patterns.is_empty() {
                hosts.push(host.clone());
                continue;
            }
            for pattern in patterns {
                let mut new_host = host.clone();
                new_host.patterns = vec![pattern.clone()];
                hosts.push(new_host);
            }
        }
        *self = hosts;
        self
    }

    fn apply_patterns(&mut self) -> &mut Self {
        let hosts = self.spread().clone();
        let mut result = Vec::new();
        let mut pattern_idxs = Vec::new();
        for (i, host) in hosts.iter().enumerate() {
            if host.matching_pattern_regexes().is_empty() {
                result.push(host.clone());
            } else {
                pattern_idxs.push(i);
            }
        }
        for &i in &pattern_idxs {
            let pattern_host = &hosts[i];
            for host in result.iter_mut() {
                if !host.matching_pattern_regexes().is_empty() {
                    continue;
                }
                for (re, neg) in pattern_host.matching_pattern_regexes() {
                    if re.is_match(&host.patterns[0]) == neg {
                        continue;
                    }
                    host.extend_if_not_contained(pattern_host);
                    break;
                }
            }
        }
        *self = result;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_entries() {
        let mut host = ConfigHost::new(vec!["h".into()]);
        host.update((EntryType::LocalForward, "1".into()));
        host.update((EntryType::LocalForward, "2".into()));
        let all = host.all_entries();
        assert!(all.contains(&(EntryType::LocalForward, "1".into())));
        assert!(all.contains(&(EntryType::LocalForward, "2".into())));
    }

    #[test]
    fn test_apply_patterns() {
        // existing tests...
    }
}
