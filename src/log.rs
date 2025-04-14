pub fn log_error(message: &str) {
    use chrono::Local;
    use std::fs::OpenOptions;
    use std::io::Write;

    // Get log file path in user's home directory
    let home_dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let log_path = home_dir.join(".sshs_error.log");

    // Append to log file with timestamp
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        if let Err(_) = writeln!(file, "[{}] {}", timestamp, message) {
            // If we can't log to the file, there's not much we can do at this point
            // In a production app, you might want to consider other fallback mechanisms
        }
    }
}
