//! Log formatting, same setup as RustHound-CE.
//! ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/main.rs

use colored::Colorize;
use env_logger::Builder;
use std::io::Write;

/// Set the level from -v / -q. Other crates stay at ERROR.
pub fn init(verbose: log::LevelFilter, quiet: bool) {
    let level = if quiet { log::LevelFilter::Off } else { verbose };

    Builder::new()
        .format(|buf, record| {
            let prefix = match record.level() {
                log::Level::Error => "[ERROR]".red().bold().to_string(),
                log::Level::Warn  => "[WARN-]".yellow().bold().to_string(),
                log::Level::Info  => "[INFO-]".green().bold().to_string(),
                log::Level::Debug => "[DEBUG]".cyan().to_string(),
                log::Level::Trace => "[TRACE]".blue().to_string(),
            };
            writeln!(buf, "{} {}", prefix, record.args())
        })
        .filter(Some("localgroups_rs"), level)
        .filter_level(log::LevelFilter::Error)
        .init();
}