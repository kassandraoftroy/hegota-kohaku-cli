//! Interactive terminal helpers: section headers, tables, and boxed text.

/// Blank line then `── title ──`.
pub fn print_section(title: &str) {
    println!();
    println!("── {title} ──");
}

/// Left-aligned columns sized to the widest header/cell. Two spaces between columns.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if headers.is_empty() {
        return;
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.chars().count());
            }
        }
    }
    print_row(headers.iter().copied(), &widths);
    for row in rows {
        print_row(row.iter().map(|s| s.as_str()), &widths);
    }
}

fn print_row<'a>(cells: impl Iterator<Item = &'a str>, widths: &[usize]) {
    let mut parts = Vec::with_capacity(widths.len());
    for (i, cell) in cells.enumerate() {
        let w = widths.get(i).copied().unwrap_or(0);
        parts.push(format!("{cell:<w$}"));
    }
    println!("{}", parts.join("  "));
}

/// Unicode light box around one or more content lines (e.g. a seed phrase).
pub fn print_box(text: &str) {
    let lines: Vec<&str> = if text.is_empty() {
        vec![""]
    } else {
        text.lines().collect()
    };
    let inner = lines
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0)
        .max(1);
    let top = format!("┌{}┐", "─".repeat(inner + 2));
    let bottom = format!("└{}┘", "─".repeat(inner + 2));
    println!("{top}");
    for line in lines {
        println!("│ {line:<inner$} │");
    }
    println!("{bottom}");
}

/// stderr progress bar: `label [####] pct%  done/total  last Xs`.
///
/// `start_block` adds `block N` when set (shielded-pool / hydrate).
pub fn block_sync_progress(
    label: &'static str,
    start_block: Option<u64>,
) -> impl Fn(u64, u64) + Send + Sync {
    use std::io::{IsTerminal, Write};
    use std::sync::atomic::{AtomicU8, Ordering};
    let last_pct = AtomicU8::new(255);
    let tick = std::sync::Mutex::new(std::time::Instant::now());
    move |done, total| {
        let last = tick
            .lock()
            .map(|mut tick| {
                let took = tick.elapsed();
                *tick = std::time::Instant::now();
                took
            })
            .unwrap_or_default();
        let total = total.max(1);
        let pct = u8::try_from((done.saturating_mul(100) / total).min(100)).unwrap_or(100);
        let prev = last_pct.swap(pct, Ordering::Relaxed);
        if prev == pct && last.as_millis() < 50 {
            return;
        }
        let stderr = std::io::stderr();
        if stderr.is_terminal() {
            let width = 28usize;
            let filled = usize::from(pct) * width / 100;
            let bar = format!("{}{}", "#".repeat(filled), "-".repeat(width - filled));
            let at = start_block.map(|start| format!("  block {}", start.saturating_add(done)));
            eprint!(
                "\r{label} [{bar}] {pct:>3}%  {done}/{total}{}  last {:.1}s",
                at.unwrap_or_default(),
                last.as_secs_f64()
            );
            let _ = stderr.lock().flush();
            if pct == 100 {
                eprintln!();
            }
        } else {
            eprintln!(
                "{label} {pct}%  {done}/{total}  last {:.1}s",
                last.as_secs_f64()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_widths_follow_widest_cell() {
        // Smoke: does not panic; exercise alignment path.
        print_table(
            &["Asset", "Amount"],
            &[
                vec!["ETH".into(), "1.0".into()],
                vec!["STABLE".into(), "1000000.0".into()],
            ],
        );
    }

    #[test]
    fn box_wraps_single_line() {
        print_box("alpha beta gamma");
    }
}
