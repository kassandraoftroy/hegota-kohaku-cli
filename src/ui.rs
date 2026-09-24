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
