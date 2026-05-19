use rich_rust::r#box::HEAVY;
use rich_rust::markup;
use rich_rust::prelude::*;
use rich_rust::renderables::PaddingDimensions;

use crate::registry::{Ecosystem, RegistryStats};

pub struct Printer {
    console: Console,
}

impl Printer {
    pub fn new() -> Self {
        Self {
            console: Console::builder().file(Box::new(std::io::stderr())).build(),
        }
    }

    pub fn banner(&self, ecosystem: Ecosystem) {
        let label = match ecosystem {
            Ecosystem::Javascript => "npm",
            Ecosystem::Python => "PyPI",
        };
        let content = format!("Protecting [bold cyan]{}[/]", label);
        self.styled_panel("Farthinder Active", "cyan", &content);
    }

    pub fn summary(&self, stats: &RegistryStats) {
        let mut lines = Vec::new();

        lines.push(format!(
            "[bold]{}[/] {} checked",
            stats.packages_checked,
            if stats.packages_checked == 1 { "package" } else { "packages" },
        ));

        if !stats.packages_quarantined.is_empty() {
            let total_versions: usize = stats
                .packages_quarantined
                .iter()
                .map(|p| p.quarantined_versions.len())
                .sum();
            lines.push(format!(
                "[bold blue]{}[/] versions quarantined across [bold blue]{}[/] {}",
                total_versions,
                stats.packages_quarantined.len(),
                if stats.packages_quarantined.len() == 1 { "package" } else { "packages" },
            ));
            for pkg in &stats.packages_quarantined {
                let summary = format_quarantined_versions(&pkg.quarantined_versions);
                lines.push(format!("[dim]  {} ({})[/]", pkg.name, summary));
            }
        }

        if !stats.downloads_blocked.is_empty() {
            lines.push(format!(
                "[bold red]{}[/] downloads blocked",
                stats.downloads_blocked.len()
            ));
            for item in &stats.downloads_blocked {
                lines.push(format!("[dim]  {}@{}[/]", item.package, item.version));
            }
        }

        if stats.connections_tunneled > 0 {
            lines.push(format!(
                "[dim]{} connections passed through[/]",
                stats.connections_tunneled
            ));
        }

        let border_color = if !stats.downloads_blocked.is_empty() {
            "red"
        } else if !stats.packages_quarantined.is_empty() {
            "blue"
        } else {
            "green"
        };

        self.styled_panel("Farthinder Summary", border_color, &lines.join("\n"));
    }

    fn styled_panel(&self, title: &str, border_color: &str, content: &str) {
        let styled = markup::render_or_plain(content);
        self.console.line();
        let panel = Panel::from_rich_text(&styled, self.console.width())
            .title_from_markup(format!("[bold]{title}[/]").as_str())
            .title_align(JustifyMethod::Left)
            .box_style(&HEAVY)
            .border_style(
                Style::new()
                    .bold()
                    .color(Color::parse(border_color).unwrap()),
            )
            .padding(PaddingDimensions::symmetric(0, 2));
        self.console.print_renderable(&panel);
        self.console.line();
    }
}

fn format_quarantined_versions(versions: &[String]) -> String {
    let mut sorted: Vec<&str> = versions.iter().map(|s| s.as_str()).collect();
    sorted.sort_unstable();
    let max_show = 3;
    if sorted.len() <= max_show {
        sorted.join(", ")
    } else {
        let shown: Vec<&str> = sorted.iter().take(max_show).copied().collect();
        format!("{}, and {} more", shown.join(", "), sorted.len() - max_show)
    }
}
