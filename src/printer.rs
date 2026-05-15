use rich_rust::r#box::HEAVY;
use rich_rust::markup;
use rich_rust::prelude::*;
use rich_rust::renderables::PaddingDimensions;

use crate::proxy::ProxyStats;
use crate::registry::Ecosystem;

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
        let text = format!("Watching [bold cyan]{}[/] traffic", label);
        let styled = markup::render_or_plain(&text);
        self.console.line();
        let panel = Panel::from_rich_text(&styled, self.console.width())
            .title_from_markup("[bold]Farthinder[/]")
            .title_align(JustifyMethod::Left)
            .box_style(&HEAVY)
            .border_style(Style::new().bold().color(Color::parse("cyan").unwrap()))
            .padding(PaddingDimensions::symmetric(0, 2));
        self.console.print_renderable(&panel);
        self.console.line();
    }

    pub fn summary(&self, stats: &ProxyStats) {
        let mut lines = Vec::new();

        lines.push(format!(
            "[bold]{}[/] connections intercepted",
            stats.connections_intercepted
        ));
        lines.push(format!(
            "[bold]{}[/] requests inspected",
            stats.requests_inspected
        ));

        if !stats.versions_suppressed.is_empty() {
            lines.push(format!(
                "[bold yellow]{}[/] versions suppressed",
                stats.versions_suppressed.len()
            ));
            for item in &stats.versions_suppressed {
                lines.push(format!("[dim]  {}@{}[/]", item.package, item.version));
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

        let content = lines.join("\n");
        let styled = markup::render_or_plain(&content);
        let border_color = if !stats.downloads_blocked.is_empty() {
            "red"
        } else if !stats.versions_suppressed.is_empty() {
            "yellow"
        } else {
            "green"
        };
        self.console.line();
        let panel = Panel::from_rich_text(&styled, self.console.width())
            .title_from_markup("[bold]Farthinder Summary[/]")
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
