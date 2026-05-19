use serde::Deserialize;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct AppConfig {
    #[serde(default = "default_min_age_hours")]
    pub min_age_hours: u32,
    #[serde(default = "default_true")]
    pub sandbox_required: bool,
}

fn default_min_age_hours() -> u32 {
    48
}

fn default_true() -> bool {
    true
}

pub fn load() -> anyhow::Result<AppConfig> {
    use figment::Figment;
    use figment::providers::{Env, Format, Toml};

    let mut figment = Figment::new();

    if let Some(dirs) = directories::ProjectDirs::from("", "", "farthinder") {
        let path = dirs.config_dir().join("config.toml");
        if path.exists() {
            figment = figment.merge(Toml::file(path));
        }
    }

    let config: AppConfig = figment.merge(Env::prefixed("FARTHINDER_")).extract()?;
    Ok(config)
}
