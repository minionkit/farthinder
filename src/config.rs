use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default = "default_min_age_hours")]
    pub min_age_hours: u64,
}

fn default_min_age_hours() -> u64 {
    48
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

pub fn data_dir() -> anyhow::Result<std::path::PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "farthinder")
        .ok_or_else(|| anyhow::anyhow!("cannot determine data directory"))?;
    let dir = dirs.data_dir().to_path_buf();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
