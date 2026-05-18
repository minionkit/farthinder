#[derive(Debug, Clone)]
pub struct Rules {
    min_age_hours: u64,
}

impl Rules {
    pub fn new(min_age_hours: u64) -> Self {
        Rules { min_age_hours }
    }

    pub fn min_age_hours(&self) -> u64 {
        self.min_age_hours
    }
}
