#[derive(Debug, Clone)]
pub struct Rules {
    min_age_hours: u32,
}

impl Rules {
    pub fn new(min_age_hours: u32) -> Self {
        Rules { min_age_hours }
    }

    pub fn min_age_hours(&self) -> u32 {
        self.min_age_hours
    }
}
