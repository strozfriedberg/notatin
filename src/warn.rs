use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Warnings {
    parse_warnings: Option<Vec<Warning>>
}

impl Warnings {
    pub fn new() -> Self {
        Warnings {
            parse_warnings: None
        }
    }

    pub fn add_warning(&mut self, warning: Warning) {
        match &mut self.parse_warnings {
            Some(parse_warnings) => parse_warnings.push(warning),
            None => self.parse_warnings = Some(vec![warning])
        }
    }

    pub fn get_warnings(&self) -> &Option<Vec<Warning>> {
        &self.parse_warnings
    }
}

impl Default for Warnings {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum WarningCode {
    WarningNom,
    WarningConversion,
    WarningOther
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Warning {
    pub warning_code: WarningCode,
    pub warning_text: String
}