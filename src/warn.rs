use serde::Serialize;
use crate::err::Error;

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

    pub fn add_warning(&mut self, code: WarningCode, text: String) {
        self.add_warning_internal(
            Warning {
                code: code,
                text: text
            }
        );
    }

    fn add_warning_internal(&mut self, warning: Warning) {
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
    WarningContent,
    WarningBigDataContent,
    WarningUnrecognizedBitflag,
    WarningOther
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Warning {
    pub code: WarningCode,
    pub text: String
}