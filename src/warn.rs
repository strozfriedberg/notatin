use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Warnings {
    parse_warnings: Option<Vec<Warning>>
}

impl Warnings {
    fn new() -> Self {
        Warnings {
            parse_warnings: None
        }
    }

    pub(crate) fn add<T: ToString>(&mut self, code: WarningCode, text: &T) {
        self.add_internal(
            Warning {
                code,
                text: text.to_string()
            }
        );
    }

    fn add_internal(&mut self, warning: Warning) {
        match &mut self.parse_warnings {
            Some(parse_warnings) => parse_warnings.push(warning),
            None => self.parse_warnings = Some(vec![warning])
        }
    }

    pub fn get(&self) -> Option<&Vec<Warning>> {
        self.parse_warnings.as_ref()
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
    WarningTransactionLog,
    WarningOther,
    Info
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Warning {
    pub code: WarningCode,
    pub text: String
}