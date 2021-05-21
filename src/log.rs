use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Logs {
    logs: Option<Vec<Log>>
}

impl Logs {
    fn new() -> Self {
        Logs {
            logs: None
        }
    }

    pub(crate) fn add<T: ToString>(&mut self, code: LogCode, text: &T) {
        self.add_internal(
            Log {
                code,
                text: text.to_string()
            }
        );
    }

    fn add_internal(&mut self, warning: Log) {
        match &mut self.logs {
            Some(logs) => logs.push(warning),
            None => self.logs = Some(vec![warning])
        }
    }

    pub fn get(&self) -> Option<&Vec<Log>> {
        self.logs.as_ref()
    }
}

impl Default for Logs {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum LogCode {
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
pub struct Log {
    pub code: LogCode,
    pub text: String
}