use std::io::{BufWriter, Write};
use std::fmt;
use serde::Serialize;
use crate::err::Error;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Logs {
    logs: Option<Vec<Log>>
}

impl Logs {
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

    pub(crate) fn get_option(self) -> Option<Self> {
        if self.logs.is_none() {
            None
        }
        else {
            Some(self)
        }
    }

    pub(crate) fn prepend_all(&mut self, prefix: &str) {
        if let Some(logs) = &mut self.logs {
            for log in logs {
                log.text = format!("{}{}", prefix, log.text)
            }
        }
    }

    pub(crate) fn extend(&mut self, additional: Self) {
        match &mut self.logs {
            Some(logs) => logs.extend(additional.logs.unwrap_or_default()),
            None => self.logs = Some(additional.logs.unwrap_or_default())
        }
    }

    pub fn write<W: Write>(&self, output: W) -> Result<(), Error> {
        let mut writer = BufWriter::new(output);
        if let Some(logs) = &self.logs {
            for log in logs {
                writeln!(
                    &mut writer,
                    "{:?} {}",
                    log.code,
                    log.text
                )?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Logs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.get_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum LogCode {
    WarningOther,
    WarningNom,
    WarningConversion,
    WarningContent,
    WarningBigDataContent,
    WarningUnrecognizedBitflag,
    WarningTransactionLog,
    WarningIterator,
    WarningBaseBlock,
    WarningParse,
    Info
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Log {
    pub code: LogCode,
    pub text: String
}