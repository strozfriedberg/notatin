//use std::error;
use thiserror::Error;
use serde::Serialize;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to read WindowsTime")]
    FailedToReadWindowsTime { source: winstructs::err::Error },
    #[error("An error has occurred while parsing: {}", detail)]
    Nom { detail: String },
    #[error("An unexpected error has occurred: {}", detail)]
    Any { detail: String },
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for Error {
    fn from(error: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        Error::Nom{ detail: format!("{:#?}", error.to_string()) }
    }
}

impl Error {
    pub fn failed_to_read_windows_time(source: winstructs::err::Error) -> Error {
        Error::FailedToReadWindowsTime { source }
    }
}
