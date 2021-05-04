use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to read WindowsTime")]
    FailedToReadWindowsTime { source: winstructs::err::Error },
    #[error("An error has occurred in the Winstructs library: {}", detail)]
    Winstructs { detail: String },
    #[error("An error has occurred while parsing: {}", detail)]
    Nom { detail: String },
    #[error("An error has occurred while converting: {}", detail)]
    Conversion { detail: String },
    #[error("An unexpected error has occurred: {}", detail)]
    Any { detail: String },
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for Error {
    fn from(error: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        Error::Nom{ detail: format!("{:#?}", error.to_string()) }
    }
}

impl From<winstructs::err::Error> for Error {
    fn from(error: winstructs::err::Error) -> Self {
        Error::Winstructs{ detail: format!("{:#?}", error.to_string()) }
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(error: std::array::TryFromSliceError) -> Self {
        Error::Conversion{ detail: format!("{:#?}", error.to_string()) }
    }
}

impl Error {
    pub fn failed_to_read_windows_time(source: winstructs::err::Error) -> Error {
        Error::FailedToReadWindowsTime { source }
    }
}
