use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("An error has occurred in the Nom library: {}", detail)]
    Nom { detail: String },
    #[error("An error has occurred in the Winstructs library: {}", detail)]
    Winstructs { detail: String },
    #[error("An error has occurred while converting: {}", detail)]
    Conversion { detail: String },
    #[error("An error has occurred in StripPrefix: {}", detail)]
    StripPrefix { detail: String },
    #[error("An error has occurred: {}", detail)]
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

impl From<std::path::StripPrefixError> for Error {
    fn from(error: std::path::StripPrefixError) -> Self {
        Error::StripPrefix{ detail: format!("{:#?}", error.to_string()) }
    }
}
