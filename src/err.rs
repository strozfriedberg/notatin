use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("An error has occurred in the Nom library: {}", detail)]
    Nom { detail: String },
    #[error("An error has occurred in the Winstructs library: {}", detail)]
    Winstructs { detail: String },
    #[error("An error has occurred while converting: {}", detail)]
    Conversion { detail: String },
    #[error("An error has occurred in StripPrefix: {}", detail)]
    StripPrefix { detail: String },
    #[error("An IO error has occurred: {}", detail)]
    Io { detail: String },
    #[error("An error has occurred: {}", detail)]
    Any { detail: String },
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for Error {
    fn from(_error: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        Error::Nom{ detail: "Nom parsing error".to_string()}
    }
}

impl From<winstructs::err::Error> for Error {
    fn from(error: winstructs::err::Error) -> Self {
        Error::Winstructs{ detail: format!("{:#?}", error.to_string()) }
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(error: std::array::TryFromSliceError) -> Self {
        println!("from(error: std::array::TryFromSliceError");
        Error::Conversion{ detail: format!("{:#?}", error.to_string()) }
    }
}

impl From<std::path::StripPrefixError> for Error {
    fn from(error: std::path::StripPrefixError) -> Self {
        println!("from(error: std::path::StripPrefixError");
        Error::StripPrefix{ detail: format!("{:#?}", error.to_string()) }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        println!("from(error: std::io::Error");
        Error::Io{ detail: format!("{:#?}", error.to_string()) }
    }
}
