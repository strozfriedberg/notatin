use thiserror::Error;

pub trait ParseWarnings {
    fn add_warning(&mut self, warning: String);
    fn get_warnings(&self) -> &Vec<String>;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to read WindowsTime")]
    FailedToReadWindowsTime { source: winstructs::err::Error },
    #[error("An error has occurred while parsing: {}", detail)]
    Nom { detail: String },
    #[error("An unexpected error has occurred: {}", detail)]
    Any { detail: String },
}

impl Error {
    pub fn failed_to_read_windows_time(source: winstructs::err::Error) -> Error {
        Error::FailedToReadWindowsTime { source }
    }
}
