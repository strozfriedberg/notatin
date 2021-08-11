/*
 * Copyright 2021 Aon Cyber Solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
        Error::Nom {
            detail: "Nom parsing error".to_string(),
        }
    }
}

impl From<winstructs::err::Error> for Error {
    fn from(error: winstructs::err::Error) -> Self {
        Error::Winstructs {
            detail: format!("{:#?}", error.to_string()),
        }
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(error: std::array::TryFromSliceError) -> Self {
        Error::Conversion {
            detail: format!("{:#?}", error.to_string()),
        }
    }
}

impl From<std::path::StripPrefixError> for Error {
    fn from(error: std::path::StripPrefixError) -> Self {
        Error::StripPrefix {
            detail: format!("{:#?}", error.to_string()),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io {
            detail: format!("{:#?}", error.to_string()),
        }
    }
}
