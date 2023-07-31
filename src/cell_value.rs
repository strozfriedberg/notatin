/*
 * Copyright 2023 Aon Cyber Solutions
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

use crate::field_serializers;
use crate::log::{LogCode, Logs};
use crate::util;
use serde::Serialize;
use strum_macros::IntoStaticStr;

#[derive(Clone, Debug, Eq, IntoStaticStr, PartialEq, Serialize)]
pub enum CellValue {
    None,
    #[serde(serialize_with = "field_serializers::field_data_as_hex")]
    Binary(Vec<u8>),
    String(String),
    MultiString(Vec<String>),
    U32(u32),
    I32(i32),
    U64(u64),
    I64(i64),
    Error,
}

impl CellValue {
    pub fn get_type(&self) -> String {
        // take advantage of IntoStaticStr which will return the enum type as a str
        let value_type: &str = self.into();
        value_type.to_string()
    }
}

impl std::fmt::Display for CellValue {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Binary(v) => write!(f, "{}", util::to_hex_string(v)),
            Self::String(v) => write!(f, "{}", v),
            Self::MultiString(v) => write!(f, "{:?}", v),
            Self::U32(v) => write!(f, "{}", v),
            Self::I32(v) => write!(f, "{}", v),
            Self::U64(v) => write!(f, "{}", v),
            Self::I64(v) => write!(f, "{}", v),
            _ => write!(f, ""),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum DecodeFormat {
    Lznt1,
    Rot13,
    Utf16,
    Utf16Multiple,
}

impl DecodeFormat {
    pub(crate) fn decode(
        &self,
        cell_value: &CellValue,
        offset: usize,
    ) -> (CellValue, Option<Logs>) {
        match self {
            DecodeFormat::Lznt1 | DecodeFormat::Utf16 | DecodeFormat::Utf16Multiple => {
                if let CellValue::Binary(b) = cell_value {
                    self.decode_bytes(b, offset)
                } else {
                    let mut warnings = Logs::default();
                    warnings.add(
                        LogCode::WarningConversion,
                        &"Unsupported CellValue/format pair",
                    );
                    (CellValue::Error, Some(warnings))
                }
            }
            DecodeFormat::Rot13 => Self::decode_string(cell_value),
        }
    }

    fn decode_bytes(&self, value_bytes: &[u8], offset: usize) -> (CellValue, Option<Logs>) {
        let mut warnings = Logs::default();
        match self {
            DecodeFormat::Lznt1 => {
                match util::decode_lznt1(value_bytes, offset, value_bytes.len()) {
                    Ok(decompressed) => (CellValue::Binary(decompressed), None),
                    _ => {
                        warnings.add(LogCode::WarningConversion, &"Error decompressing lznt1");
                        (CellValue::Error, Some(warnings))
                    }
                }
            }
            DecodeFormat::Utf16 => match value_bytes.get(offset..) {
                Some(slice) => {
                    let s = util::from_utf16_le_string(
                        slice,
                        value_bytes.len() - offset,
                        &mut warnings,
                        "decode_content",
                    );
                    (CellValue::String(s), warnings.get_option())
                }
                None => {
                    warnings.add(LogCode::WarningConversion, &"Buffer too small");
                    (CellValue::Error, Some(warnings))
                }
            },
            DecodeFormat::Utf16Multiple => match value_bytes.get(offset..) {
                Some(slice) => {
                    let m = util::from_utf16_le_strings(
                        slice,
                        value_bytes.len(),
                        &mut warnings,
                        "decode_content",
                    );
                    (CellValue::MultiString(m), warnings.get_option())
                }
                None => {
                    warnings.add(LogCode::WarningConversion, &"Buffer too small");
                    (CellValue::Error, Some(warnings))
                }
            },
            _ => (CellValue::None, warnings.get_option()),
        }
    }

    fn decode_string(cell_value: &CellValue) -> (CellValue, Option<Logs>) {
        match cell_value {
            CellValue::String(s) => (CellValue::String(util::decode_rot13(s)), None),
            CellValue::MultiString(m) => {
                let mut decoded = vec![];
                for s in m {
                    decoded.push(util::decode_rot13(s));
                }
                (CellValue::MultiString(decoded), None)
            }
            _ => {
                let mut warnings = Logs::default();
                warnings.add(
                    LogCode::WarningConversion,
                    &"Unsupported CellValue/format pair",
                );
                (CellValue::Error, Some(warnings))
            }
        }
    }
}

impl DecodableValue for CellValue {
    fn decode_content(&self, format: &DecodeFormat, offset: usize) -> (CellValue, Option<Logs>) {
        format.decode(self, offset)
    }
}

pub trait DecodableValue {
    fn decode_content(&self, format: &DecodeFormat, offset: usize) -> (CellValue, Option<Logs>);
}
