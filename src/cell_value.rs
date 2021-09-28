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

use crate::log::{LogCode, Logs};
use crate::util;
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum CellValue {
    ValueNone,
    #[serde(serialize_with = "util::field_data_as_hex")]
    ValueBinary(Vec<u8>),
    ValueString(String),
    ValueMultiString(Vec<String>),
    ValueU32(u32),
    ValueI32(i32),
    ValueU64(u64),
    ValueI64(i64),
    ValueError,
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
                if let CellValue::ValueBinary(b) = cell_value {
                    self.decode_bytes(b, offset)
                } else {
                    let mut warnings = Logs::default();
                    warnings.add(
                        LogCode::WarningConversion,
                        &"Unsupported CellValue/format pair",
                    );
                    (CellValue::ValueError, Some(warnings))
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
                    Ok(decompressed) => (CellValue::ValueBinary(decompressed), None),
                    _ => {
                        warnings.add(LogCode::WarningConversion, &"Error decompressing lznt1");
                        (CellValue::ValueError, Some(warnings))
                    }
                }
            }
            DecodeFormat::Utf16 => {
                let s = util::from_utf16_le_string(
                    &value_bytes[offset..],
                    value_bytes.len() - offset,
                    &mut warnings,
                    "decode_content",
                );
                (CellValue::ValueString(s), warnings.get_option())
            }
            DecodeFormat::Utf16Multiple => {
                let m = util::from_utf16_le_strings(
                    &value_bytes[offset..],
                    value_bytes.len(),
                    &mut warnings,
                    "decode_content",
                );
                (CellValue::ValueMultiString(m), warnings.get_option())
            }
            _ => (CellValue::ValueNone, warnings.get_option()),
        }
    }

    fn decode_string(cell_value: &CellValue) -> (CellValue, Option<Logs>) {
        match cell_value {
            CellValue::ValueString(s) => (CellValue::ValueString(util::decode_rot13(s)), None),
            CellValue::ValueMultiString(m) => {
                let mut decoded = vec![];
                for s in m {
                    decoded.push(util::decode_rot13(s));
                }
                (CellValue::ValueMultiString(decoded), None)
            }
            _ => {
                let mut warnings = Logs::default();
                warnings.add(
                    LogCode::WarningConversion,
                    &"Unsupported CellValue/format pair",
                );
                (CellValue::ValueError, Some(warnings))
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
