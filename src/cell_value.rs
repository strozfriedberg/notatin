use serde::Serialize;
use crate::util;
use crate::log::{LogCode, Logs};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum CellValue {
    ValueNone,
    #[serde(serialize_with = "util::data_as_hex")]
    ValueBinary(Vec<u8>),
    ValueString(String),
    ValueMultiString(Vec<String>),
    ValueU32(u32),
    ValueI32(i32),
    ValueU64(u64),
    ValueI64(i64),
    ValueError
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum CellState {
    Allocated,
    ModifiedTransactionLog,
    DeletedTransactionLog,
    DeletedPrimaryFile
}

pub enum DecodeFormat {
    Lznt1,
    Rot13,
    Utf16,
    Utf16Multiple
}

impl DecodableValue for CellValue {
    fn decode_content(&self, format: DecodeFormat, offset: usize) -> (CellValue, Option<Logs>) {
        match format {
            DecodeFormat::Lznt1 |
            DecodeFormat::Utf16 |
            DecodeFormat::Utf16Multiple => {
                if let CellValue::ValueBinary(b) = self {
                    DecodableValue::decode_bytes(b, format, offset)
                }
                else {
                    let mut warnings = Logs::default();
                    warnings.add(LogCode::WarningConversion, &"Unsupported CellValue/format pair");
                    (CellValue::ValueError, Some(warnings))
                }
            },
            DecodeFormat::Rot13 => DecodableValue::decode_string(self)
        }
    }
}

pub trait DecodableValue {
    fn decode_content(&self, format: DecodeFormat, offset: usize) -> (CellValue, Option<Logs>);
}

impl dyn DecodableValue {
    pub(crate) fn decode_string(cell_value: &CellValue) -> (CellValue, Option<Logs>) {
        match cell_value {
            CellValue::ValueString(s) => (CellValue::ValueString(util::decode_rot13(&s)), None),
            CellValue::ValueMultiString(m) => {
                let mut decoded = vec![];
                for s in m {
                    decoded.push(util::decode_rot13(&s));
                }
                (CellValue::ValueMultiString(decoded), None)
            },
            _ => {
                let mut warnings = Logs::default();
                warnings.add(LogCode::WarningConversion, &"Unsupported CellValue/format pair");
                (CellValue::ValueError, Some(warnings))
            }
        }
    }

    pub(crate) fn decode_bytes(value_bytes: &[u8], format: DecodeFormat, offset: usize) -> (CellValue, Option<Logs>) {
        let mut warnings = Logs::default();
        match format {
            DecodeFormat::Lznt1 => {
                match util::decode_lznt1(value_bytes, offset, value_bytes.len()) {
                    Ok(decompressed) => (CellValue::ValueBinary(decompressed), None),
                    _ => {
                        warnings.add(LogCode::WarningConversion, &"Error decompressing lznt1");
                        (CellValue::ValueError, Some(warnings))
                    }
                }
            },
            DecodeFormat::Utf16 => {
                let s = util::from_utf16_le_string(&value_bytes[offset..], value_bytes.len(), &mut warnings, &"decode_content");
                (CellValue::ValueString(s), warnings.get_option())
            }
            DecodeFormat::Utf16Multiple => {
                let m = util::from_utf16_le_strings(&value_bytes[offset..], value_bytes.len(), &mut warnings, &"decode_content");
                (CellValue::ValueMultiString(m), warnings.get_option())
            },
            _ => (CellValue::ValueNone, warnings.get_option())
        }
    }
}