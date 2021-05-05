use serde::Serialize;
use crate::util;

#[derive(Debug, Eq, PartialEq, Serialize)]
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