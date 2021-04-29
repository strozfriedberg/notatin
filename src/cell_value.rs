use serde::{ser, Serialize};
use crate::util;

#[derive(Debug, Eq, PartialEq, Serialize)]
pub enum CellValue {
    ValueNone,
    #[serde(serialize_with = "data_as_hex")]
    ValueBinary(Vec<u8>),
    ValueString(String),
    ValueMultiString(Vec<String>),
    ValueU32(u32),
    ValueI32(i32),
    ValueU64(u64),
    ValueI64(i64)
}

fn data_as_hex<S: ser::Serializer>(x: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&util::to_hex_string(x))
}