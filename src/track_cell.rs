use nom::{named, alt, tag};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CellType {
    CellOther,
    CellKey,
    CellValue,
    CellSecurity,
    CellBigData,
    CellIndexRoot,
    CellHashLeaf,
    CellFastLeaf,
    CellIndexLeaf
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrackCell {
    pub file_offset_absolute: usize,
    pub cell_type: CellType,
    pub is_allocated: bool,
    pub is_used: bool,
    pub sequence_num: u32
}

impl TrackCell {
    pub(crate) fn read_cell_type(input: &[u8]) -> CellType {
        named!(cell_type<CellType>, alt!(
            tag!("nk")            => { |_| CellType::CellKey } |
            tag!("vk")            => { |_| CellType::CellValue } |
            tag!("sk")            => { |_| CellType::CellSecurity } |
            tag!("lf")            => { |_| CellType::CellFastLeaf } |
            tag!("li")            => { |_| CellType::CellIndexLeaf } |
            tag!("lh")            => { |_| CellType::CellHashLeaf } |
            tag!("ri")            => { |_| CellType::CellIndexRoot } |
            tag!("db")            => { |_| CellType::CellBigData }
        ));
        match cell_type(input) {
            Ok((_, cell_type)) => cell_type,
            Err(_) => CellType::CellOther
        }
    }
}