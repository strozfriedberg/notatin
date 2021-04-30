use core::fmt::Debug;
use nom::{
    IResult,
    number::complete::le_i32
};
use std::convert::TryFrom;
use serde::Serialize;

pub trait Cell {
    fn size(&self) -> u32;
    fn name_lowercase(&self) -> Option<String>;
}

impl Debug for dyn Cell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cell {}, size:{}", self.name_lowercase().unwrap(), self.size())
    }
}

impl Eq for dyn Cell {}

impl PartialEq for dyn Cell {
    fn eq(&self, other: &Self) -> bool {
        self.size() == other.size()&&
        self.name_lowercase() == other.name_lowercase()
    }
}
pub trait CellSubKeyList {
    fn size(&self) -> u32;
    fn offsets(&self, hbin_offset: u32) -> Vec<u32>;
}

impl Debug for dyn CellSubKeyList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CellSubKeyList size:{}", self.size())
    }
}

impl PartialEq for dyn CellSubKeyList {
    fn eq(&self, other: &Self) -> bool {
        self.size() == other.size() &&
        self.offsets(0) == other.offsets(0)
    }
}

impl Eq for dyn CellSubKeyList {}

#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct CellUnknown {
    pub size: u32,
    pub signature: [u8; 2],
    pub data: Vec<u8>
}

impl Cell for CellUnknown {
    fn size(&self) -> u32 {
        self.size
    }

    fn name_lowercase(&self) -> Option<String> {
        None
    }
}

pub fn parse_cell_other() -> impl Fn(&[u8]) -> IResult<&[u8], Box<dyn Cell>> {
    |input: &[u8]| {
        let (input, ret) = parse_cell_unknown_internal(input)?;
        Ok((
            input,
            Box::new(ret)
        ))
    }
 }

fn parse_cell_unknown_internal(input: &[u8]) -> IResult<&[u8], CellUnknown> {
    let start_pos = input.as_ptr() as usize;
    let (input, size) = le_i32(input)?;
    let (input, signature) = take!(input, 2)?;
    let size_abs = size.abs() as u32;
    let (input, data) = take!(input, size_abs - (input.as_ptr() as usize - start_pos) as u32)?;

    Ok((
        input,
        CellUnknown {
            size: size_abs,
            signature: <[u8; 2]>::try_from(signature).unwrap_or_default(),
            data: data.to_vec()
        },
    ))
}