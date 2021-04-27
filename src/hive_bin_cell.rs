use core::fmt::Debug;
use nom::{
    IResult,    
    number::complete::le_i32
};
use std::convert::TryFrom;

pub trait HiveBinCell {
    fn signature(&self) -> [u8;2];
    fn size(&self) -> u32;
    fn name_lowercase(&self) -> Option<String>;
}

impl Debug for dyn HiveBinCell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let sig_string = String::from_utf8(self.signature().to_vec()).unwrap();
        write!(f, "HiveBinCell signature:{} size:{}", sig_string, self.size())
    }
}

impl Eq for dyn HiveBinCell {}

impl PartialEq for dyn HiveBinCell {
    fn eq(&self, other: &Self) -> bool {
        self.signature() == other.signature() &&
        self.size() == other.size()
    }
}

pub trait HiveBinCellSubKeyList {
    fn signature(&self) -> [u8;2];
    fn size(&self) -> u32;
    fn offsets(&self, hbin_offset: u32) -> Vec<u32>;
}

impl Debug for dyn HiveBinCellSubKeyList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let sig_string = String::from_utf8(self.signature().to_vec()).unwrap();
        write!(f, "HiveBinCellSubKeyList signature:{} size:{}", sig_string, self.size())
    }
}

impl PartialEq for dyn HiveBinCellSubKeyList {
    fn eq(&self, other: &Self) -> bool {
        self.signature() == other.signature() &&
        self.size() == other.size()
    }
}

impl Eq for dyn HiveBinCellSubKeyList {}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct HiveBinCellUnknown {
    pub size: u32,
    pub signature: [u8; 2],
    pub data: Vec<u8>
}

impl HiveBinCell for HiveBinCellUnknown {    
    fn size(&self) -> u32 {
        self.size
    }

    fn signature(&self) -> [u8;2] {
        self.signature
    }

    fn name_lowercase(&self) -> Option<String> {
        None
    }
}

pub fn parse_hive_bin_cell_other() -> impl Fn(&[u8]) -> IResult<&[u8], Box<dyn HiveBinCell>> {
    |input: &[u8]| {
        let (input, ret) = parse_hive_bin_cell_unknown_internal(input)?;
        Ok((
            input,
            Box::new(ret)
        ))
    }
 }

fn parse_hive_bin_cell_unknown_internal(input: &[u8]) -> IResult<&[u8], HiveBinCellUnknown> {
    let (input, size) = le_i32(input)?;
    let (input, signature) = take!(input, 2)?;
    
    let bytes_consumed: u32 = 6;
    let abs_size = size.abs() as u32;
    let (input, data) = take!(input, abs_size - bytes_consumed)?;

    Ok((
        input,
        HiveBinCellUnknown {
            size: abs_size,
            signature: <[u8; 2]>::try_from(signature).unwrap(),
            data: data.to_vec()
        },
    ))
}