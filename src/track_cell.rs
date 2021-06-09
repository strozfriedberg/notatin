use nom::{named, alt, tag};
use serde::Serialize;
use bitflags::bitflags;
use blake3::Hash;
use crate::impl_serialize_for_bitflags;
use crate::impl_flags_from_bits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrackHbin {
    pub file_offset_absolute: usize,
    pub size: usize,
    pub track_cells: Vec<TrackCell>
}

impl TrackHbin {
    pub(crate) fn find_hbin_mut(track_hbins: &mut Vec<Self>, file_offset_absolute: usize) -> Option<&mut Self> {
        let res = Self::find_hbin_search(track_hbins, file_offset_absolute);
        match res {
            Ok(index) => Some(&mut track_hbins[index as usize]),
            Err(_) => None
        }
    }

    pub(crate) fn find_hbin(track_hbins: &[Self], file_offset_absolute: usize) -> Option<&Self> {
        let res = Self::find_hbin_search(track_hbins, file_offset_absolute);
        match res {
            Ok(index) => Some(&track_hbins[index]),
            Err(_) => None
        }
    }

    pub(crate) fn find_hbins_index(track_hbins: &mut Vec<Self>, file_offset_absolute: usize, file_offset_absolute_end: usize) -> Vec<usize> {
        let mut hbins = Vec::new();
        let mut bytes_needed: isize = (file_offset_absolute_end - file_offset_absolute) as isize;
        let res = Self::find_hbin_search(track_hbins, file_offset_absolute);
        match res {
            Ok(mut index) => {
                while bytes_needed > 0 {
                    let hbin = &track_hbins[index];
                    hbins.push(index);
                    bytes_needed -= hbin.size as isize;
                    index += 1;
                }
                hbins
            },
            Err(_) => hbins
        }
    }

    fn find_hbin_search(track_hbins: &[Self], file_offset_absolute: usize) -> Result<usize, usize> {
        track_hbins.binary_search_by(
            |track_hbin| {
                if track_hbin.file_offset_absolute > file_offset_absolute {
                    std::cmp::Ordering::Greater
                }
                else if track_hbin.file_offset_absolute + track_hbin.size < file_offset_absolute {
                    std::cmp::Ordering::Less
                }
                else {
                    std::cmp::Ordering::Equal
                }
            }
        )
    }
}

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

bitflags! {
    #[allow(non_camel_case_types)]
    #[derive(Default)]
    pub struct TrackCellFlags: u16 {
        const TRACK_CELL_ALLOCATED   = 0x0001; // The cell is allocated (size < 0)
        const TRACK_CELL_USED        = 0x0002; // The cell is used
        const TRACK_CELL_OVERWRITTEN = 0x0004; // The cell is overwritten by a transaction log section
        const TRACK_CELL_NEW         = 0x0008; // (Used during transaction log analysis) The cell is new or updated from a tranasction log
    }
}
impl_serialize_for_bitflags! { TrackCellFlags }
impl_flags_from_bits! { TrackCellFlags, u16 }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrackCell {
    pub file_offset_absolute: usize,
    pub cell_type: CellType,
    pub cell_flags: TrackCellFlags,
    pub sequence_num: u32,
    pub hash: Hash
}

impl TrackCell {
    pub(crate) fn sort(track_cells: &mut Vec<Self>) {
        track_cells.sort_by(
            |a, b| {
                let cmp = a.file_offset_absolute.cmp(&b.file_offset_absolute);
                if cmp == std::cmp::Ordering::Equal {
                    let cmp = a.sequence_num.cmp(&b.sequence_num);
                    if cmp == std::cmp::Ordering::Equal && a.cell_flags.contains(TrackCellFlags::TRACK_CELL_OVERWRITTEN) {
                        std::cmp::Ordering::Less
                    }
                    else {
                        cmp
                    }
                }
                else {
                    cmp
                }
            }
        )
    }

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