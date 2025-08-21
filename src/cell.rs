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

use nom::{branch::alt, bytes::complete::tag, combinator::map, IResult, Parser};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CellState {
    DeletedTransactionLog = -3,
    DeletedPrimaryFile = -2,
    DeletedPrimaryFileSlack = -1,
    Allocated = 0,
    ModifiedTransactionLog = 1,
    // All Deleted* values are < 0 for support of `is_deleted()`.
    // Make sure any new Deleted* values follow this pattern.
}

impl Default for CellState {
    fn default() -> Self {
        Self::Allocated
    }
}

impl CellState {
    pub fn is_deleted(self) -> bool {
        (self as i8) < 0
    }

    pub fn is_deleted_primary_file(self) -> bool {
        self == Self::DeletedPrimaryFile || self == Self::DeletedPrimaryFileSlack
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
    CellIndexLeaf,
}

impl CellType {
    pub(crate) fn read_cell_type(input: &[u8]) -> Self {
        fn cell_type(b: &[u8]) -> IResult<&[u8], CellType> {
            alt((
                map(tag("nk"), |_| CellType::CellKey),
                map(tag("vk"), |_| CellType::CellValue),
                map(tag("sk"), |_| CellType::CellSecurity),
                map(tag("lf"), |_| CellType::CellFastLeaf),
                map(tag("li"), |_| CellType::CellIndexLeaf),
                map(tag("lh"), |_| CellType::CellHashLeaf),
                map(tag("ri"), |_| CellType::CellIndexRoot),
                map(tag("db"), |_| CellType::CellBigData),
            ))
            .parse(b)
        }

        match cell_type(input) {
            Ok((_, cell_type)) => cell_type,
            Err(_) => CellType::CellOther,
        }
    }
}


pub trait Cell {
    fn get_file_offset_absolute(&self) -> usize;
    fn get_hash(&self) -> Option<blake3::Hash>;
    fn get_logs(&self) -> &crate::log::Logs;
    fn has_or_is_recovered(&self) -> bool;
}
