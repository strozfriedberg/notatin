use core::fmt::Debug;

pub trait Cell {
    fn size(&self) -> u32;
    fn lowercase(&self) -> Option<String>{
        None
    }
    fn is_key(&self) -> bool {
        false
    }
    fn is_key_root(&self) -> bool {
        false
    }
}

impl Debug for dyn Cell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cell {}, size:{}", self.lowercase().unwrap(), self.size())
    }
}

impl Eq for dyn Cell {}

impl PartialEq for dyn Cell {
    fn eq(&self, other: &Self) -> bool {
        self.size() == other.size() &&
        self.lowercase() == other.lowercase()
    }
}

pub trait CellSubKeyList {
    fn size(&self) -> u32;
    fn get_offset_list(&self, hbin_offset_absolute: u32) -> Vec<u32>;
}

impl Debug for dyn CellSubKeyList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CellSubKeyList size:{}", self.size())
    }
}

impl PartialEq for dyn CellSubKeyList {
    fn eq(&self, other: &Self) -> bool {
        self.size() == other.size() &&
        self.get_offset_list(0) == other.get_offset_list(0)
    }
}

impl Eq for dyn CellSubKeyList {}