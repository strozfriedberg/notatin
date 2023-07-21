use std::convert::TryInto;

macro_rules! BLOCK {
    ($a:ident, $b:ident) => {
        $b ^= $a;
        $a = $a.rotate_left(20);
        $a = $a.wrapping_add($b);
        $b = $b.rotate_left(9);
        $b ^= $a;
        $a = $a.rotate_left(27);
        $a = $a.wrapping_add($b);
        $b = $b.rotate_left(19);
    };
}

pub(crate) fn marvin32(seed: u64, data: &[u8], mut dlen: usize) -> u64 {
    let mut s0: u32 = (seed & 0xFFFFFFFF) as u32;
    let mut s1: u32 = (seed >> 32) as u32;

    let mut i = 0;

    while dlen > 3 {
        s0 = s0.wrapping_add(u32::from_le_bytes(data[i..i+4].try_into().unwrap()));
        BLOCK!(s0, s1);
        i += 4;
        dlen -= 4;
    }

    s0 = s0.wrapping_add(match dlen {
        0 => 0x80,
        1 => 0x8000 | (data[i] as u32),
        2 => 0x800000 | (u16::from_le_bytes(data[i..i+2].try_into().unwrap()) as u32),
        3 => 0x80000000 | ((data[i+2] as u32) << 16) | (u16::from_le_bytes(data[i..i+2].try_into().unwrap()) as u32),
        _ => unreachable!()
    });

    BLOCK!(s0, s1);
    BLOCK!(s0, s1);

    (s0 as u64) | ((s1 as u64) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marvin32() {
        let seed_1: u64 = 0x4FB61A001BDBCC;
        let seed_2: u64 = 0x804FB61A001BDBCC;
        let seed_3: u64 = 0x804FB61A801BDBCC;

        let data_0: [u8; 0] = [];
        let data_1 = [ 0xAF ];
        let data_2 = [ 0xE7, 0x0F ];
        let data_3 = [ 0x37, 0xF4, 0x95 ];
        let data_4 = [ 0x86, 0x42, 0xDC, 0x59 ];
        let data_5 = [ 0x15, 0x3F, 0xB7, 0x98, 0x26 ];
        let data_6 = [ 0x09, 0x32, 0xE6, 0x24, 0x6C, 0x47 ];
        let data_7 = [ 0xAB, 0x42, 0x7E, 0xA8, 0xD1, 0x0F, 0xC7 ];

        assert_eq!(0x30ED35C100CD3C7D, marvin32(seed_1, &data_0, 0));
        assert_eq!(0x48E73FC77D75DDC1, marvin32(seed_1, &data_1, 1));
        assert_eq!(0xB5F6E1FC485DBFF8, marvin32(seed_1, &data_2, 2));
        assert_eq!(0xF0B07C789B8CF7E8, marvin32(seed_1, &data_3, 3));
        assert_eq!(0x7008F2E87E9CF556, marvin32(seed_1, &data_4, 4));
        assert_eq!(0xE6C08C6DA2AFA997, marvin32(seed_1, &data_5, 5));
        assert_eq!(0x6F04BF1A5EA24060, marvin32(seed_1, &data_6, 6));
        assert_eq!(0xE11847E4F0678C41, marvin32(seed_1, &data_7, 7));
        assert_eq!(0x10A9D5D3996FD65D, marvin32(seed_2, &data_0, 0));
        assert_eq!(0x68201F91960EBF91, marvin32(seed_2, &data_1, 1));
        assert_eq!(0x64B581631F6AB378, marvin32(seed_2, &data_2, 2));
        assert_eq!(0xE1F2DFA6E5131408, marvin32(seed_2, &data_3, 3));
        assert_eq!(0x36289D9654FB49F6, marvin32(seed_2, &data_4, 4));
        assert_eq!(0x0A06114B13464DBD, marvin32(seed_2, &data_5, 5));
        assert_eq!(0xD6DD5E40AD1BC2ED, marvin32(seed_2, &data_6, 6));
        assert_eq!(0xE203987DBA252FB3, marvin32(seed_2, &data_7, 7));
        assert_eq!(0xA37FB0DA2ECAE06C, marvin32(seed_3, &[ 0x00 ], 1));
        assert_eq!(0xFECEF370701AE054, marvin32(seed_3, &[ 0xFF ], 1));
        assert_eq!(0xA638E75700048880, marvin32(seed_3, &[ 0x00, 0xFF ], 2));
        assert_eq!(0xBDFB46D969730E2A, marvin32(seed_3, &[ 0xFF, 0x00 ], 2));
        assert_eq!(0x9D8577C0FE0D30BF, marvin32(seed_3, &[ 0xFF, 0x00, 0xFF ], 3));
        assert_eq!(0x4F9FBDDE15099497, marvin32(seed_3, &[ 0x00, 0xFF, 0x00 ], 3));
        assert_eq!(0x24EAA279D9A529CA, marvin32(seed_3, &[ 0x00, 0xFF, 0x00, 0xFF ], 4));
        assert_eq!(0xD3BEC7726B057943, marvin32(seed_3, &[ 0xFF, 0x00, 0xFF, 0x00 ], 4));
        assert_eq!(0x920B62BBCA3E0B72, marvin32(seed_3, &[ 0xFF, 0x00, 0xFF, 0x00, 0xFF ], 5));
        assert_eq!(0x1D7DDF9DFDF3C1BF, marvin32(seed_3, &[ 0x00, 0xFF, 0x00, 0xFF, 0x00 ], 5));
        assert_eq!(0xEC21276A17E821A5, marvin32(seed_3, &[ 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF ], 6));
        assert_eq!(0x6911A53CA8C12254, marvin32(seed_3, &[ 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00 ], 6));
        assert_eq!(0xFDFD187B1D3CE784, marvin32(seed_3, &[ 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF ], 7));
        assert_eq!(0x71876F2EFB1B0EE8, marvin32(seed_3, &[ 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00 ], 7));
    }
}
