use std::convert::TryInto;
// ported from https://github.com/dotnet/coreclr/blob/e2bcca7d9d0e36510eaba9b1028e16a5de39cee9/src/System.Private.CoreLib/shared/System/Marvin.cs

/// Computes a 64-hash using the Marvin algorithm.
pub fn compute_hash(data: &[u8], count: u32, seed: u64) -> u64 {
    let mut ucount = count;
    let mut p0 = seed as u32;
    let mut p1 = (seed >> 32) as u32;

    let mut byte_offset = 0;

    while ucount >= 8 {
        p0 += data[byte_offset] as u32;//Unsafe.As<byte, uint>(ref Unsafe.Add(ref data, byteOffset));
        let res = block(p0, p1);
        p0 = res.0;
        p1 = res.1;

        p0 += data[byte_offset + 4] as u32;//Unsafe.As<byte, uint>(ref Unsafe.Add(ref data, byteOffset + 4));
        let res = block(p0, p1);
        p0 = res.0;
        p1 = res.1;

        byte_offset += 8;
        ucount -= 8;
    }

    /*match ucount {
        4 | 0 => {
            if ucount == 4 {
                p0 += data[byte_offset] as u32;//Unsafe.As<byte, uint>(ref Unsafe.Add(ref data, byteOffset));
                let res = block(p0, p1);
                p0 = res.0;
                p1 = res.1;
            }
            p0 += 0x80;
        },
        5 | 1 => {
            if ucount == 5 {
                p0 += data[byte_offset] as u32;//Unsafe.As<byte, uint>(ref Unsafe.Add(ref data, byteOffset));
                byte_offset += 4;
                let res = block(p0, p1);
                p0 = res.0;
                p1 = res.1;
            }
            p0 += 0x8000 | u32::from_le_bytes(data[byte_offset].try_into().unwrap());// Unsafe.Add(ref data, byteOffset);
        },
        6 | 2 => {
            if ucount == 6 {
                p0 += data[byte_offset] as u32;//Unsafe.As<byte, uint>(ref Unsafe.Add(ref data, byteOffset));
                byte_offset += 4;
                let res = block(p0, p1);
                p0 = res.0;
                p1 = res.1;
            }
            p0 += 0x800000 | data[byte_offset] as u16;//Unsafe.As<byte, ushort>(ref Unsafe.Add(ref data, byteOffset));
        },
        7 | 3 => {
            if ucount == 7 {
                p0 += data[byte_offset] as u32;//Unsafe.As<byte, uint>(ref Unsafe.Add(ref data, byteOffset));
                byte_offset += 4;
                let res = block(p0, p1);
                p0 = res.0;
                p1 = res.1;
            }
            p0 += 0x80000000 |
                    (((uint)(Unsafe.Add(ref data, byteOffset + 2))) << 16) |
                    (uint)(Unsafe.As<byte, ushort>(ref Unsafe.Add(ref data, byteOffset)));
        },
        _ => { let t=3; }
    }*/

    let res = block(p0, p1);
    p0 = res.0;
    p1 = res.1;

    let res = block(p0, p1);
    p0 = res.0;
    p1 = res.1;

    return ((p1 as u64) << 32) | p0 as u64;
}

fn block(rp0: u32, rp1: u32) -> (u32, u32) {
    let mut p0 = rp0;
    let mut p1 = rp1;

    p1 ^= p0;
    p0 = _rotl(p0, 20);

    p0 += p1;
    p1 = _rotl(p1, 9);

    p1 ^= p0;
    p0 = _rotl(p0, 27);

    p0 += p1;
    p1 = _rotl(p1, 19);

    //rp0 = p0;
    //rp1 = p1;
    (p0, p1)
}

fn _rotl(value: u32, shift: i32) -> u32 {
    return (value << shift) | (value >> (32 - shift));
}

pub const DEFAULT_SEED: u64 = 0x82EF4D887A4E55C5;
