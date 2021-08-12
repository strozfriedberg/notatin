/*
 * Copyright 2021 Aon Cyber Solutions
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

use std::convert::TryInto;
use std::mem;

// ported from https://github.com/msuhanov/yarp/blob/41e1ba1e21035a2287447fa6a0fe627afbd213ff/yarp/RegistryFile.py#L46

pub const DEFAULT_SEED: u64 = 0x82EF_4D88_7A4E_55C5;

fn rotl(x: u32, n: u32, w: u32) -> u32 {
    (x << n) | (x >> (w - n))
}

fn mix(file_info: (u32, u32), val: u32) -> (u32, u32) {
    let (mut lo, mut hi) = file_info;
    lo = lo.wrapping_add(val);
    hi ^= lo;
    lo = rotl(lo, 20, 32).wrapping_add(hi);
    hi = rotl(hi, 9, 32) ^ lo;
    lo = rotl(lo, 27, 32).wrapping_add(hi);
    hi = rotl(hi, 19, 32);
    (lo, hi)
}

/// Computes a 64-hash using the Marvin algorithm.
pub(crate) fn compute_hash(buffer: &[u8], len: u32, seed: u64) -> u64 {
    let size_of_u32 = mem::size_of::<u32>();
    let slice_to_u32 = |s: &[u8]| -> [u8; 4] {
        s.try_into()
            .expect("We generated this slice so we know it's the proper length")
    };

    let lo: u32 = (seed & 0xFFFFFFFF).try_into().unwrap();
    let hi: u32 = (seed >> 32).try_into().unwrap();
    let mut file_info = (lo, hi);

    let mut length = len;
    let mut pos = 0;
    let mut val: u32;

    while length >= 4 {
        val = u32::from_le_bytes(slice_to_u32(&buffer[pos..pos + size_of_u32]));
        file_info = mix(file_info, val);
        pos += 4;
        length -= 4;
    }

    let mut fin: u32 = 0x80;
    if length == 3 {
        fin = (fin << 8) | buffer[pos + 2] as u32;
    } else if length == 2 {
        fin = (fin << 8) | buffer[pos + 1] as u32;
    } else if length == 1 {
        fin = (fin << 8) | buffer[pos] as u32;
    }

    file_info = mix(file_info, fin);
    file_info = mix(file_info, 0);
    let (lo, hi) = file_info;
    ((hi as u64) << 32) | lo as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marvin_hash() {
        let mut empty = [0; 1003];
        empty[1000] = 1;
        empty[1001] = 2;
        empty[1002] = 3;

        assert_eq!(0x0C9A_656E_D61F_AC08, compute_hash(&empty, 1003, 12345));
        assert_eq!(0xAE64_2DC7_796A_A02D, compute_hash(&empty, 1002, 12345));
        assert_eq!(0x51AA_D4BF_1788_54C2, compute_hash(&empty, 1001, 12345));
        assert_eq!(0x29EE_E938_063F_AEC6, compute_hash(&empty, 1000, 12345));
    }
}
