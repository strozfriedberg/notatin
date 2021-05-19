use std::convert::TryInto;
use std::mem;

// ported from https://github.com/msuhanov/yarp/blob/41e1ba1e21035a2287447fa6a0fe627afbd213ff/yarp/RegistryFile.py#L46

pub const DEFAULT_SEED: u64 = 0x82EF_4D88_7A4E_55C5;

fn rotl(x: u32, n: u32, w: u32) -> u32 {
	(x << n) | (x >> (w - n))
}

fn mix(state: (u32, u32), val: u32) -> (u32, u32){
    let (mut lo, mut hi) = state;
    lo = lo.wrapping_add(val);
    hi ^= lo;
    lo = rotl(lo, 20, 32).wrapping_add(hi);
    hi = rotl(hi, 9, 32) ^ lo;
    lo = rotl(lo, 27, 32).wrapping_add(hi);
    hi = rotl(hi, 19, 32);
	(lo, hi)
}

/// Computes a 64-hash using the Marvin algorithm.
pub fn compute_hash(buffer: &[u8], len: u32, seed: u64) -> u64 {
    let size_of_u32 = mem::size_of::<u32>();
    let slice_to_u32 = |s: &[u8]| -> [u8; 4] { s.try_into().expect("We generated this slice so we know it's the proper length") };

    let lo: u32 = (seed & 0xFFFFFFFF).try_into().unwrap();
	let hi: u32 = (seed >> 32).try_into().unwrap();
	let mut state = (lo, hi);

	let mut length = len;
	let mut pos = 0;
	let mut val: u32;

	while length >= 4 {
		val = u32::from_le_bytes(slice_to_u32(&buffer[pos..pos + size_of_u32]));
		state = mix(state, val);
		pos += 4;
		length -= 4;
    }

	let mut fin: u32 = 0x80;
	if length == 3 {
        fin = (fin << 8) | u32::from_le_bytes(slice_to_u32(&buffer[pos + 2 .. pos + 2 + size_of_u32]));
    }
	else if length == 2 {
        fin = (fin << 8) | u32::from_le_bytes(slice_to_u32(&buffer[pos + 1 .. pos + 1 + size_of_u32]));
    }
	else if length == 1 {
        fin = (fin << 8) | u32::from_le_bytes(slice_to_u32(&buffer[pos .. pos + size_of_u32]));
    }

	state = mix(state, fin);
	state = mix(state, 0);
	let (lo, hi) = state;
	((hi as u64) << 32) | lo as u64
}