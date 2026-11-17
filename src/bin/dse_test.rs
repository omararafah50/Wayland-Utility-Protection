use std::hint::black_box;
use zeroize::Zeroize;

#[inline(never)]
pub fn naive_wipe(mut buffer: [u8; 32]) {
    buffer = [0u8; 32];
    black_box(&buffer);
}

#[inline(never)]
pub fn volatile_wipe(buffer: &mut [u8; 32]) {
    for byte in buffer.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    black_box(buffer);
}

#[inline(never)]
pub fn zeroize_wipe(buffer: &mut [u8; 32]) {
    buffer.zeroize();
    black_box(buffer);
}

fn main() {
    let mut s1 = [0xAA; 32];
    let mut s2 = [0xBB; 32];
    let mut s3 = [0xCC; 32];

    naive_wipe(black_box(s1));
    volatile_wipe(black_box(&mut s2));
    zeroize_wipe(black_box(&mut s3));
}
