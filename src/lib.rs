#![no_std]
//! This is a platform agnostic library for the Macronix MX25V NOR flash series using [embedded-hal](https://github.com/rust-embedded/embedded-hal).
//!
//! Multiple chips are supported:
//! * MX25V512F
//! * MX25V1006
//! * MX25V1035
//! * MX25V2006
//! * MX25V2035
//! * MX25V4006
//! * MX25V4035
//! * MX25V8006
//! * MX25V8035
//! * MX25V1606
//! * MX25V1635

pub mod asynchronous;
pub mod blocking;
mod command;
pub mod error;
pub mod register;

use crate::error::Error;

pub const _512K: u32 = 0x00FFFF;
pub const _1M:   u32 = 0x01FFFF;
pub const _2M:   u32 = 0x03FFFF;
pub const _4M:   u32 = 0x07FFFF;
pub const _8M:   u32 = 0x0FFFFF;
pub const _16M:  u32 = 0x1FFFFF;

pub const BLOCK64_SIZE: u32 = 0x010000;
pub const BLOCK32_SIZE: u32 = BLOCK64_SIZE / 2;

pub const SECTOR_SIZE: u32 = 0x1000;
pub const PAGE_SIZE: u32 = 0x100;

pub(crate) fn check_erase<E>(capacity: usize, from: u32, to: u32) -> Result<(), Error<E>> {
    let capacity = capacity as u32;
    if from > to || to > capacity {
        return Err(Error::OutOfBounds);
    }
    if !from.is_multiple_of(SECTOR_SIZE) || !to.is_multiple_of(SECTOR_SIZE) {
        return Err(Error::NotAligned);
    }
    Ok(())
}

pub(crate) fn check_write<E>(capacity: usize, offset: u32, length: usize) -> Result<(), Error<E>> {
    let capacity = capacity as u32;
    let length = length as u32;
    if length > capacity || offset > capacity - length {
        return Err(Error::OutOfBounds);
    }
    Ok(())
}
