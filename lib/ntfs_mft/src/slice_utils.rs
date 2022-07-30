
use byteorder::*;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Range;
use windows_sys::Win32::Foundation::FILETIME;

pub struct AttributeDataField<'a, T : SliceReadable<'a, T>> {
    name : &'static str,
    offset : usize,
    dynamic_size : Option<fn(&'a [u8]) -> usize>,
    phantom : PhantomData<T>
}

pub struct AttributeDisplayInfo {
    pub name : &'static str,
    pub range : Range<usize>
}

impl<'a, T : SliceReadable<'a, T>> AttributeDataField<'a, T> {
    pub fn read(&self, slice : &'a [u8]) -> T {
        T::read(slice, self.offset, self.get_size(slice))
    }

    pub fn get_size(&self, slice : &'a [u8]) -> usize {
        match self.dynamic_size {
            Some(dynamic_size) => dynamic_size(&slice),
            None => size_of::<T>()
        }
    }

    pub fn get_range(&self, slice : &'a [u8]) -> Range<usize> {
        self.offset..self.offset + self.get_size(slice)
    }

    pub fn get_name(&self) -> &'static str {
        self.name
    }

    pub fn get_display_info(&self, slice : &'a [u8]) -> AttributeDisplayInfo {
        AttributeDisplayInfo { name:  self.name, range: self.get_range(slice) }
    }

    pub const fn new(name : &'static str, offset : usize) -> Self {
        AttributeDataField { name, offset, phantom: PhantomData, dynamic_size: None }
    }

    pub const fn new_dynamic(name : &'static str, offset : usize, size_fn : fn(&'a [u8]) -> usize) -> Self {
        AttributeDataField { name, offset, phantom: PhantomData, dynamic_size: Some(size_fn) }
    }
}

// Slice readable types
pub trait SliceReadable<'a, T> {
    fn read(slice : &'a [u8], offset : usize, size : usize) -> T;
}

impl<'a> SliceReadable<'a, u64> for u64 {
    fn read(slice : &'a [u8], offset : usize, size : usize) -> u64 { LittleEndian::read_u64(&slice[offset..offset+size]) }
}

impl<'a> SliceReadable<'a, u32> for u32 {
    fn read(slice : &'a [u8], offset : usize, size : usize) -> u32 { LittleEndian::read_u32(&slice[offset..offset+size]) }
}

impl<'a> SliceReadable<'a, u16> for u16 {
    fn read(slice : &[u8], offset : usize, size : usize) -> u16 { LittleEndian::read_u16(&slice[offset..offset+size]) }
}

impl<'a> SliceReadable<'a, u8> for u8 {
    fn read(slice : &[u8], offset : usize, _size : usize) -> u8 { slice[offset] }
}

impl<'a> SliceReadable<'a, &'a [u8]> for &'a [u8] {
    fn read(slice : &'a [u8], offset : usize, size : usize) -> &'a [u8] {
        &slice[offset..offset+size]
    }
}

// FILETIME
impl<'a> SliceReadable<'a, FILETIME> for FILETIME {
    fn read(slice : &[u8], offset : usize, _size : usize) -> FILETIME { 
        FILETIME { 
            dwLowDateTime : LittleEndian::read_u32(&slice[offset..offset+4]), 
            dwHighDateTime : LittleEndian::read_u32(&slice[offset+4..offset+8])
        }
    }
}

// Special shenanigans for our u48
pub struct u48 ( [u8 ; 6] );

impl From<&[u8]> for u48 {
    fn from(slice: &[u8]) -> Self {
        let mut val = u48([0u8;6]);
        val.0.copy_from_slice(&slice[0..6]);
        val
    }
}

impl Into<u64> for u48 {
    fn into(self) -> u64 {
        LittleEndian::read_u48(&self.0)
    }
}

impl<'a> SliceReadable<'a, u48> for u48 {
    fn read(slice : &[u8], offset : usize, size : usize) -> u48 { u48::from(&slice[offset..offset+size]) }
}