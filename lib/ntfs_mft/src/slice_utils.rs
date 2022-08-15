
use chrono::{NaiveDate, NaiveDateTime, Duration};
use byteorder::*;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::{Range, Add};

pub struct MftDataField<'a, T : SliceReadable<'a, T>> {
    name : &'static str,
    offset : usize,
    dynamic_size : Option<fn(&'a [u8]) -> usize>,
    phantom : PhantomData<T>
}

pub struct FieldDisplayInfo {
    pub name : &'static str,
    pub range : Range<usize>,
    pub display_string : String
}

impl<'a, T : SliceReadable<'a, T> + Debug> MftDataField<'a, T> {
    pub fn read(&self, slice : &'a [u8]) -> T {
        if self.get_size(slice) + self.offset > slice.len() {
            panic!("Tried to read outside of slice range: {} from slice of size {}", self.get_size(slice) + self.offset, slice.len());
        }
        T::read(slice, self.offset, self.get_size(slice))
    }

    pub fn get_size(&self, slice : &'a [u8]) -> usize {
        match self.dynamic_size {
            Some(dynamic_size) => dynamic_size(&slice),
            None => T::get_size()
        }
    }

    pub fn get_range(&self, slice : &'a [u8]) -> Range<usize> {
        self.offset..self.offset + self.get_size(slice)
    }

    pub fn get_name(&self) -> &'static str {
        self.name
    }

    pub fn get_display_info(&self, slice : &'a [u8]) -> FieldDisplayInfo {
        FieldDisplayInfo { name: self.name, range: self.get_range(slice), display_string: format!("{:?}", self.read(slice) ) }
    }

    pub const fn new(name : &'static str, offset : usize) -> Self {
        MftDataField { name, offset, phantom: PhantomData, dynamic_size: None }
    }

    pub const fn new_dynamic(name : &'static str, offset : usize, size_fn : fn(&'a [u8]) -> usize) -> Self {
        MftDataField { name, offset, phantom: PhantomData, dynamic_size: Some(size_fn) }
    }
}

// Slice readable types
pub trait SliceReadable<'a, T> {
    fn read(slice : &'a [u8], offset : usize, size : usize) -> T;
    fn get_size() -> usize { size_of::<T>() }
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

impl<'a> SliceReadable<'a, &'a [u16]> for &'a [u16] {
    fn read(slice : &'a [u8], offset : usize, size : usize) -> &'a [u16] {
        // Technically could fail on bad alignment, but that should never happen in our cases
        unsafe { std::slice::from_raw_parts(slice[offset..offset+size].as_ptr() as *const u16, size / 2) }
    }
}

// FILETIME
impl<'a> SliceReadable<'a, NaiveDateTime> for NaiveDateTime {
    fn read(slice : &[u8], offset : usize, _size : usize) -> NaiveDateTime { 
        // Windows FILETIME is specified as the number of 100ns increments since 1601/01/01 00:00:00
        let epoch : NaiveDateTime = NaiveDate::from_ymd(1601, 1, 1).and_hms(0, 0, 0);
        let dt_part = LittleEndian::read_i64(&slice[offset..offset+8]);
        
        // We divide by 10 to get from 100ns increments to microseconds. Using ns directly will overflow a 64 bit int.
        epoch.add(Duration::microseconds(dt_part / 10))
    }

    // Need to specially override for this time since the return type size and the input size differ
    fn get_size() -> usize {
        size_of::<i64>()
    }
}

// Special shenanigans for our u48
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub struct u48 ( u64 );

impl From<&[u8]> for u48 {
    fn from(slice: &[u8]) -> Self {
        u48 ( LittleEndian::read_u48(&slice[0..6]))
    }
}

impl Into<u64> for u48 {
    fn into(self) -> u64 {
        self.0
    }
}

impl<'a> SliceReadable<'a, u48> for u48 {
    fn read(slice : &[u8], offset : usize, size : usize) -> u48 { u48::from(&slice[offset..offset+size]) }
    fn get_size() -> usize { 6 }
}