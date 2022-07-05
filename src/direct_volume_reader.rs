use windows_sys::{
    Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, CloseHandle, GetLastError},
    Win32::Storage::FileSystem::{FILE_GENERIC_READ,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING,CreateFileA},
    Win32::System::Ioctl::{NTFS_VOLUME_DATA_BUFFER,FSCTL_GET_NTFS_VOLUME_DATA},
    Win32::System::IO::{DeviceIoControl}
};

use std::{ffi::{CString, c_void}, io::Seek};
use std::path::Path;
use std::fs::{File};
use std::io::{Read, SeekFrom};

use crate::{
    common::*, 
    mft_parser::*};
use crate::ntfs_file_reader::NtfsFileReader;

pub fn create_mft_reader(path_string : &str) -> Result<Box<dyn MftReader>, String> {

    let path = Path::new(path_string);

    if !path.exists() {
        return Err(format!("Path {} does not exist", path_string));
    }

    // Parse the path to determine if this is a drive or a file
    let mut is_valid_drive_letter = false;
    if (2..3).contains(&path_string.len()) {
        // Should only be ascii, if not then yikes
        let chars  = path_string.as_bytes();

        let letter = chars[0] as char;
        if ('a'..='z').contains(&letter) || ('A'..='Z').contains(&letter) && chars[1] as char == ':' {
            is_valid_drive_letter = true;
        }
    }

    if is_valid_drive_letter {
        if cfg!(windows) {
            // Direct volume reader
            let reader = DirectVolumeMftReader::new(path_string)?;
            Ok(reader)
        } else {
            Err("Direct volume MFT reads (e.g. c:) are only supported on Windows".to_owned()) 
        }            
    } else {
        // File reader
        let reader = FileMftReader::new(path_string)?;
        Ok(reader)
    }
}


pub trait MftReader {
    fn get_mft_size_bytes(&self) -> i64;
    fn get_max_number_of_records(&self) -> usize;
    fn read_records_into_buffer(&mut self, first_record_id : i64, num_records : usize, buffer : &mut [u8]) -> Result<usize, String>;
}

pub struct FileMftReader {
    mft_file: File
}

impl FileMftReader {
    pub fn new(file_name : &str) -> Result<Box<FileMftReader>, String> {
        let file = match File::open(file_name) {
            Ok(file) => {
                file
            },
            Err(err) => {
                return Err(err.to_string())
            }
        };
        
        let reader = FileMftReader {
            mft_file: file
        };

        // TODO: Verify this is an MFT
        return Ok(Box::new(reader))
    }
}

impl MftReader for FileMftReader {
    fn get_mft_size_bytes(&self) -> i64 {
        self.mft_file.metadata().unwrap().len() as i64
    }

    fn get_max_number_of_records(&self) -> usize {
        (self.get_mft_size_bytes() / MFT_RECORD_SIZE as i64) as usize
    }

    fn read_records_into_buffer(&mut self, first_record_id : i64, _num_records : usize, buffer : &mut [u8]) -> Result<usize, String> {
        match self.mft_file.seek(SeekFrom::Start(first_record_id as u64 * MFT_RECORD_SIZE as u64)) {
            Ok(_) => {
                match self.mft_file.read(buffer) {
                    Ok(bytes_read) => return Ok(bytes_read / MFT_RECORD_SIZE),
                    Err(err) => return Err(err.to_string())
                }
            },
            Err(err) => {
                return Err(err.to_string());
            }
        }
    }
}

pub struct DirectVolumeMftReader {
    drive_letter : String,
    volume_path : String,
    volume_handle : HANDLE,
    ntfs_volume_data : NTFS_VOLUME_DATA_BUFFER,
    is_open : bool,
    mft_file_reader : NtfsFileReader,
}

impl MftReader for DirectVolumeMftReader {
    fn get_mft_size_bytes(&self) -> i64 {
        self.ntfs_volume_data.MftValidDataLength
    }

    fn get_max_number_of_records(&self) -> usize {
        (self.get_mft_size_bytes() / MFT_RECORD_SIZE as i64) as usize
    }

    fn read_records_into_buffer(&mut self, first_record_id : i64, num_records : usize, buffer : &mut [u8]) -> Result<usize, String> {
        if !self.is_open {
            return Err("MFT was not opened!".to_owned())
        }

        let buffer_record_capacity = buffer.len() / MFT_RECORD_SIZE;
        if buffer_record_capacity < num_records {
            return Err(format!("Requested {} records, but buffer of size {} can only fit {} records", num_records, buffer.len(), buffer_record_capacity))
        }

        let max_requested_record_id = std::cmp::min(first_record_id + (num_records as i64), self.get_max_number_of_records() as i64);

        if max_requested_record_id > self.get_max_number_of_records() as i64 {
            return Err(format!("Tried to request records beyond end of MFT, requested record {}, max is {}", max_requested_record_id, self.get_max_number_of_records()))
        }

        self.mft_file_reader.read_file_bytes(first_record_id * MFT_RECORD_SIZE as i64, num_records * MFT_RECORD_SIZE, buffer, self.volume_handle)
    }
}

impl Default for DirectVolumeMftReader {
    #[inline]
    fn default() -> DirectVolumeMftReader {
        DirectVolumeMftReader { 
            drive_letter: String::default(), 
            volume_path: String::default(), 
            volume_handle: HANDLE::default(), 
            ntfs_volume_data: unsafe { std::mem::MaybeUninit::<NTFS_VOLUME_DATA_BUFFER>::zeroed().assume_init() },
            is_open: false,
            mft_file_reader: NtfsFileReader::default()
        }
    }
}

impl Drop for DirectVolumeMftReader {
    #[inline]
    fn drop(&mut self) {
        if self.volume_handle != HANDLE::default() {
            unsafe {
                let _ = CloseHandle(self.volume_handle);
            }
        }
    }
}

impl DirectVolumeMftReader {

    #[allow(dead_code)]
    pub fn get_mft_start_offset_bytes(&self) -> i64 {
        self.ntfs_volume_data.BytesPerCluster as i64 * self.ntfs_volume_data.MftStartLcn
    }

    pub fn new(drive_letter : &str) -> Result<Box<DirectVolumeMftReader>, String> {
        
        // Validate drive letter, should be something like "c: or "C:"
        let mut is_valid_drive_letter = false;
        if drive_letter.len() == 2 {
            // Should only be ascii, if not then yikes
            let chars  = drive_letter.as_bytes();

            let letter = chars[0] as char;
            if ('a'..='z').contains(&letter) || ('A'..='Z').contains(&letter) && chars[1] as char == ':' {
                is_valid_drive_letter = true;
            }
        }

        if !is_valid_drive_letter {
            return Err(format!("Invalid drive letter: {}", drive_letter));
        }

        let mut reader = Box::new(DirectVolumeMftReader::default());

        // This could all be in one function but I'm separating them for readability
        reader.drive_letter = drive_letter.to_owned();
        reader.open_drive()?;
        reader.read_mft_info()?;

        // Parse the MFT file
        reader.is_open = true;

        Ok(reader)
    }

    fn open_drive(&mut self) -> Result<(), String> {
    
        self.volume_path = format!("\\\\.\\{}", self.drive_letter);

        let volume_path_cstr = CString::new(self.volume_path.as_bytes()).unwrap();

        self.volume_handle = unsafe {
            CreateFileA(
                volume_path_cstr.as_ptr() as *const u8,
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, // This actually means other processes CAN read and write the file, i.e. not exclusive locking
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0
            )
        };

        if self.volume_handle == INVALID_HANDLE_VALUE {
            // RETURN FAIL
            return Err(format!("CreateFileA failed: {:#x}", unsafe { GetLastError() } ));
        }

        Ok(())
    }

    fn read_mft_info(&mut self)  -> Result<(), String> {

        let result = unsafe { 
            DeviceIoControl(
                self.volume_handle,
                FSCTL_GET_NTFS_VOLUME_DATA,
                std::ptr::null(),
                0,
                std::ptr::addr_of_mut!(self.ntfs_volume_data) as *mut c_void,
                std::mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut()
            )
        };

        if result == 0 {
            return Err(format!("DeviceIoControl error: {:#x}", unsafe { GetLastError() }));
        }

        // Now we need to read the $MFT record (first record) from the MFT to determine the physical MFT file layout,
        // that is, its layout on the disk - the MFT needn't necessarily be contiguous, it is often split across
        // multiple runs.
        // What we do here is initialize our NtfsFileReader with an initial known run so we can leverage that to get
        // the first MFT record
        let mut bootstrapped_mft_file_reader = NtfsFileReader::new(self.ntfs_volume_data.BytesPerCluster.into(), self.ntfs_volume_data.BytesPerCluster.into());
        bootstrapped_mft_file_reader.add_run(self.ntfs_volume_data.Mft2StartLcn, 1);

        let mut mft_record_buffer : [u8 ; MFT_RECORD_SIZE] = [0 ; MFT_RECORD_SIZE];

        let bytes_read = bootstrapped_mft_file_reader.read_file_bytes(0, MFT_RECORD_SIZE, &mut mft_record_buffer[..], self.volume_handle)?;

        if bytes_read != MFT_RECORD_SIZE {
            return Err(format!("Read invalid number of bytes for MFT record, expected {}, got {}", MFT_RECORD_SIZE, bytes_read));
        }

        let mft_record_result = read_single_mft_record(&mft_record_buffer, 0)?;

        match mft_record_result {
            Some(MftRecord { file_name_info : Some(mft_file_name), file_data_info : Some(MftFileDataInfo::NonResident(mft_file_data)), .. }) => {
                if mft_file_name.get_file_name() != "$MFT" {
                    return Err(format!("MFT file_name was not $MFT, got '{}' instead!", mft_file_name.get_file_name()))
                }

                self.mft_file_reader = mft_file_data.get_direct_file_reader(self.ntfs_volume_data.BytesPerCluster as usize)?;
            },
            _ => {
                return Err("MFT record data was missing!".to_owned())
            }
        }

        Ok(())
    }
}



