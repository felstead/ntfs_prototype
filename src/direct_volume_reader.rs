use windows_sys::{
    Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, CloseHandle, GetLastError},
    Win32::Storage::FileSystem::{FILE_GENERIC_READ,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING,CreateFileA,ReadFile},
    Win32::System::Ioctl::{NTFS_VOLUME_DATA_BUFFER,FSCTL_GET_NTFS_VOLUME_DATA},
    Win32::System::IO::{OVERLAPPED,OVERLAPPED_0,OVERLAPPED_0_0,DeviceIoControl}
};

use std::ffi::{CString, c_void};

pub const MFT_RECORD_SIZE : usize = 1024;

pub struct DirectVolumeMftReader {
    drive_letter : String,
    volume_path : String,
    volume_handle : HANDLE,
    ntfs_volume_data : NTFS_VOLUME_DATA_BUFFER,
    is_open : bool
}

impl Default for DirectVolumeMftReader {
    #[inline]
    fn default() -> DirectVolumeMftReader {
        DirectVolumeMftReader { 
            drive_letter: String::default(), 
            volume_path: String::default(), 
            volume_handle: HANDLE::default(), 
            ntfs_volume_data: unsafe { std::mem::MaybeUninit::<NTFS_VOLUME_DATA_BUFFER>::zeroed().assume_init() },
            is_open: false
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

    pub fn get_mft_start_offset_bytes(&self) -> i64 {
        if !self.is_open {
            panic!("MFT was not opened!")
        }
        self.ntfs_volume_data.BytesPerCluster as i64 * self.ntfs_volume_data.MftStartLcn
    }

    pub fn get_mft_size_bytes(&self) -> i64 {
        if !self.is_open {
            panic!("MFT was not opened!")
        }

        self.ntfs_volume_data.MftValidDataLength
    }

    pub fn get_max_number_of_records(&self) -> usize {
        (self.get_mft_size_bytes() / MFT_RECORD_SIZE as i64) as usize
    }

    pub fn open_mft(&mut self, drive_letter : &str) -> Result<(), String> {
        
        // Validate drive letter, should be something like "c: or "C:"
        let mut is_valid_drive_letter = false;
        if drive_letter.len() == 2 {
            // Should only be ascii, if not then yikes
            let chars  = drive_letter.as_bytes();

            let letter = chars[0] as char;
            if ((letter >= 'a' && letter <= 'z') || (letter > 'A' && letter < 'Z')) && chars[1] as char == ':' {
                is_valid_drive_letter = true;
            }
        }

        if !is_valid_drive_letter {
            return Err(format!("Invalid drive letter: {}", drive_letter));
        }

        self.drive_letter = drive_letter.to_owned();

        // This could all be in one function but I'm separating them for readability
        self.open_drive()?;
        self.read_mft_info()?;

        self.is_open = true;

        Ok(())
    }

    fn open_drive(&mut self) -> Result<(), String> {
    
        self.volume_path = format!("\\\\.\\{}", self.drive_letter);

        let volume_path_cstr = CString::new(self.volume_path.as_bytes()).unwrap();

        self.volume_handle = unsafe {
            CreateFileA(
                volume_path_cstr.as_ptr() as *const u8,
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, // This actually means other processes CAN read and write
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

        Ok(())
    }

    pub fn read_records_into_buffer(&self, first_record_id : i64, num_records : usize, buffer : &mut [u8]) -> Result<u64, String> {
        if !self.is_open {
            return Err("MFT was not opened!".to_owned())
        }

        let buffer_record_capacity = buffer.len() / MFT_RECORD_SIZE;
        if buffer_record_capacity < num_records {
            return Err(format!("Requested {} records, but buffer of size {} can only fit {} records", num_records, buffer.len(), buffer_record_capacity).to_owned())
        }

        let max_requested_record_id = first_record_id + (num_records as i64);
        if max_requested_record_id > self.get_max_number_of_records() as i64 {
            return Err(format!("Tried to request records beyond end of MFT, requested record {}, max is {}", max_requested_record_id, self.get_max_number_of_records()))
        }

        let read_offset = self.get_mft_start_offset_bytes() + (first_record_id * MFT_RECORD_SIZE as i64);
        let mut overlapped  = OVERLAPPED {
            Anonymous: OVERLAPPED_0 {
                Anonymous: OVERLAPPED_0_0 {
                    Offset: read_offset as u32,
                    OffsetHigh: (read_offset >> 32) as u32
                },
            },
            hEvent: 0,
            Internal: 0,
            InternalHigh: 0,
        };


        let read_result = unsafe {
            ReadFile(
                self.volume_handle,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                std::ptr::null_mut(),
                std::ptr::addr_of_mut!(overlapped)
            )
        };

        if read_result == 0 {
            return Err(format!("ReadFile error: {:#x}", unsafe { GetLastError() }));
        }


        Ok(0)
    }

}



