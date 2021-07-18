use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use zeronet_cryptography::{create, sign, verify};

/// zeronet_cryptography wrapper exports
#[no_mangle]
pub extern "C" fn verify_msg(
    data_char: *const c_char,
    address_char: *const c_char,
    sign_char: *const c_char,
) -> bool {
    let data = unsafe { CStr::from_ptr(data_char) };
    let address = unsafe { CStr::from_ptr(address_char) };
    let sign = unsafe { CStr::from_ptr(sign_char) };

    let data = data.to_str().unwrap();
    let address = address.to_str().unwrap();
    let sign = sign.to_str().unwrap();
    match verify(data, address, sign) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[no_mangle]
pub extern "C" fn sign_msg(
    data_char: *const c_char,
    private_key_char: *const c_char,
) -> *const c_char {
    let data = unsafe { CStr::from_ptr(data_char) };
    let private_key = unsafe { CStr::from_ptr(private_key_char) };

    let data: &str = data.to_str().unwrap();
    let private_key = private_key.to_str().unwrap();
    let s = match sign(data, private_key) {
        Ok(sign) => CString::new(sign).unwrap(),
        Err(err) => CString::new(format!("ERROR: {}", err)).unwrap(),
    };
    let ptr = s.as_ptr();
    core::mem::forget(s);
    ptr
}

#[no_mangle]
pub extern "C" fn create_key_pair() -> KeyPair {
    let (public, private) = create();
    let public_str = CString::new(public).unwrap();
    let private_str = CString::new(private).unwrap();
    let public = public_str.as_ptr();
    let private = private_str.as_ptr();
    core::mem::forget(public_str);
    core::mem::forget(private_str);
    KeyPair {
        public: public,
        private: private,
    }
}

#[repr(C)]
pub struct KeyPair {
    public: *const c_char,
    private: *const c_char,
}
