//! Windows : identité des processus aux deux bouts d'un pipe nommé, et
//! descripteur de sécurité « propriétaire seul » pour créer un pipe.
//!
//! Sous Windows, n'importe quel compte peut créer un pipe nommé du même nom
//! avant nous, ou s'y connecter si les droits par défaut le permettent. Les
//! deux côtés vérifient donc à qui appartient le processus en face (SID de
//! son jeton), comme `peer_cred` sous Unix.
#![allow(unsafe_code)]

use std::{ffi::c_void, io, os::windows::io::RawHandle, ptr};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{
        Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::{
        Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
        Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

/// SID du compte système local (service OpenSSH Authentication Agent).
pub const LOCAL_SYSTEM: &str = "S-1-5-18";

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY : poignée ouverte par nous, fermée une seule fois.
        unsafe { CloseHandle(self.0) };
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// SID (forme texte `S-1-5-21-…`) du propriétaire du jeton d'un processus.
fn token_sid(process: HANDLE) -> io::Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY : `process` est valide ; `token` reçoit une nouvelle poignée.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(token);
    let mut buf = vec![0u64; 64]; // 512 octets, alignés.
    let mut len = 0u32;
    // SAFETY : tampon de la taille annoncée.
    let ok = unsafe {
        GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut len)
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY : GetTokenInformation(TokenUser) écrit un TOKEN_USER en tête.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY : `sid` pointe dans `buf`, encore vivant ; `text` est alloué
    // par le système et libéré par LocalFree.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let s = unsafe {
        let n = (0..).take_while(|&i| *text.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
        LocalFree(text.cast());
        s
    };
    Ok(s)
}

/// SID de l'utilisateur courant.
pub fn current_user_sid() -> io::Result<String> {
    // SAFETY : pseudo-poignée du processus courant, pas à fermer.
    token_sid(unsafe { GetCurrentProcess() })
}

fn process_sid(pid: u32) -> io::Result<String> {
    // SAFETY : ouverture en lecture limitée ; poignée fermée par `Handle`.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    let h = Handle(h);
    token_sid(h.0)
}

/// SID du processus serveur d'un pipe auquel on est connecté.
pub fn pipe_server_sid(pipe: RawHandle) -> io::Result<String> {
    let mut pid = 0u32;
    // SAFETY : `pipe` est une poignée de pipe ouverte par l'appelant.
    if unsafe { GetNamedPipeServerProcessId(pipe as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    process_sid(pid)
}

/// SID du processus client connecté à notre pipe.
pub fn pipe_client_sid(pipe: RawHandle) -> io::Result<String> {
    let mut pid = 0u32;
    // SAFETY : `pipe` est une instance de serveur connectée.
    if unsafe { GetNamedPipeClientProcessId(pipe as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    process_sid(pid)
}

/// Descripteur de sécurité : accès complet pour l'utilisateur courant
/// seulement (pas d'héritage, pas d'autres comptes).
pub struct OwnerOnly {
    sd: PSECURITY_DESCRIPTOR,
    attrs: SECURITY_ATTRIBUTES,
}

// Le descripteur est en lecture seule une fois créé.
unsafe impl Send for OwnerOnly {}
unsafe impl Sync for OwnerOnly {}

impl OwnerOnly {
    pub fn new() -> io::Result<Self> {
        let sddl = wide(&format!("D:P(A;;GA;;;{})", current_user_sid()?));
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY : chaîne terminée par zéro ; `sd` libéré par LocalFree.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, ptr::null_mut())
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        Ok(Self { sd, attrs })
    }

    /// Pointeur à passer à `CreateNamedPipeW` (valable tant que `self` vit).
    pub fn as_ptr(&self) -> *mut c_void {
        (&self.attrs as *const SECURITY_ATTRIBUTES).cast_mut().cast()
    }
}

impl Drop for OwnerOnly {
    fn drop(&mut self) {
        // SAFETY : alloué par ConvertStringSecurityDescriptor…, libéré une fois.
        unsafe { LocalFree(self.sd) };
    }
}
