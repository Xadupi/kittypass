//! Relais lancé par le navigateur (messagerie native) : transmet les messages
//! de l'extension KeePassXC-Browser à KittyPass par son socket local, et
//! les réponses en retour. Il ne lit ni ne garde rien : tout est chiffré de
//! bout en bout entre l'extension et l'application.
#![forbid(unsafe_code)]

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::{io, os::unix::net::UnixStream, process::ExitCode, thread};

    use kittypass_core::browser::transport::{check_socket, read_frame, socket_path, write_frame};

    // Le navigateur passe en argument le manifeste et l'extension appelante ;
    // le manifeste ne liste que l'extension KeePassXC-Browser.
    let Ok(path) = socket_path() else { return ExitCode::FAILURE };
    if let Err(e) = check_socket(&path) {
        eprintln!("kittypass-proxy : {e}");
        return ExitCode::FAILURE;
    }
    let Ok(socket) = UnixStream::connect(&path) else {
        eprintln!("kittypass-proxy : KittyPass n'est pas lancé (ou l'intégration navigateur est désactivée)");
        return ExitCode::FAILURE;
    };
    let Ok(mut from_app) = socket.try_clone() else { return ExitCode::FAILURE };
    let mut to_app = socket;

    // Application → navigateur (réponses et notifications).
    let back = thread::spawn(move || {
        let mut out = io::stdout().lock();
        while let Ok(Some(msg)) = read_frame(&mut from_app, false) {
            if write_frame(&mut out, &msg, true).is_err() {
                break;
            }
        }
        // L'application s'est arrêtée : on quitte, le navigateur relancera
        // le relais à la prochaine tentative de connexion.
        std::process::exit(0);
    });

    // Navigateur → application.
    let mut input = io::stdin().lock();
    while let Ok(Some(msg)) = read_frame(&mut input, true) {
        if write_frame(&mut to_app, &msg, false).is_err() {
            break;
        }
    }
    let _ = to_app.shutdown(std::net::Shutdown::Both);
    let _ = back.join();
    ExitCode::SUCCESS
}

/// Windows : pipe nommé de l'utilisateur ; on vérifie que le serveur est
/// bien lancé sous notre compte avant de lui transmettre quoi que ce soit.
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::{os::windows::io::AsRawHandle, process::ExitCode};

    use kittypass_core::{
        browser::transport::{pipe_name, read_frame, write_frame},
        winsec,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::ClientOptions,
    };

    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return ExitCode::FAILURE };
    rt.block_on(async {
        let Ok(name) = pipe_name() else { return ExitCode::FAILURE };
        let pipe = match ClientOptions::new().open(&name) {
            Ok(p) => p,
            Err(_) => {
                eprintln!("kittypass-proxy : KittyPass n'est pas lancé (ou l'intégration navigateur est désactivée)");
                return ExitCode::FAILURE;
            }
        };
        let mine = winsec::current_user_sid().ok();
        if mine.is_none() || winsec::pipe_server_sid(pipe.as_raw_handle()).ok() != mine {
            eprintln!("kittypass-proxy : le pipe n'appartient pas à l'utilisateur courant");
            return ExitCode::FAILURE;
        }
        let (mut from_app, mut to_app) = tokio::io::split(pipe);

        // Navigateur → application : lecture bloquante de stdin dans un fil.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        std::thread::spawn(move || {
            let mut input = std::io::stdin().lock();
            while let Ok(Some(msg)) = read_frame(&mut input, true) {
                if tx.blocking_send(msg).is_err() {
                    break;
                }
            }
        });
        let up = async move {
            while let Some(msg) = rx.recv().await {
                let mut framed = Vec::with_capacity(msg.len() + 4);
                if write_frame(&mut framed, &msg, false).is_err() || to_app.write_all(&framed).await.is_err() {
                    break;
                }
            }
        };
        // Application → navigateur.
        let down = async move {
            let mut out = std::io::stdout().lock();
            while let Ok(len) = from_app.read_u32_le().await {
                let len = len as usize;
                if len > kittypass_core::browser::protocol::MAX_MESSAGE_BYTES {
                    break;
                }
                let mut buf = vec![0u8; len];
                if from_app.read_exact(&mut buf).await.is_err() || write_frame(&mut out, &buf, true).is_err() {
                    break;
                }
            }
        };
        // L'un des deux côtés s'est fermé : on quitte.
        tokio::select! { _ = up => {}, _ = down => {} }
        ExitCode::SUCCESS
    })
}

#[cfg(not(any(unix, windows)))]
fn main() -> std::process::ExitCode {
    eprintln!("kittypass-proxy : plateforme non prise en charge");
    std::process::ExitCode::FAILURE
}
