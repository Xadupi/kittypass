//! Écoute locale où se connecte le relais `kittypass-proxy`.
//!
//! Seul l'utilisateur courant peut s'y connecter :
//! - Unix : socket dans un dossier 0700, socket 0600, et vérification de
//!   l'UID du processus pair à chaque connexion ;
//! - Windows : pipe nommé créé avec un accès réservé au propriétaire, en
//!   première instance (personne ne l'occupe à notre place), refus des
//!   clients distants, et vérification du compte du client.

use std::{path::{Path, PathBuf}, sync::Arc};

use kittypass_core::browser::protocol::{MAX_MESSAGE_BYTES, notification};
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::broadcast,
    task::JoinHandle,
};

use crate::{App, AppError, AppResult, BrowserConnection, Prompter};

/// Connexions simultanées au plus (une par navigateur ouvert, en pratique).
const MAX_CONNECTIONS: usize = 16;

/// Serveur en marche ; l'arrêter (`stop` ou `drop`) ferme l'écoute.
pub struct BrowserServer {
    path: PathBuf,
    notify: broadcast::Sender<Value>,
    task: JoinHandle<()>,
}

impl BrowserServer {
    /// Démarre l'écoute à l'emplacement par défaut.
    pub async fn start<P: Prompter + 'static>(app: Arc<App>, prompter: Arc<P>) -> AppResult<Self> {
        #[cfg(unix)]
        let path = kittypass_core::browser::transport::socket_path()?;
        #[cfg(windows)]
        let path = PathBuf::from(kittypass_core::browser::transport::pipe_name()?);
        Self::start_at(path, app, prompter).await
    }

    #[cfg(unix)]
    pub async fn start_at<P: Prompter + 'static>(path: PathBuf, app: Arc<App>, prompter: Arc<P>) -> AppResult<Self> {
        use kittypass_core::browser::transport::{current_uid, prepare_dir};
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::{UnixListener, UnixStream};
        // Limite des sockets Unix (`sun_path`, 108 octets sous Linux).
        if path.as_os_str().len() >= 108 {
            return Err(AppError::Io(format!("chemin du socket trop long ({})", path.display())));
        }
        let dir = path.parent().ok_or(AppError::Io("chemin du socket invalide".into()))?;
        prepare_dir(dir).map_err(|e| AppError::Io(e.to_string()))?;
        if std::fs::symlink_metadata(&path).is_ok() {
            // Un autre KittyPass écoute déjà ? Sinon, socket orphelin.
            if UnixStream::connect(&path).await.is_ok() {
                return Err(AppError::Io("l'intégration navigateur est déjà active dans une autre fenêtre".into()));
            }
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let (notify, _) = broadcast::channel(16);
        let tx = notify.clone();
        let uid = current_uid()?;
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                // Autre utilisateur, ou trop de connexions : fermée aussitôt.
                if !stream.peer_cred().is_ok_and(|c| c.uid() == uid) {
                    continue;
                }
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                let (app, prompter, rx) = (app.clone(), prompter.clone(), tx.subscribe());
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = serve(stream, &app, &*prompter, rx).await;
                });
            }
        });
        Ok(Self { path, notify, task })
    }

    #[cfg(windows)]
    pub async fn start_at<P: Prompter + 'static>(path: PathBuf, app: Arc<App>, prompter: Arc<P>) -> AppResult<Self> {
        use kittypass_core::winsec;
        use std::os::windows::io::AsRawHandle;
        use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

        let name = path.as_os_str().to_owned();
        let sd = Arc::new(winsec::OwnerOnly::new()?);
        let me = winsec::current_user_sid()?;
        let create = move |first: bool, sd: &winsec::OwnerOnly| -> std::io::Result<NamedPipeServer> {
            let mut o = ServerOptions::new();
            o.first_pipe_instance(first).reject_remote_clients(true).max_instances(MAX_CONNECTIONS + 1);
            // SAFETY : `sd` reste vivant pendant l'appel ; le système copie
            // le descripteur dans le pipe.
            #[allow(unsafe_code)]
            unsafe {
                o.create_with_security_attributes_raw(&name, sd.as_ptr())
            }
        };
        let mut server = create(true, &sd).map_err(|e| match e.raw_os_error() {
            // ERROR_ACCESS_DENIED : le nom est déjà pris (autre fenêtre de
            // KittyPass, ou un autre programme).
            Some(5) => AppError::Io("l'intégration navigateur est déjà active dans une autre fenêtre".into()),
            _ => AppError::Io(e.to_string()),
        })?;
        let (notify, _) = broadcast::channel(16);
        let tx = notify.clone();
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        let task = tokio::spawn(async move {
            loop {
                if server.connect().await.is_err() {
                    match create(false, &sd) {
                        Ok(s) => server = s,
                        Err(_) => return,
                    }
                    continue;
                }
                let Ok(next) = create(false, &sd) else { return };
                let stream = std::mem::replace(&mut server, next);
                if !winsec::pipe_client_sid(stream.as_raw_handle()).is_ok_and(|s| s == me) {
                    continue;
                }
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                let (app, prompter, rx) = (app.clone(), prompter.clone(), tx.subscribe());
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = serve(stream, &app, &*prompter, rx).await;
                });
            }
        });
        Ok(Self { path, notify, task })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Prévient les navigateurs connectés (`database-locked`,
    /// `database-unlocked`).
    pub fn notify(&self, action: &str) {
        let _ = self.notify.send(notification(action));
    }

    pub fn stop(self) {}
}

impl Drop for BrowserServer {
    fn drop(&mut self) {
        self.task.abort();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<Option<Vec<u8>>> {
    let len = match s.read_u32_le().await {
        Ok(n) => n as usize,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    if len > MAX_MESSAGE_BYTES {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "message trop long"));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, v: &Value) -> std::io::Result<()> {
    let data = serde_json::to_vec(v)?;
    s.write_u32_le(data.len() as u32).await?;
    s.write_all(&data).await?;
    s.flush().await
}

async fn serve<P: Prompter, S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    app: &App,
    prompter: &P,
    mut notes: broadcast::Receiver<Value>,
) -> std::io::Result<()> {
    let Ok(mut conn) = BrowserConnection::new() else { return Ok(()) };
    loop {
        tokio::select! {
            frame = read_frame(&mut stream) => {
                let Some(raw) = frame? else { return Ok(()) };
                let reply = app.browser_request(&mut conn, &raw, prompter).await;
                write_frame(&mut stream, &reply).await?;
            }
            note = notes.recv() => match note {
                Ok(v) => write_frame(&mut stream, &v).await?,
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
        }
    }
}
