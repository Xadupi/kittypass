use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;
use kittypass_core::Error as CoreError;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("application non configurée")]
    NotConfigured,
    #[error("application déjà configurée sur cet appareil")]
    AlreadyConfigured,
    #[error("coffre verrouillé")]
    Locked,
    #[error("aucun coffre sur le serveur : utilisez « Créer »")]
    NoRemoteVault,
    #[error("un coffre existe déjà sur ce compte : utilisez « Rejoindre »")]
    RemoteVaultExists,
    #[error("cette entrée n'a pas de code 2FA")]
    NoTotp,
    #[error("erreur de stockage local : {0}")]
    Io(String),
    #[error("trousseau du système indisponible")]
    SecretStore,
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind().to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(_: serde_json::Error) -> Self {
        Self::Io("profil illisible".into())
    }
}

impl AppError {
    /// Code stable, utilisé par l'interface pour réagir (ex. demander la 2FA).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Core(e) => match e {
                CoreError::InvalidKeyOrCorrupted => "invalid_password",
                CoreError::InvalidCredentials => "invalid_credentials",
                CoreError::InvalidInvite => "invalid_invite",
                CoreError::UsernameTaken => "username_taken",
                CoreError::TotpRequired => "totp_required",
                CoreError::InvalidTotp => "invalid_totp",
                CoreError::SessionExpired => "session_expired",
                CoreError::RateLimited => "rate_limited",
                CoreError::Network => "network",
                CoreError::RollbackDetected => "rollback_detected",
                CoreError::DifferentVault => "different_vault",
                CoreError::InsecureUrl => "insecure_url",
                CoreError::WeakMasterPassword(_) => "weak_password",
                CoreError::KeyFile(_) => "key_file",
                _ => "error",
            },
            Self::NotConfigured => "not_configured",
            Self::AlreadyConfigured => "already_configured",
            Self::Locked => "locked",
            Self::NoRemoteVault => "no_remote_vault",
            Self::RemoteVaultExists => "remote_vault_exists",
            Self::NoTotp => "no_totp",
            Self::Io(_) => "io",
            Self::SecretStore => "secret_store",
        }
    }
}

/// Sérialisé pour l'interface en `{code, message}`.
impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("AppError", 2)?;
        st.serialize_field("code", self.code())?;
        st.serialize_field("message", &self.to_string())?;
        st.end()
    }
}
