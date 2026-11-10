use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Erreurs du cœur.
///
/// Les messages ne contiennent jamais de secret, ni d'indice permettant de
/// distinguer « mauvais mot de passe » de « fichier altéré » : les deux sont
/// signalés par `InvalidKeyOrCorrupted`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("mot de passe ou fichier clé incorrect, ou fichier corrompu")]
    InvalidKeyOrCorrupted,
    #[error("fichier clé refusé : {0}")]
    KeyFile(&'static str),
    #[error("format de fichier non pris en charge")]
    UnsupportedFormat,
    #[error("en-tête KDBX invalide : {0}")]
    MalformedHeader(&'static str),
    #[error("paramètres de dérivation hors limites : {0}")]
    KdfOutOfBounds(&'static str),
    #[error("fichier trop volumineux")]
    TooLarge,
    #[error("mot de passe maître trop faible : {0}")]
    WeakMasterPassword(&'static str),
    #[error("entrée introuvable")]
    EntryNotFound,
    #[error("groupe introuvable")]
    GroupNotFound,
    #[error("pièce jointe introuvable")]
    AttachmentNotFound,
    #[error("identifiant invalide")]
    InvalidId,
    #[error("saisie automatique : {0}")]
    AutoType(String),
    #[error("agent SSH : {0}")]
    Ssh(String),
    #[error("paramètre invalide : {0}")]
    InvalidArgument(&'static str),
    #[error("erreur d'écriture du coffre")]
    Save,
    #[error("générateur aléatoire du système indisponible")]
    Rng,
    #[error("échec de la fusion des coffres")]
    MergeFailed,
    #[error("le coffre distant n'est pas le même coffre (créé sur un autre appareil)")]
    DifferentVault,
    #[error("le serveur a renvoyé une version plus ancienne que la dernière vue (retour en arrière suspect)")]
    RollbackDetected,
    #[error("trop d'écritures concurrentes, réessayez")]
    SyncContention,
    #[error("adresse de serveur refusée : HTTPS obligatoire hors machine locale")]
    InsecureUrl,
    #[error("identifiants invalides")]
    InvalidCredentials,
    #[error("code 2FA requis")]
    TotpRequired,
    #[error("code 2FA incorrect")]
    InvalidTotp,
    #[error("session expirée, reconnectez-vous")]
    SessionExpired,
    #[error("trop de tentatives, réessayez plus tard")]
    RateLimited,
    #[error("erreur réseau")]
    Network,
    #[error("code d'invitation invalide, expiré ou déjà utilisé")]
    InvalidInvite,
    #[error("cet identifiant est déjà pris sur ce serveur")]
    UsernameTaken,
    #[error("réponse inattendue du serveur ({0})")]
    Server(u16),
}
