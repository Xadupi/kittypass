//! Intégration KeePassXC-Browser : KittyPass répond à l'extension
//! officielle comme le ferait KeePassXC (même protocole, mêmes données dans
//! le coffre), pour le remplissage, la 2FA, l'enregistrement d'identifiants,
//! le générateur et les passkeys.
//!
//! Le cœur ne fait que les briques sans interface : chiffrement du canal,
//! messages, correspondance des URL, passkeys, et les données du coffre
//! (associations, réglages d'accès par entrée). Les confirmations à
//! l'utilisateur et le transport (socket local) sont dans l'application.

pub mod crypto;
pub mod matching;
pub mod passkeys;
pub mod protocol;
pub mod transport;
