use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Config {
    /// Adresses des reverse proxies autorisés à fournir `X-Forwarded-For`.
    /// Toute autre source voit cet en-tête ignoré (sinon un attaquant
    /// contournerait la limitation par IP en inventant son adresse).
    pub trusted_proxies: Vec<IpAddr>,
    /// Exige la 2FA : sans elle, un compte ne peut que configurer sa 2FA.
    pub require_2fa: bool,
    pub max_vault_bytes: usize,
    /// Nombre de versions conservées par coffre.
    pub versions_kept: i64,
    pub max_vaults_per_user: i64,
    /// Place totale (toutes versions de tous les coffres) par compte.
    pub max_user_bytes: i64,
    pub access_ttl: i64,
    pub refresh_ttl: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            require_2fa: false,
            max_vault_bytes: 64 * 1024 * 1024,
            versions_kept: 50,
            max_vaults_per_user: 20,
            max_user_bytes: 2 * 1024 * 1024 * 1024,
            access_ttl: 15 * 60,
            refresh_ttl: 30 * 24 * 3600,
        }
    }
}
