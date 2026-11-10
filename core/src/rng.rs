use crate::{Error, Result};

/// Remplit `buf` avec l'aléa du système d'exploitation (CSPRNG).
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

/// Entier uniforme dans `0..n`, sans biais (échantillonnage par rejet).
pub(crate) fn below(n: u32) -> Result<u32> {
    if n == 0 {
        return Err(Error::InvalidArgument("borne nulle"));
    }
    // Plus grand multiple de n représentable : on rejette au-delà pour éviter
    // le biais du modulo.
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        fill(&mut b)?;
        let v = u32::from_le_bytes(b);
        if v < zone {
            return Ok(v % n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_zero_is_rejected() {
        assert!(below(0).is_err());
    }

    #[test]
    fn below_stays_in_range() {
        for n in [1, 2, 3, 7, 62, 94, u32::MAX] {
            for _ in 0..200 {
                assert!(below(n).unwrap() < n);
            }
        }
    }

    /// Test du khi-deux grossier : détecte un biais important de distribution.
    #[test]
    fn below_is_roughly_uniform() {
        let n = 10u32;
        let samples = 100_000;
        let mut counts = [0u32; 10];
        for _ in 0..samples {
            counts[below(n).unwrap() as usize] += 1;
        }
        let expected = samples as f64 / n as f64;
        let chi2: f64 = counts
            .iter()
            .map(|&c| (c as f64 - expected).powi(2) / expected)
            .sum();
        // 9 degrés de liberté : p = 0.0001 correspond à environ 33.7.
        assert!(chi2 < 33.7, "distribution biaisée, chi2 = {chi2}");
    }
}
