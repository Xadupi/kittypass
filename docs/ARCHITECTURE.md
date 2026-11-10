# KittyPass — Architecture et modèle de menace

Gestionnaire de mots de passe compatible KeePass (KDBX 4), synchronisé via un
serveur auto-hébergé (Proxmox), exposé sur Internet, multi-utilisateur.

## 1. Principe : zero-knowledge

Le serveur ne stocke **que** des fichiers `.kdbx` chiffrés et des empreintes
d'authentification. Il ne voit jamais :

- le mot de passe maître ;
- la clé de déchiffrement du coffre ;
- le contenu des entrées (titres, URL, identifiants compris).

Une compromission totale du serveur donne à l'attaquant des fichiers KDBX qu'il
doit attaquer hors-ligne contre Argon2id, exactement comme un fichier KeePass volé.

## 2. Composants

```
kittypass/
├── core/        Rust — KDBX, dérivation de clés, fusion, client HTTP de synchro
├── server/      Rust (axum + SQLite) — comptes, 2FA, stockage versionné
├── desktop/     Tauri (Windows, Linux Debian .deb, Linux AppImage/Flatpak)
└── android/     Kotlin + core via UniFFI, service Autofill, BiometricPrompt
```

Un seul cœur crypto, testé une fois, partagé par toutes les plateformes.

## 3. Dérivation des clés

```
mot de passe maître ──┬──► KDF du KDBX (Argon2id, paramètres dans l'en-tête) ──► clé du coffre
                      │
                      └──► Argon2id(mdp, sel_compte, 64 MiB, t=3, p=4) = master_key
                                     │
                                     └──► HKDF-SHA256(master_key, "kittypass/auth/v1") = auth_key
                                                    │
                       serveur stocke : HMAC-SHA256(poivre, sel_serveur ‖ auth_key)
```

- `auth_key` a déjà 256 bits d'entropie : un HMAC suffit côté serveur. Un hachage
  lent ne protégerait rien de plus et permettrait d'épuiser le CPU du serveur.
  Le **poivre** est dérivé de `secret.key`, stocké hors de la base : une fuite
  de la base seule ne permet même pas de tester des `auth_key`.
- Les paramètres Argon2id du compte sont imposés (64 MiB, t=3, p=4) et le sel
  fait toujours 32 octets. Ainsi, les vrais et les faux comptes sont
  indiscernables au pré-login.

- `auth_key` est la seule chose envoyée au serveur. Elle est à sens unique : la
  connaître ne permet ni de retrouver le mot de passe ni d'ouvrir le coffre.
- Le serveur re-hache `auth_key` : une fuite de sa base ne permet pas de se
  connecter (« pass-the-hash » impossible).
- `sel_compte` est public (renvoyé au pré-login). Pour un identifiant inconnu,
  le serveur renvoie un sel **déterministe** (HMAC du nom avec un secret serveur)
  afin de ne pas révéler quels comptes existent.

## 4. Authentification serveur

1. `POST /api/v1/prelogin` → sel et paramètres KDF.
2. `POST /api/v1/login` (identifiant + `auth_key` + code TOTP si activé).
3. Le serveur délivre :
   - un **jeton d'accès** opaque de 256 bits, valable 15 min ;
   - un **jeton de rafraîchissement** de 256 bits, à usage unique (rotation),
     lié à l'appareil. Réutiliser un ancien jeton révoque toute la famille de
     jetons (détection de vol).
4. Le serveur ne stocke que le SHA-256 des jetons.

2FA : TOTP (RFC 6238), codes de secours à usage unique, anti-rejeu (un code ne
sert qu'une fois par fenêtre).

## 5. Synchronisation

- Chaque coffre a un numéro de version côté serveur.
- `PUT /vaults/{id}` avec `If-Match: <version>`. Si quelqu'un a écrit entre
  temps → `409 Conflict`.
- Le client télécharge alors la version distante, **fusionne** localement
  (par UUID d'entrée et date de modification, l'historique KeePass est conservé,
  les suppressions passent par `DeletedObjects`), puis renvoie le résultat.
- Le serveur conserve les N dernières versions pour pouvoir revenir en arrière
  (protection contre un client bogué ou un rançongiciel).
- Fonctionnement hors-ligne : une copie `.kdbx` locale est toujours disponible.

## 6. Biométrie

On ne stocke jamais le mot de passe maître en clair. La clé composite KDBX est
chiffrée par une clé matérielle :

- Android : Keystore (StrongBox si disponible), `setUserAuthenticationRequired`,
  la clé est invalidée si une nouvelle empreinte est enregistrée ;
- Windows : Windows Hello (`KeyCredentialManager`) + DPAPI ;
- Linux : pas de biométrie standard. On utilise le trousseau Secret Service,
  optionnel, avec un délai d'expiration.

## 7. Modèle de menace

| Attaquant | Capacité | Protection |
|---|---|---|
| Réseau (Wi-Fi public, FAI) | Écoute ou modifie le trafic | TLS 1.3 obligatoire, épinglage de certificat optionnel, contenu de toute façon chiffré |
| Serveur compromis | Lit et modifie la base et les fichiers | Zero-knowledge. Intégrité KDBX (HMAC) : une modification est détectée. Le client refuse de remplacer un coffre local par un fichier invalide |
| Serveur malveillant | Envoie une vieille version (rollback) | Le client mémorise la dernière version vue et alerte en cas de recul |
| Utilisateur A du même serveur | Tente de lire le coffre de B | Contrôle d'accès par propriétaire sur chaque route, identifiants non devinables. Tests IDOR systématiques |
| Bourrage d'identifiants / force brute | Essaie des mots de passe en ligne | Argon2id côté serveur, limitation par IP et par compte, 2FA |
| Énumération de comptes | Distinguer les comptes existants | Pré-login au sel déterministe, mêmes messages et temps de réponse |
| Vol de jeton | Rejoue un jeton | Courte durée, rotation, détection de réutilisation, révocation par appareil |
| Vol de l'appareil (verrouillé) | Accès au fichier local | Fichier KDBX chiffré, verrouillage auto, clé biométrique matérielle |
| Malware local (session active) | Lit la mémoire, le presse-papiers | Hors périmètre complet. Atténuations : effacement mémoire (`zeroize`), presse-papiers vidé après 30 s, `FLAG_SECURE` sur Android |
| Fichier KDBX piégé | Fait planter le parseur ou épuise la mémoire | Limites de taille et de paramètres KDF, fuzzing du parseur |

## 8. Plan de tests de sécurité (par fonctionnalité)

- Tests unitaires et de propriétés (proptest) sur la crypto et la fusion.
- Fuzzing (cargo-fuzz) du parseur KDBX et des entrées de l'API.
- Tests d'intégration offensifs sur l'API : IDOR, contournement d'authentification,
  rejeu de jetons et de TOTP, énumération, injection SQL, en-têtes, tailles
  excessives, conditions de course sur la synchro.
- Analyse de dépendances : `cargo audit`, `cargo deny` (`deny.toml` : failles,
  crates non maintenues, licences compatibles GPL-3.0, pas d'OpenSSL, crates.io
  seulement ; chaque exception y est datée et justifiée).

### Tests d'intrusion (boîte noire)

Faits contre un serveur jetable (binaire de version, vraie pile HTTP) : contrôle d'accès (IDOR, routes admin,
jetons détournés), chemins piégés, CORS, méthodes, `Content-Type`, JSON dupliqué ou très imbriqué, valeurs
extrêmes, contrebande HTTP (CL+TE, double `Content-Length`), en-têtes géants, connexions lentes, force brute,
secrets dans le journal. Protections ajoutées à cette occasion : limitation de débit par /64 en IPv6, quota
par compte (`max_user_bytes`, 2 Gio), 8 transferts de coffre à la fois, en-têtes ≤ 64 Kio reçus en 10 s,
connexion ≤ 10 min, 512 connexions simultanées (Caddy filtre aussi en amont).

### Fuzzing

`core/fuzz` (crate à part, Rust nightly) contient 13 cibles : `kdbx`, `keyfile`,
`import_csv`, `import_bitwarden`, `import_1pux`, `browser_message`, `passkeys`,
`url_matching`, `ssh_settings`, `ssh_key`, `ssh_agent_reply`, `otp`, `autotype`.
Les entrées de départ sont dans `core/fuzz/seeds/<cible>`.

```bash
cd core/fuzz
cargo +nightly fuzz run -O kdbx corpus/kdbx seeds/kdbx -- -max_total_time=240
cargo +nightly fuzz run -O kdbx artifacts/kdbx/<crash>   # rejouer un plantage
```

La CI lance chaque cible 30 s. Toute entrée qui fait planter devient un test
de non-régression.
- Analyse statique : `clippy -D warnings`, `#![forbid(unsafe_code)]` hors FFI.

## keepass-rs corrigé (`vendor/keepass`)

La bibliothèque `keepass` 0.17.0 est embarquée et corrigée (rechercher
« KittyPass patch ») :

- **Fusion et pièces jointes** : la fusion recopiait les références de pièces
  jointes d'un coffre à l'autre sans les données (« TODO » en amont). Chaque
  appareil numérotant ses pièces jointes à partir de 0, une entrée fusionnée
  pointait vers le fichier d'une autre. Les entrées venant de l'autre coffre
  sont désormais rattachées au stock local (données identiques partagées).
- **Retrait / remplacement d'une pièce jointe** : supprimait aussi les données
  encore utilisées par l'historique de l'entrée (référence pendante à
  l'enregistrement).
- **Données personnalisées** : toute valeur qui ressemblait à du base64 était
  décodée en binaire à la lecture (« true » devenait 3 octets). En KDBX XML ces
  valeurs sont toujours du texte ; KeePassXC y range ses réglages (exclusion
  des rapports, KeePassXC-Browser…).
- **Fichiers clés v2.0** (`.keyx`) : l'empreinte de contrôle (`Hash`) du
  fichier n'était pas vérifiée ; un fichier abîmé donnait une autre clé au
  lieu d'une erreur.
- **En-têtes malformés** (trouvé par fuzzing) : un champ numérique d'en-tête
  plus court que prévu (compression, tours, flux interne en KDBX 3 et 4,
  entiers des paramètres de dérivation) faisait paniquer la lecture ; c'est
  maintenant une erreur. Test : `short_numeric_header_fields_are_errors_not_panics`.

Limites ajoutées côté KittyPass : profondeur des groupes ≤ 64 (au-delà
d'environ 100 niveaux, la bibliothèque ne relit plus le fichier qu'elle a
écrit), pièces jointes ≤ 16 MiB chacune et 40 MiB au total, historique élagué
selon les réglages du coffre (10 versions / 6 MiB par défaut, plafonds 100 /
16 MiB), noms sans caractères de contrôle, de direction (U+202E…) ni
séparateurs de chemin.

## Compatibilité des fichiers

- Un fichier **KDBX 3.1** (format par défaut de KeePassXC, dérivation
  AES-KDF) est converti à l'ouverture en KDBX 4 avec Argon2id : la
  bibliothèque n'écrit que le KDBX 4, et AES-KDF résiste bien moins aux
  attaques par GPU sur un fichier stocké côté serveur. KeePassXC relit le
  résultat (test d'interopérabilité aller-retour).
- Les valeurs reprises telles quelles d'une entrée existante ne sont pas
  revalidées : une entrée créée par un autre logiciel KeePass, aux règles
  plus souples, reste modifiable. Seules les valeurs nouvelles sont soumises
  aux limites de KittyPass.
- Recherche : syntaxe KeePassXC (champs, `-`/`!`, `+`, `*`, `?`, guillemets,
  `is:expired`), sans expressions régulières (pas de ReDoS). Le mot de passe
  n'est cherché qu'avec `password:` explicite ; les valeurs d'attributs
  protégés jamais.

## Interface de bureau (façon KeePassXC)

- Mise en page : barre d'outils, arbre des groupes + tags, liste triable, aperçu
  (onglets Général/Avancé), éditeur à onglets Entrée/Avancé/2FA/Historique,
  générateur mot de passe / phrase de passe, raccourcis clavier de KeePassXC.
- Aucun secret dans les vues : mots de passe, TOTP et attributs protégés ne
  quittent le Rust que sur demande explicite (afficher / copier). Le
  presse-papiers est vidé après 30 s.
- Aucun `innerHTML` : tout le DOM est construit avec `textContent`.
- Tous les formulaires sont `method="dialog"` : même si le JavaScript ne charge
  pas, une soumission native ne peut pas mettre un mot de passe dans l'URL (la CSP
  `form-action 'none'` le bloquerait aussi).
- Le verrouillage efface la liste, l'arbre, l'aperçu et l'éditeur en cours.
- Banc de test navigateur : `desktop/ui-test/harness.html` (régénéré depuis
  `ui/index.html`) + `mock.js`, un faux coffre rempli de charges XSS. Servir
  `desktop/` avec `python3 -m http.server --bind 127.0.0.1` puis ouvrir
  `/ui-test/harness.html` ; `window.__xss` doit rester indéfini.

### Thèmes

Apparence = un **thème** (Clair par défaut, Pastel, Sombre, Système qui suit
le mode clair/sombre du bureau) × une **couleur d'accent** (Vert par défaut,
Émeraude, Sarcelle, Bleu, Indigo, Violet, Framboise, Orange, Ambre,
Graphite). Fonds, bordures et surlignages sont dérivés de l'accent
(`color-mix`) ; les boutons principaux et la sélection utilisent un dégradé
dont le texte blanc garde un contraste ≥ 4,5:1 (WCAG AA) pour chaque accent.
Ce sont des préférences d'affichage gardées dans le stockage local de la vue
(`localStorage`), appliquées avant l'affichage par `theme.js` (fichier local,
compatible avec la CSP `script-src 'self'`).

**Android (à venir)** : thème Material You (couleurs dynamiques tirées du fond
d'écran, Android 12+), avec la palette verte de KittyPass en repli sur les
versions plus anciennes.

### Tests de la vraie application

`desktop/ui-test/wd.py` pilote l'application réelle (Rust, serveur, fichiers)
par WebDriver (`tauri-driver` + `WebKitWebDriver`). Les boîtes de dialogue du
système n'étant pas pilotables, la **version de développement seulement**
lit la réponse dans le fichier désigné par `KITTYPASS_TEST_DIALOG` ; ce code
est exclu de la version distribuée (`cfg(debug_assertions)`, vérifié : la
chaîne est absente du binaire `release`).

## Rapports de sécurité

- **Bilan de santé** (comme KeePassXC) : mots de passe de qualité ≤ « Faible »,
  réutilisés (nombre d'autres entrées), entrées expirées. Corbeille et
  mots de passe vides ignorés. Les vues ne contiennent aucun mot de passe.
- **Robustesse** : zxcvbn, mêmes niveaux et seuils que KeePassXC (Mauvais ≤ 0,
  Médiocre < 40, Faible < 75, Bon < 100 bits, Excellent). Le titre,
  l'identifiant et l'URL de l'entrée servent de dictionnaire (un mot de passe
  qui les reprend est pénalisé). Calcul réparti sur 8 cœurs au plus ; la jauge
  de l'éditeur utilise la même estimation.
- **Exclusion des rapports** : champ standard KDBX 4.1 `QualityCheck = False`
  (KeePass 2.48+, KeePassXC 2.7+), plus l'ancienne donnée personnalisée
  `KnownBad = true` (KeePassXC ≤ 2.6). Les deux sont lus et écrits ; vérifié
  dans les deux sens avec `keepassxc-cli` 2.7.10.
- **Have I Been Pwned** : k-anonymat. Seuls les 5 premiers caractères
  hexadécimaux du SHA-1 partent (un appel par préfixe distinct, 8 en
  parallèle au plus, en-tête `Add-Padding: true`) ; la comparaison des
  suffixes est locale. HTTPS obligatoire (sauf machine locale), pas de
  redirection, réponse ≤ 4 MiB et validée ligne par ligne. Jamais
  automatique : l'utilisateur confirme. Le coffre n'est pas bloqué pendant
  les requêtes, et rien n'est renvoyé s'il est verrouillé entre-temps.
- Limite connue : zxcvbn copie le mot de passe dans des chaînes qu'il n'efface
  pas (même défaut que zxcvbn-c dans KeePassXC).

### zxcvbn corrigé (`vendor/zxcvbn`)

zxcvbn 3.1.1 est embarqué et corrigé (rechercher « KittyPass patch ») :

- **Calculs saturés en u64** : dès 6 segments (terme additif 10000⁵ > 2⁶⁴) ou
  20 caractères aléatoires, toutes les décompositions valaient `u64::MAX` et
  l'interprétation « tout aléatoire » gagnait par défaut. Les motifs des mots
  de passe longs étaient ignorés (« correct horse battery staple » : 164 bits
  au lieu de 61). Calcul désormais en `f64`, et `factorial` ne déborde plus
  (panique au-delà de 20 segments).
- **Alphabet réel** pour les segments aléatoires (comme zxcvbn-c) au lieu de
  10 possibilités par caractère.
- **Déterminisme** : l'ordre de parcours des `HashMap` changeait le résultat
  d'une exécution à l'autre (103 ou 95 bits pour le même mot de passe).


## Fichier clé

Le coffre peut exiger un fichier clé en plus du mot de passe maître (clé
composite KeePass : SHA-256(SHA-256(mot de passe) ‖ clé du fichier)).

- Formats acceptés comme KeePassXC : XML v1.0/v2.0 (empreinte v2.0 vérifiée),
  32 octets bruts, 64 caractères hexadécimaux, sinon SHA-256 du fichier. Les
  fichiers créés par KittyPass sont des `.keyx` v2.0 aléatoires (32 octets),
  écrits en `0600` sans jamais écraser un fichier existant.
- Le fichier n'est **jamais** envoyé au serveur. Seul son chemin peut être
  mémorisé dans `profile.json` (case « Mémoriser », comme KeePassXC).
- Seuls les fichiers ordinaires sont lus (pas de tube nommé ni de
  périphérique qui bloquerait la lecture), 512 MiB au plus.
- Ajout, remplacement ou retrait : la nouvelle version chiffrée n'est
  adoptée localement qu'une fois acceptée par le serveur ; hors ligne, rien
  ne change. Les autres appareils, qui ont encore l'ancienne clé, échouent au
  déverrouillage suivant et demandent le fichier.

## Import et export

Tout fichier est lu ou écrit par Rust ; l'interface ne fait que transmettre le
chemin choisi dans la boîte de dialogue du système.

**Import** (CSV, coffre KeePass `.kdbx`, Bitwarden JSON non chiffré,
1Password `.1pux`) : les entrées vont dans un **nouveau groupe** (rien n'est
remplacé), en une seule opération tout-ou-rien.

- Plafonds : fichier ≤ 64 MiB (vérifié avant et pendant la lecture),
  100 000 entrées, 256 attributs par entrée, 16 niveaux de groupes (au-delà,
  le reste du chemin est replié dans un nom), 200 avertissements.
- 1Password : l'archive n'est jamais extraite sur le disque ; la taille
  **décompressée réelle** est bornée (bombes zip), 50 000 fichiers au plus,
  pièces jointes ≤ 16 MiB chacune et 256 MiB au total.
- Les secrets (mot de passe, notes, attributs protégés) ne sont **jamais
  modifiés** : un secret invalide (caractère interdit en XML, trop long) fait
  ignorer l'entrée avec un avertissement qui ne le recopie pas. Les champs
  visibles perdent leurs caractères impossibles ; les noms de groupes,
  d'attributs et de pièces jointes perdent aussi les caractères de contrôle,
  de direction et les séparateurs de chemin.
- Une 2FA illisible est gardée dans l'attribut protégé « TOTP importé » ; une
  clé base32 brute devient un URI `otpauth://`.
- Un attribut nommé comme un champ standard (« Title »…) devient
  « Title (importé) » au lieu d'écraser le champ.
- Coffre KeePass : copie (nouveaux identifiants), sans historique ni
  corbeille, exclusion des rapports conservée.

**Export** :

| Format | Contenu | Chiffré |
|---|---|---|
| Copie `.kdbx` | tout, historique et corbeille compris, avec **sa propre** clé (mot de passe ≥ 10 caractères, fichier clé facultatif) | oui |
| CSV (format KeePassXC) | champs, 2FA, étiquettes ; ni attributs ni pièces jointes | **non** |
| XML KeePass 2.x | champs, attributs, étiquettes, expiration, exclusion, pièces jointes ; pas l'historique | **non** |
| HTML imprimable | tout le texte ; noms des pièces jointes | **non** |

- Exports en clair : avertissement, case à cocher puis confirmation ; la
  corbeille n'est jamais exportée ; fichier écrit en `0600`.
- Écriture refusée dans le dossier de KittyPass (lien symbolique compris) :
  un export ne peut pas écraser le coffre local.
- CSV : les valeurs ne sont pas modifiées. Un tableur peut interpréter une
  valeur commençant par `=`, `+`, `-` ou `@` comme une formule (injection
  CSV) ; l'interface le signale. Les neutraliser altérerait des mots de
  passe réels.
- HTML : tout est échappé, aucun lien cliquable, CSP `default-src 'none'`
  (ni script ni ressource externe), `no-referrer`.

Interopérabilité vérifiée par les tests avec `keepassxc-cli` : import d'un
`.kdbx` et d'un CSV produits par KeePassXC ; XML exporté réimporté par
KeePassXC puis relu à l'identique ; copie `.kdbx` avec fichier clé ouverte par
KeePassXC.

## Intégration navigateur (KeePassXC-Browser)

KittyPass répond à l'extension officielle **KeePassXC-Browser** comme le ferait
KeePassXC 2.7.10 : même protocole, mêmes données dans le coffre. Un coffre
partagé avec KeePassXC garde donc ses associations, ses réglages par entrée et
ses passkeys.

**Chaîne :** extension → messagerie native du navigateur → `kittypass-proxy`
(binaire installé à côté de l'application) → socket Unix
`$XDG_RUNTIME_DIR/kittypass/browser.sock` → `App::browser_request`.

- `core/src/browser/` : `crypto` (NaCl `crypto_box`, nonce incrémenté façon
  libsodium, refus des clés d'ordre faible et du rejeu), `protocol` (enveloppe,
  codes d'erreur 0–33, 1 Mio max), `matching` (correspondance d'URL),
  `passkeys` (WebAuthn ES256 / EdDSA), `transport` (socket, trames u32).
- `core/src/vault/browser.rs` : associations (`KPXC_BROWSER_<nom>` dans les
  données personnalisées du coffre, fusionnées « la plus récente gagne » ; une
  révocation laisse une valeur vide datée pour gagner la fusion), réglages
  `KeePassXC-Browser Settings` `{Allow, Deny, Realm}`, `BrowserHideEntry`,
  URL supplémentaires `KP2A_URL*`, empreinte = SHA-256 de l'UUID racine.
- `app/src/browser.rs` : traitement des actions et confirmations (`Prompter`) ;
  `browser_server.rs` : socket (dossier 0700, socket 0600, UID du pair vérifié) ;
  `browser_hosts.rs` : manifestes des navigateurs.
- `desktop/src/browser.rs` : interrupteur, questions dans la fenêtre
  (`browser_prompt` / `browser_answer`), notifications de verrouillage.

**Interrupteur manuel.** L'extension ne parle qu'à un hôte
(`org.keepassxc.keepassxc_browser`). Activer écrit nos manifestes (Firefox,
LibreWolf, Chromium, Chrome, Brave, Edge, Vivaldi présents dans `$HOME`) et met
celui de KeePassXC de côté en `….json.keepassxc` (jamais écrasé) ; désactiver
le remet. Si KeePassXC a sa propre intégration activée, il réécrit ses
manifestes au lancement : l'interface le signale.

**Règles de sécurité.**
- Le canal chiffré n'authentifie rien : toute action sur le coffre exige une
  association prouvée sur la connexion (`associate`, `test-associate`, ou
  `keys` de `get-logins`) ; comparaison des clés en temps constant. Une
  association ne peut pas en remplacer une autre du même nom.
- Correspondance stricte : même schéma (http → https permis, jamais l'inverse ;
  sans schéma = https), même port, sous-domaine seulement à une frontière de
  label et jamais sur un suffixe public, IP exactes, corbeille et entrées
  masquées exclues.
- Aucun identifiant sans accord : « Autoriser » de l'entrée, ou confirmation
  (avec « Se souvenir » → listes Allow/Deny). Si le formulaire part vers un
  autre hôte, l'autorisation doit le couvrir aussi et la question l'affiche.
- 2FA et mises à jour seulement pour des entrées déjà remises sur cette
  connexion et valables pour le site ; toute mise à jour est confirmée et
  garde l'ancienne version dans l'historique. Les nouveaux identifiants vont
  dans « KeePassXC-Browser Passwords », URL sans requête ni fragment.
- Une question à la fois, abandonnée au bout de 2 minutes ; verrouiller refuse
  les questions en cours. Les requêtes du navigateur ne repoussent pas le
  verrouillage automatique.
- Passkeys : origine https (ou `http://localhost`), RP ID = hôte ou domaine
  parent, jamais un suffixe public (origines liées acceptées si le site les
  publie), défi ≥ 16 octets, identifiant utilisateur 1–64 octets,
  `excludeCredentials` respecté, confirmation à chaque création et connexion.
  Attributs `KPEX_PASSKEY_*` (clé PKCS#8 protégée, jamais envoyée à
  l'interface), AAGUID de KeePassXC, attestation « none », compteur 0,
  drapeaux UP/UV/BE/BS. RSA non proposé (RUSTSEC-2023-0071).
- Le relais refuse un socket dont le dossier n'appartient pas à l'utilisateur
  ou est ouvert aux autres (sinon un autre compte pourrait se faire passer pour
  KittyPass et recevoir les identifiants enregistrés).

**Tests.** Unitaires (cœur), `app/tests/browser.rs` (fausse extension parlant
le vrai protocole : flux complet, abus du protocole, sites piégés, passkeys),
`proxy/tests/relay.rs` (vrai binaire du relais), banc d'essai de l'interface.
Essai réel fait dans Firefox 159 isolé (HOME, profil, données et socket dans
un bac à sable ; extension 1.10.3 ; pilotage WebDriver BiDi) : association,
remplissage, « Se souvenir », passkey créée puis utilisée avec signature
vérifiée par WebCrypto, verrouillage et demande de déverrouillage, retour à
KeePassXC. Le chemin du socket doit rester sous 108 octets (limite Unix).

**À faire :** Windows (canal nommé, manifestes dans le registre), empaquetage
de `kittypass-proxy` dans le .deb / AppImage, enregistrement depuis la bannière
de l'extension testé seulement par les tests d'intégration.

## Paramètres, raccourcis et saisie automatique

**Paramètres** : une seule boîte (bouton « Paramètres », Ctrl+,) avec Apparence, Raccourcis, Saisie auto,
Navigateur, Importer, Exporter, Fichier clé. Coffre verrouillé : seuls Apparence, Raccourcis et Saisie auto
sont proposés (le bouton flottant de l'écran de déverrouillage y mène).

**Raccourcis dans la fenêtre** (réglables, gardés dans le stockage local de l'interface) : par défaut ceux de
KeePassXC (Ctrl+B identifiant, Ctrl+C mot de passe, Ctrl+U URL, Ctrl+T 2FA, Ctrl+Maj+V saisie auto, Ctrl+N,
Ctrl+E, Suppr, Ctrl+F, Ctrl+G, Ctrl+R, Ctrl+L, Ctrl+,). Refusés : combinaisons sans Ctrl/Alt (sauf F1–F12,
Suppr…), Ctrl+A/V/X/Z/Y/S (édition de texte), doublons. Un stockage modifié à la main est revalidé au
chargement. Copier le mot de passe et Suppr gardent leur sens habituel dans un champ ou une sélection.

**Séquences** (`core/src/autotype.rs`) : syntaxe KeePass (`{USERNAME}{TAB}{PASSWORD}{ENTER}`, `{S:Attr}`,
`{TOTP}`, touches, répétitions, modificateurs `+^%#`, `{DELAY n}`, `{DELAY=n}`, `{CLEARFIELD}`). Les valeurs des
champs sont tapées littéralement, jamais réinterprétées. `{CMD}`, `{REF}`, `{PICKCHARS}`, `{T-…}`… sont refusés
(une séquence ne lance rien et ne lit que l'entrée choisie). Bornes : 1024 caractères, répétition ≤ 100, pause
≤ 10 s, 20 000 touches. Les touches compilées (`Typed`) sont effacées de la mémoire après usage.

**Réglages d'entrée** : élément KDBX `AutoType` (activation, séquence, associations fenêtre → séquence avec
joker `*`), lu et écrit aussi par KeePassXC ; modification archivée dans l'historique. Un groupe avec
`EnableAutoType = false` et la corbeille désactivent la saisie ; séquence : association, puis entrée, puis
groupes parents, puis séquence par défaut de l'appareil (`autotype.json`).

**Émulation du clavier** (`desktop/src/autotype/`) :
- Wayland : portail « Bureau à distance » (KDE, GNOME). La disposition réelle est lue auprès du compositeur
  (`wl_keyboard.keymap`, xkbcommon) ; chaque caractère est traduit en code de touche + Maj/AltGr *avant* de
  taper : un caractère absent de la disposition arrête tout au lieu d'être mal tapé (le portail en keysyms
  ignore AltGr : « € » disparaissait sur AZERTY). Autorisation demandée une fois par le bureau ; le jeton de
  restauration est gardé en 0600 (`autotype-portal.token`), révocable dans les réglages du système.
- X11 : XTest. Les caractères passent tous par une touche libre réassignée puis restaurée : la disposition
  annoncée par le serveur peut différer de celle des clients (XWayland annonce « us » sur un clavier AZERTY).
  Attente du relâchement des modificateurs (3 s), Verr. Maj neutralisé puis rétabli.
- Garde-fous : KittyPass se réduit, attend (500 ms par défaut), refuse de taper s'il a encore le focus et
  s'arrête s'il le reprend ; sous X11, s'arrête aussi si la fenêtre active change et refuse sa propre fenêtre.
  Une seule saisie à la fois. Dans la fenêtre, Ctrl+Maj+V attend le relâchement des touches.

**Raccourci global** : portail « Raccourcis globaux » sous Wayland (le bureau fait confirmer), saisie de
touche sur la racine sous X11 (avec ou sans Verr. Maj / Verr. Num). Il ouvre toujours le choix de l'entrée
(pré-rempli sous X11 avec les entrées associées au titre de la fenêtre active) : une fenêtre ne peut pas
obtenir un mot de passe en imitant un titre. Coffre verrouillé : le choix s'ouvre après le déverrouillage.

**Tests réels** (ignorés par défaut) :
`KP_X11_TEST=1 cargo test -p kittypass-desktop -- --ignored x11_types` et
`KP_PORTAL_TEST=1 [KP_PORTAL_DIR=…] cargo test -p kittypass-desktop -- --ignored portal_types` tapent dans un
xterm de test et vérifient le texte reçu (le second demande l'autorisation du bureau).

## Agent SSH

Fonctionnement de KeePassXC : KittyPass n'est pas lui-même un agent, il **ajoute les clés à l'agent SSH du
système** (`SSH_AUTH_SOCK`, ou un socket choisi dans Paramètres › Agent SSH) et les retire. Désactivé par
défaut ; réglages de l'appareil dans `ssh.json`.

**Réglages d'entrée** (`core/src/ssh.rs`, `core/src/vault/ssh.rs`) : pièce jointe `KeeAgent.settings`, format
de KeePassXC (XML UTF-8 ; l'UTF-16 avec BOM du greffon KeeAgent est lu aussi). Autoriser la clé, l'ajouter au
déverrouillage, la retirer au verrouillage, confirmation à chaque usage (contrainte `confirm` de l'agent, qui
passe par ssh-askpass), durée de vie (1 s à 30 jours). Clé en pièce jointe de l'entrée ou dans un fichier de
l'appareil (chemin absolu ou `~/…`, pas de variables). Des réglages par défaut retirent la pièce jointe. Toute
modification va dans l'historique. Réglages illisibles (autre appareil, autre logiciel) : l'entrée est
ignorée, l'éditeur repart des valeurs par défaut. La corbeille n'est jamais utilisée.

**Clés** : format OpenSSH seulement (`ssh-key`, sans DSA). Une clé chiffrée est ouverte avec le mot de passe de
l'entrée, comme dans KeePassXC. L'ancien format PEM est refusé avec la commande de conversion
(`ssh-keygen -p -f fichier`). Taille ≤ 1 Mio. La clé déchiffrée n'existe en mémoire que le temps de l'envoi, dans
des tampons effacés (`Zeroizing`, capacité exacte pour éviter des copies par réallocation). KittyPass ne garde
ensuite que la clé publique, pour savoir quoi retirer.

**Agent** (`app/src/ssh.rs`) : protocole draft-miller-ssh-agent (ajout avec ou sans contraintes, retrait,
liste). Avant tout envoi, KittyPass vérifie que l'agent tourne sous le même utilisateur (`SO_PEERCRED`) : un
socket d'un autre compte ne reçoit rien. Réponses bornées (256 Kio, 1024 clés), délai de 5 s : un faux agent
ne peut ni bloquer ni faire allouer KittyPass. Retrait des clés « à retirer » : verrouillage manuel,
automatique ou demandé par le navigateur, fermeture de l'appli et signaux d'arrêt (SIGTERM, SIGINT, SIGHUP).
Désactiver l'agent retire toutes les clés ajoutées. Une clé qui n'a pas pu être ajoutée au déverrouillage ne
bloque pas celui-ci : elle est signalée dans la barre d'état et dans Paramètres › Agent SSH.

**Tests** : unitaires (réglages piégés, UTF-16, entités XML refusées, clés tronquées ou au mauvais format,
messages et réponses de l'agent), `core/tests/ssh.rs` (KeePassXC relit les pièces jointes et KittyPass relit
le fichier réécrit par KeePassXC), `app/tests/ssh.rs` (vrai `ssh-agent` jetable : ajout au déverrouillage,
retrait au verrouillage, mauvaise phrase de passe, clé non autorisée, fichier, durée de vie, désactivation,
signature par l'agent avec `ssh-keygen -Y sign`, faux agent hostile). Essai réel dans l'appli (tauri-driver) :
pièce jointe, réglages, ajout, signature, verrouillage, déverrouillage, arrêt par SIGTERM.

**À faire :** Windows (canal nommé d'OpenSSH `\\.\pipe\openssh-ssh-agent`, et Pageant).

## Compte (Paramètres › Compte)

- **Administration** (comptes admin seulement, `is_admin` dans `GET /account`) : invitations
  (`POST /admin/invites`, 1 h à 30 j, admin seulement si la 2FA est active), liste des comptes
  (`GET /admin/users`) et désactivation (`POST /admin/users/{nom}/disabled` : sessions fermées,
  connexion refusée ; impossible sur son propre compte). Le serveur ne crée jamais de compte avec
  un mot de passe choisi par l'admin : zero-knowledge.
- **Mot de passe maître** = mot de passe du compte. Changement : le mot de passe actuel et la force du nouveau sont
  vérifiés localement, puis le serveur change la clé d'authentification (nouveau sel) et ferme les autres sessions ;
  enfin le coffre est re-chiffré et envoyé (la version distante, encore sous l'ancienne clé, est lue avec la clé
  précédente gardée en mémoire). Les autres appareils, refusés par le serveur (`invalid_credentials`), demandent le
  nouveau mot de passe : `adopt_master_password` se connecte avec, puis déchiffre le coffre distant avec, avant de
  re-chiffrer le fichier local.
- **2FA** : `setup` → QR code calculé côté Rust (crate `qrcode`), dessiné sur un canvas ; `enable` renvoie 10 codes de
  secours montrés une fois et effacés à la fermeture ; `disable` exige mot de passe et code.
- **Sessions** : liste et révocation ; la session de cet appareil ne peut pas être révoquée d'ici. Une synchro dont la
  session a été révoquée se reconnecte une fois avec le mot de passe du coffre ouvert.
- **Versions** : jamais de retour en arrière destructif. Une version est importée dans un nouveau groupe (même code que
  l'import KDBX), ce qui survit à la fusion avec les autres appareils ; ou enregistrée telle quelle, hors du dossier
  de KittyPass.
- **Verrouillage automatique** : `lock.json`, 30 s à 24 h ou jamais ; un fichier invalide donne 5 min, jamais « jamais ».
