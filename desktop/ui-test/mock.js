// Fausse API Tauri pour tester l'interface dans un navigateur, avec un coffre
// en mémoire. Les données contiennent des charges XSS partout : si l'une
// s'exécute, window.__xss est défini.
(() => {
"use strict";
window.__calls = [];
window.__clipboard = null;
const XSS = '<img src=x onerror="window.__xss=1">';
const now = () => Math.floor(Date.now() / 1000);
let seq = 100;
const uid = () => `00000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;

const db = {
  configured: true,
  unlocked: false,
  groups: [
    { id: "root", parent: null, name: "Racine" },
    { id: "g-perso", parent: "root", name: "Perso" },
    { id: "g-xss", parent: "root", name: XSS },
    { id: "g-sub", parent: "g-perso", name: "Banques" },
    { id: "bin", parent: "root", name: "Corbeille", bin: true },
  ],
  entries: [
    {
      id: "e1", group: "root", title: XSS, username: "<script>window.__xss=2</script>", url: "javascript:window.__xss=3",
      notes: "<svg onload=window.__xss=4>", password: "pw-1", otp: null, tags: [XSS, "a;b"], expires: null,
      custom: [{ key: XSS, value: "<b onmouseover=window.__xss=5>", protected: false }, { key: "PIN", value: "1234", protected: true }],
      attachments: [{ name: '"><img src=x onerror=window.__xss=6>.txt', size: 12 }], history: [], modified: now() - 86400,
    },
    {
      id: "e2", group: "g-sub", title: "Banque", username: "alice", url: "https://banque.example", notes: "ligne 1\nligne 2",
      password: "s3cret-banque", otp: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", tags: ["finance"], expires: now() - 3600,
      custom: [], attachments: [], modified: now() - 3600,
      history: [{ title: "Banque (ancien)", username: "alice", url: "https://old.example", notes: XSS, password: "ancien-mdp", modified: now() - 7200 }],
    },
    {
      id: "e3", group: "g-perso", title: "Mail", username: "bob", url: "https://mail.example", notes: "", password: "mail-pw",
      otp: null, tags: [], expires: now() + 30 * 86400, custom: [], attachments: [], history: [], modified: now(),
    },
  ],
};

const err = (code, message) => Promise.reject({ code, message });
const locked = () => (db.unlocked ? null : err("locked", "coffre verrouillé"));
const entry = (id) => db.entries.find((e) => e.id === id) || (() => { throw { code: "error", message: "entrée introuvable" }; })();
const within = (gid, anc) => {
  for (let g = db.groups.find((x) => x.id === gid); g; g = db.groups.find((x) => x.id === g.parent)) if (g.id === anc) return true;
  return false;
};
const inBin = (gid) => within(gid, "bin");
const tree = (g) => ({
  id: g.id, name: g.name, icon: null, is_recycle_bin: Boolean(g.bin),
  entry_count: db.entries.filter((e) => e.group === g.id).length,
  children: db.groups.filter((c) => c.parent === g.id).sort((a, b) => Boolean(a.bin) - Boolean(b.bin) || a.name.localeCompare(b.name)).map(tree),
});
const item = (e) => ({ id: e.id, group_id: e.group, title: e.title, username: e.username, url: e.url, tags: e.tags, expires: e.expires, expired: e.expires != null && e.expires <= now(), modified: e.modified });
const view = (e) => ({
  id: e.id, group_id: e.group, in_recycle_bin: inBin(e.group), title: e.title, username: e.username, url: e.url, notes: e.notes,
  has_totp: Boolean(e.otp), tags: e.tags, expires: e.expires,
  custom: e.custom.map((c) => ({ key: c.key, value: c.protected ? null : c.value, protected: c.protected })),
  attachments: e.attachments,
  history: e.history.map((h, index) => ({ index, modified: h.modified, title: h.title, username: h.username, url: h.url })),
});
const snapshot = (e) => ({ title: e.title, username: e.username, url: e.url, notes: e.notes, password: e.password, modified: e.modified, custom: e.custom });
const matches = (e, q) => {
  q = q.toLowerCase();
  if (q.startsWith("tag:")) return e.tags.some((t) => t.toLowerCase().includes(q.slice(4).replace(/"/g, "")));
  if (q === "is:expired") return e.expires != null && e.expires <= now();
  return (e.title + e.username + e.url + e.notes + e.tags.join(" ")).toLowerCase().includes(q);
};
function secretOf(e, field) {
  if (field === "password") return e.password;
  if (field === "username") return e.username;
  if (field === "url") return e.url;
  if (field === "totp") return "123456";
  if (field && field.custom) return e.custom.find((c) => c.key === field.custom).value;
  throw { code: "error", message: "champ inconnu" };
}

const handlers = {
  status: () => ({
    configured: db.configured, unlocked: db.unlocked, server_url: "https://coffre.example", username: "alice", last_seen: 3,
    key_file: db.rememberedKey ?? null, has_key_file: db.unlocked && Boolean(db.keyFile),
  }),
  unlock: ({ password }) => handlers.unlock_with_key_file({ password, keyFile: db.rememberedKey ?? null, remember: db.rememberedKey != null }),
  unlock_with_key_file: ({ password, keyFile, remember }) => {
    if (password !== "correct-password-123" || (keyFile ?? null) !== (db.keyFile ?? null)) return err("invalid_password", "mot de passe incorrect");
    db.unlocked = true;
    db.rememberedKey = remember ? keyFile : null;
    return null;
  },
  // Boîtes de dialogue du système : le test fixe la réponse dans window.__nextPick.
  pick_file: ({ purpose }) => { window.__pickPurpose = purpose; const p = window.__nextPick ?? null; window.__nextPick = null; return p; },
  generate_key_file: () => window.__nextKeyFile ?? null,
  set_key_file: ({ change }) => {
    if (!db.unlocked) return err("locked", "coffre verrouillé");
    if (change.password !== "correct-password-123") return err("invalid_password", "mot de passe incorrect");
    if (window.__offline) return err("network", "serveur injoignable");
    db.keyFile = change.key_file;
    db.rememberedKey = change.remember ? change.key_file : null;
    return { version: 5, pulled: 0, pushed: true };
  },
  import_file: ({ req }) => new Promise((resolve, reject) => setTimeout(() => {
    if (!db.unlocked) return reject({ code: "locked", message: "coffre verrouillé" });
    if (req.format === "kdbx" && req.password !== "source-password-1") return reject({ code: "invalid_password", message: "mot de passe incorrect" });
    window.__importReq = req;
    const gid = uid();
    db.groups.push({ id: gid, parent: req.parent, name: req.name || "import " + XSS });
    db.entries.push({ id: uid(), group: gid, title: "Importée " + XSS, username: "u", url: "", notes: "", password: "pw", tags: [], custom: [], attachments: [], history: [], modified: now(), expires: null });
    resolve({ group_id: gid, imported: 1, skipped: 1, warnings: ["« " + XSS + " » ignorée : mot de passe trop long"] });
  }, window.__importDelay ?? 0)),
  export_file: ({ req }) => { if (!db.unlocked) return err("locked", "coffre verrouillé"); window.__exportReq = req; return window.__exportCancel ? false : true; },
  lock: () => { db.unlocked = false; },
  touch: () => null,
  groups: () => locked() || tree(db.groups[0]),
  tags: () => {
    const m = new Map();
    for (const e of db.entries) if (!inBin(e.group)) for (const t of e.tags) m.set(t, (m.get(t) || 0) + 1);
    return [...m.entries()].sort();
  },
  add_group: ({ parent, name }) => { const id = uid(); db.groups.push({ id, parent, name }); return id; },
  rename_group: ({ id, name }) => { db.groups.find((g) => g.id === id).name = name; },
  move_group: ({ id, parent }) => { if (within(parent, id)) return err("error", "déplacement de groupe impossible"); db.groups.find((g) => g.id === id).parent = parent; },
  delete_group: ({ id }) => {
    if (inBin(id)) { db.groups = db.groups.filter((g) => !within(g.id, id)); db.entries = db.entries.filter((e) => db.groups.some((g) => g.id === e.group)); }
    else db.groups.find((g) => g.id === id).parent = "bin";
  },
  restore_group: ({ id }) => { db.groups.find((g) => g.id === id).parent = "root"; },
  empty_recycle_bin: () => {
    const before = db.entries.length;
    db.groups = db.groups.filter((g) => g.id === "bin" || !inBin(g.id));
    db.entries = db.entries.filter((e) => !inBin(e.group) && db.groups.some((g) => g.id === e.group));
    return before - db.entries.length;
  },
  entries: ({ query, group }) => locked() || {
    items: db.entries
      .filter((e) => (query ? matches(e, query) && !inBin(e.group) && (!group || within(e.group, group)) : group ? e.group === group : !inBin(e.group)))
      .map(item),
    truncated: false,
  },
  entry: ({ id }) => locked() || view(entry(id)),
  history_entry: ({ id, index }) => { const e = entry(id); const h = e.history[index]; return { ...view(e), ...h, has_totp: false, custom: [], attachments: [], history: [] }; },
  reveal: ({ id, field, history }) => locked() || secretOf(history == null ? entry(id) : entry(id).history[history], field),
  totp: () => ({ code: "123456", remaining: 17, period: 30 }),
  copy: ({ id, field, history }) => { window.__clipboard = secretOf(history == null ? entry(id) : entry(id).history[history], field); return 30; },
  copy_value: ({ value }) => { window.__clipboard = value; return 30; },
  generate: ({ opts }) => {
    if (opts.kind === "passphrase") {
      if (opts.words < 1 || opts.words > 100) return err("error", "nombre de mots hors limites");
      return { value: Array(opts.words).fill("chat").join(opts.separator), entropy: opts.words * 12.92 };
    }
    if (opts.length < 8) return err("error", "longueur hors limites");
    return { value: "G".repeat(opts.length), entropy: opts.length * 6.5 };
  },
  add_entry: ({ group, input }) => {
    const id = uid();
    db.entries.push({ id, group: group || "root", ...input, otp: input.otp, custom: input.custom.map((c) => ({ key: c.key, value: c.value ?? "", protected: c.protected })), attachments: [], history: [], modified: now() });
    return id;
  },
  update_entry: ({ id, input }) => {
    const e = entry(id);
    e.history.unshift(snapshot(e));
    const custom = input.custom.map((c) => {
      if (c.value !== null) return { key: c.key, value: c.value, protected: c.protected };
      const old = e.custom.find((x) => x.key === (c.original_key || c.key));
      if (!old) throw { code: "error", message: "valeur d'attribut manquante" };
      return { key: c.key, value: old.value, protected: c.protected };
    });
    Object.assign(e, input, { custom, otp: input.keep_otp ? e.otp : input.otp, modified: now() });
    delete e.keep_otp;
  },
  clone_entry: ({ id }) => { const e = entry(id); const c = { ...structuredClone(e), id: uid(), title: e.title + " (copie)" }; db.entries.push(c); return c.id; },
  expire_entry: ({ id }) => { entry(id).expires = now(); },
  set_entry_tags: ({ id, tags }) => { entry(id).tags = tags; },
  open_entry_url: ({ id }) => { window.__opened = entry(id).url; },
  biometric_status: () => ({ available: true, enabled: Boolean(db.bio), reason: null }),
  autofill_status: () => ({ supported: false, enabled: false }),
  autofill_settings: () => null,
  biometric_enable: ({ password }) => (password === "correct-password-123" ? void (db.bio = true) : err("invalid_password", "mot de passe incorrect")),
  biometric_disable: () => { db.bio = false; },
  biometric_unlock: () => { db.unlocked = true; },
  forget_favicon: () => null,
  update_check: () => ({ current: "1.0.0", latest: "1.1.0", notes: "Nouveautés :\n- exemple", installable: true }),
  update_install: () => null,
  update_open_page: () => null,
  delete_entry: ({ id }) => { const e = entry(id); if (inBin(e.group)) db.entries = db.entries.filter((x) => x !== e); else { e.prev = e.group; e.group = "bin"; } },
  restore_entry: ({ id }) => { const e = entry(id); e.group = e.prev || "root"; },
  move_entry: ({ id, group }) => { entry(id).group = group; },
  restore_history: ({ id, index }) => { const e = entry(id); const h = e.history[index]; e.history.unshift(snapshot(e)); Object.assign(e, h, { modified: now() }); },
  attach_file: ({ id }) => { const name = window.__nextAttachment || null; if (name) entry(id).attachments.push({ name, size: 42 }); return name; },
  export_attachment: ({ id, name }) => { window.__exported = [id, name]; return true; },
  remove_attachment: ({ id, name }) => { const e = entry(id); e.attachments = e.attachments.filter((a) => a.name !== name); },
  strength: ({ input }) => {
    const pw = input.password;
    const bits = pw ? (new Set(pw).size * pw.length) / 2 : 0;
    const q = !(bits > 0) ? "bad" : bits < 40 ? "poor" : bits < 75 ? "weak" : bits < 100 ? "good" : "excellent";
    window.__strengthCalls = (window.__strengthCalls || 0) + 1;
    return { bits, quality: q };
  },
  health_report: () => locked() || (() => {
    const live = db.entries.filter((e) => !inBin(e.group) && e.password);
    const items = [];
    for (const e of live) {
      const bits = e.password.length * 4;
      const quality = bits < 40 ? "poor" : bits < 75 ? "weak" : bits < 100 ? "good" : "excellent";
      const reused = live.filter((x) => x !== e && x.password === e.password).length;
      const expired = e.expires != null && e.expires <= now();
      if (bits < 75 || reused || expired) items.push({ entry: item(e), bits, quality, reused, expired, excluded: Boolean(e.excluded) });
    }
    items.sort((a, b) => a.bits - b.bits);
    return { items, checked: live.length, excluded: live.filter((e) => e.excluded).length };
  })(),
  set_excluded_from_reports: ({ id, excluded }) => { const e = entry(id); e.excluded = excluded; e.modified = now(); },
  hibp_check: () => locked() || new Promise((resolve, reject) => setTimeout(() => {
    if (!db.unlocked) return reject({ code: "locked", message: "coffre verrouillé" });
    if (window.__hibpFail) return reject({ code: "network", message: "serveur injoignable" });
    const live = db.entries.filter((e) => !inBin(e.group) && e.password);
    const pwned = { "pw-1": 9659365, "mail-pw": 1234 };
    const items = live.filter((e) => pwned[e.password]).map((e) => ({ entry: item(e), count: pwned[e.password], excluded: Boolean(e.excluded) }));
    items.sort((a, b) => b.count - a.count);
    resolve({ items, checked: live.length, queries: live.length });
  }, 300)),
  sync: () => (window.__syncNeedsTotp ? ((window.__syncNeedsTotp = false), err("totp_required", "code 2FA requis")) : { version: 4, pulled: 0, pushed: true }),
  browser_status: () => ({
    enabled: Boolean(db.browserEnabled),
    running: Boolean(db.browserEnabled),
    hosts: {
      browsers: [
        { browser: "Firefox", owner: db.browserEnabled ? "kitty_pass" : "kee_pass_xc", backup: Boolean(db.browserEnabled) },
        { browser: "Chromium", owner: db.browserEnabled ? "kitty_pass" : "none", backup: false },
      ],
      keepassxc_overrides: Boolean(window.__kpxcOverrides),
    },
  }),
  browser_set_enabled: ({ enabled }) => { db.browserEnabled = enabled; return handlers.browser_status(); },
  browser_answer: ({ id, answer }) => { (window.__answers ||= []).push({ id, answer }); },
  browser_associations: () => locked() || (db.assoc ||= [{ id: "Firefox perso", created: 1800000000 }]),
  browser_revoke: ({ id }) => { db.assoc = (db.assoc || []).filter((a) => a.id !== id); return true; },
  entry_browser: ({ id }) => locked() || structuredClone(entry(id).browser ?? { hidden: false, allow: ["example.org"], deny: ["evil.example"] }),
  set_entry_browser: ({ id, view }) => { entry(id).browser = structuredClone(view); window.__entryBrowser = [id, view]; },
  autotype_status: () => ({ config: structuredClone(db.autotype ??= { default_sequence: "{USERNAME}{TAB}{PASSWORD}{ENTER}", key_delay_ms: 25, start_delay_ms: 500, global_shortcut: null, method: "auto" }), effective: "portal", wayland: true }),
  save_autotype_config: ({ config }) => {
    if (config.default_sequence.includes("{CMD")) return err("error", "saisie automatique : paramètre non pris en charge : {CMD}");
    db.autotype = structuredClone(config);
    return handlers.autotype_status();
  },
  entry_autotype: ({ id }) => locked() || structuredClone(entry(id).autotype ?? { enabled: true, sequence: null, associations: [] }),
  set_entry_autotype: ({ id, view }) => { entry(id).autotype = structuredClone(view); window.__entryAutotype = [id, view]; },
  autotype_matches: ({ window: w }) => locked() || db.entries.filter((e) => w.toLowerCase().includes(e.title.toLowerCase())).map((e) => ({ id: e.id, group_id: e.group_id, title: e.title, username: e.username, url: e.url, tags: e.tags ?? [], expires: null, expired: false, modified: null })),
  autotype_entry: (args) => locked() || void (globalThis.__typed = [args.id, args.window]),
  ssh_status: () => {
    const config = structuredClone(db.ssh ??= { enabled: false, socket: null });
    const keys = config.enabled ? Object.entries(db.sshAgent ??= {}).map(([entry, k]) => ({ fingerprint: k.fingerprint, comment: k.comment, entry })) : [];
    return { config, socket: config.socket ?? "/run/user/1000/agent", available: config.enabled, error: null, keys, unlock_errors: config.enabled ? ['Serveur ' + XSS + ' : phrase de passe incorrecte'] : [] };
  },
  save_ssh_config: ({ config }) => {
    if (config.socket && !config.socket.startsWith("/")) return err("error", "agent SSH : le chemin de l'agent doit être absolu");
    db.ssh = structuredClone(config);
    if (!config.enabled) db.sshAgent = {};
    return handlers.ssh_status();
  },
  entry_ssh: ({ id }) => {
    const e = locked() || entry(id);
    const s = structuredClone(e.ssh ?? { allow: false, add_at_open: false, remove_at_close: false, confirm: false, use_lifetime: false, lifetime_secs: 600, use_attachment: false, attachment_name: "", file_name: "", save_attachment_to_temp_file: false });
    const has = s.use_attachment ? e.attachments.some((a) => a.name === s.attachment_name) : Boolean(s.file_name);
    const key = has ? { algorithm: "ssh-ed25519", fingerprint: "SHA256:abc", comment: XSS, encrypted: true, public_key: "ssh-ed25519 AAAAC3 test" } : null;
    return { settings: s, key, key_error: has || !s.allow ? null : "agent SSH : aucun fichier de clé indiqué", in_agent: Boolean(db.sshAgent?.[id]) };
  },
  set_entry_ssh: ({ id, settings }) => {
    if (settings.use_lifetime && settings.lifetime_secs < 1) return err("error", "agent SSH : durée de vie hors limites");
    entry(id).ssh = structuredClone(settings); window.__entrySsh = [id, settings];
  },
  ssh_add: ({ id }) => {
    if (!db.ssh?.enabled) return err("error", "agent SSH : l'agent SSH est désactivé dans les paramètres");
    (db.sshAgent ??= {})[id] = { fingerprint: "SHA256:abc", comment: XSS };
  },
  ssh_remove: ({ id }) => { delete db.sshAgent?.[id]; },
  lock_config: () => structuredClone(db.lock ??= { auto_lock_secs: 300 }),
  save_lock_config: ({ config }) => (db.lock = structuredClone(config)),
  account: () => ({ username: XSS, totp_enabled: Boolean(db.tfa), require_2fa: false, is_admin: true }),
  favicon: ({ url }) => (url && url.includes("example") ? "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==" : null),
  create_invite: ({ admin, hours }) => ({ code: "INVITE-" + hours, expires_in_hours: hours, admin, server_url: "https://kp.example" }),
  users: () => structuredClone(db.users ??= [
    { username: "alice", is_admin: true, totp_enabled: true, disabled: false, created_at: 1790000000, current: true },
    { username: XSS, is_admin: false, totp_enabled: false, disabled: false, created_at: 1795000000, current: false },
  ]),
  set_user_disabled: ({ username, disabled }) => { db.users.find((u) => u.username === username).disabled = disabled; },
  sessions: () => structuredClone(db.sessions ??= [
    { id: "s1", device: "Portable", created_at: 1800000000, last_seen: 1800000500, current: true },
    { id: "s2", device: XSS, created_at: 1790000000, last_seen: 1795000000, current: false },
  ]),
  revoke_session: ({ id }) => { db.sessions = db.sessions.filter((s) => s.id !== id); },
  revoke_other_sessions: () => { const n = db.sessions.filter((s) => !s.current).length; db.sessions = db.sessions.filter((s) => s.current); return n; },
  change_master_password: ({ current }) => (current === "mot-de-passe-actuel" ? { version: 9, pulled: 0, pushed: true } : err("invalid_password", "mot de passe incorrect")),
  adopt_master_password: ({ password }) => (password === "nouveau-mot-de-passe" ? { version: 9, pulled: 1, pushed: false } : err("invalid_credentials", "identifiants invalides")),
  setup_2fa: () => ({ secret: "JBSWY3DPEHPK3PXP", uri: "otpauth://totp/KittyPass:alice?secret=JBSWY3DPEHPK3PXP", qr_size: 25, qr: Array.from({ length: 625 }, (_, i) => ((i * 7) % 3 === 0)) }),
  enable_2fa: ({ code }) => (code === "123456" ? ((db.tfa = true), ["AAAA-BBBB-CCCC-DDDD", XSS]) : err("invalid_totp", "code 2FA incorrect")),
  disable_2fa: ({ code }) => (code === "123456" ? void (db.tfa = false) : err("invalid_credentials", "identifiants invalides")),
  vault_versions: () => [{ version: 8, created_at: 1800000000, size: 4096 }, { version: 7, created_at: 1799000000, size: 4000 }],
  restore_version: ({ req }) => (req.version === 7 && req.password !== "ancien" ? err("invalid_password", "mot de passe incorrect") : (window.__restored = req, { group_id: db.groups?.[0]?.id ?? "root", imported: 3, skipped: 0, warnings: [] })),
  save_version: () => true,
  relogin: ({ totp }) => (totp === "654321" ? null : err("invalid_credentials", "identifiants invalides")),
};
window.__db = db;
window.__TAURI__ = {
  core: {
    invoke: async (cmd, args) => {
      window.__calls.push([cmd, args]);
      const h = handlers[cmd];
      if (!h) throw { code: "error", message: "commande inconnue " + cmd };
      return await h(args || {});
    },
  },
  app: { getVersion: async () => "1.0.0" },
  event: { listen: async (ev, cb) => { (window.__listeners ||= {})[ev] = cb; return () => {}; } },
};
})();
