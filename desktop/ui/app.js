// Interface KittyPass. Règle de sécurité : les données du coffre ne sont
// jamais insérées en HTML (pas d'innerHTML), uniquement via textContent ou
// des éléments créés un à un, pour qu'un titre piégé ne puisse pas exécuter
// de script. Les secrets (mots de passe, liens 2FA, attributs protégés) ne
// sont demandés au cœur Rust qu'à l'affichage explicite ; les copies se
// font côté Rust.
"use strict";

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const listen = (ev, cb) => window.__TAURI__.event.listen(ev, cb);
const emit = (ev, payload) => window.__TAURI__.event.emit(ev, payload);
/** Fenêtre « accès rapide » (bureau) : seulement les demandes du navigateur
 *  et le choix de la saisie automatique. La fenêtre principale lui laisse ces
 *  demandes ; sous Android, sans fenêtre rapide, elle les traite elle-même. */
const QUICK = window.__TAURI_INTERNALS__?.metadata?.currentWindow?.label === "quick";
const PROMPTS_HERE = QUICK || /Android/i.test(navigator.userAgent);
if (QUICK) document.body.classList.add("quick");
/** Fenêtre rapide : sa hauteur suit ce qu'elle montre (boîte ouverte ou
 *  déverrouillage). */
function fitQuick() {
  if (!QUICK) return;
  requestAnimationFrame(() => {
    const dlg = document.querySelector("dialog[open]");
    const box = dlg ?? (!$("view-unlock").hidden ? $("view-unlock") : null);
    if (!box) return;
    const prev = box.style.maxHeight;
    box.style.maxHeight = "none";
    const h = Math.ceil(box.scrollHeight);
    box.style.maxHeight = prev;
    invoke("quick_resize", { height: h }).catch(() => {});
  });
}
if (QUICK) {
  new MutationObserver(fitQuick).observe(document.body, { subtree: true, attributes: true, attributeFilter: ["open", "hidden"], childList: true });
}
/** Fenêtre rapide sans rien à montrer : elle se cache. */
function quickIdle() {
  if (QUICK && !$("view-main").hidden && !document.querySelector("dialog[open]")) invoke("quick_hide").catch(() => {});
}
const $ = (id) => document.getElementById(id);
const MASK = "••••••••••";

/** Crée un élément : `el("td", { className: "x" }, "texte", autreElement)`. */
function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "dataset") Object.assign(e.dataset, v);
    else if (k.startsWith("aria") || k === "role" || k === "title" || k === "draggable") e.setAttribute(toAttr(k), v);
    else e[k] = v;
  }
  for (const c of children) e.append(c instanceof Node ? c : document.createTextNode(String(c ?? "")));
  return e;
}
const toAttr = (k) => (k.startsWith("aria") ? "aria-" + k.slice(4).toLowerCase() : k);

function icon(name) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  const use = document.createElementNS(ns, "use");
  use.setAttribute("href", "#i-" + name);
  svg.append(use);
  return svg;
}

const state = {
  group: null, // groupe sélectionné
  root: null, // arbre des groupes
  binId: null,
  items: [], // liste affichée
  selected: null, // entrée sélectionnée
  view: null, // fiche de l'entrée sélectionnée
  sort: { key: "title", dir: 1 },
  editing: null, // { id|null, view|null }
  totpTimer: null,
  collapsed: new Set(),
  historyIndex: null,
};

// ---------------------------------------------------------------- utilitaires

function show(view) {
  for (const v of ["setup", "unlock", "main"]) $("view-" + v).hidden = v !== view;
  document.body.classList.toggle("main-view", view === "main");
}

function errorText(e) {
  if (e && typeof e === "object" && e.message) return e.message;
  return String(e);
}

let statusTimer = 0;
function setStatus(text) {
  $("status").textContent = text;
  // Téléphone : le message est une bulle au-dessus de la barre du bas, effacée après quelques secondes.
  clearTimeout(statusTimer);
  if (text && window.matchMedia("(max-width: 640px)").matches) {
    statusTimer = setTimeout(() => { if ($("status").textContent === text) $("status").textContent = ""; }, 4000);
  }
}

async function busy(button, fn) {
  button.disabled = true;
  try {
    return await fn();
  } finally {
    button.disabled = false;
  }
}

const dateFmt = new Intl.DateTimeFormat("fr-FR", { dateStyle: "short", timeStyle: "short" });
const fmtDate = (ts) => (ts == null ? "" : dateFmt.format(new Date(ts * 1000)));
const fmtSize = (n) => (n < 1024 ? `${n} o` : n < 1048576 ? `${(n / 1024).toFixed(1)} Kio` : `${(n / 1048576).toFixed(1)} Mio`);
const nowSecs = () => Math.floor(Date.now() / 1000);

/** Lien cliquable seulement pour http(s) : jamais de javascript:, file:… */
function urlNode(url) {
  if (/^https?:\/\//i.test(url)) {
    return el("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, url);
  }
  return document.createTextNode(url);
}

/** Boîte de confirmation ou de saisie. Résout avec true/false, ou le texte saisi (null si annulé). */
function ask(message, { input = null, ok = "OK", danger = false, secret = false } = {}) {
  const dlg = $("ask-dialog");
  const form = $("ask-form");
  $("ask-message").textContent = message;
  const field = $("ask-input");
  field.hidden = input === null;
  field.type = secret ? "password" : "text";
  field.value = input ?? "";
  $("ask-ok").textContent = ok;
  $("ask-ok").className = danger ? "danger" : "primary";
  dlg.showModal();
  (input === null ? $("ask-ok") : field).focus();
  if (input !== null) field.select();
  return new Promise((resolve) => {
    const done = (value) => {
      form.removeEventListener("submit", onOk);
      $("ask-cancel").removeEventListener("click", onCancel);
      dlg.removeEventListener("cancel", onCancel);
      dlg.close();
      field.value = "";
      resolve(value);
    };
    const onOk = (ev) => {
      ev.preventDefault();
      done(input === null ? true : field.value);
    };
    const onCancel = (ev) => {
      ev.preventDefault();
      done(input === null ? false : null);
    };
    form.addEventListener("submit", onOk);
    $("ask-cancel").addEventListener("click", onCancel);
    dlg.addEventListener("cancel", onCancel);
  });
}

function setupTabs(attr, onChange) {
  const tabs = document.querySelectorAll(`[data-${attr}tab]`);
  for (const t of tabs) {
    t.addEventListener("click", () => selectTab(attr, t.dataset[attr + "tab"], onChange));
  }
}

function selectTab(attr, name, onChange) {
  for (const t of document.querySelectorAll(`[data-${attr}tab]`)) {
    t.setAttribute("aria-selected", String(t.dataset[attr + "tab"] === name));
  }
  for (const p of document.querySelectorAll(`[data-${attr}panel]`)) {
    p.hidden = p.dataset[attr + "panel"] !== name;
  }
  if (onChange) onChange(name);
}

// ---------------------------------------------------------------- démarrage

async function refresh() {
  const s = await invoke("status");
  if (!s.configured) return show("setup");
  if (!s.unlocked) {
    $("unlock-account").textContent = `${s.username} — ${s.server_url}`;
    unlockKey.path = s.key_file ?? null;
    $("unlock-keyfile-remember").checked = s.key_file != null;
    renderKeyPath("unlock", unlockKey.path, "Aucun");
    show("unlock");
    $("unlock-form").password.focus();
    showBioUnlock();
    return;
  }
  show("main");
  $("status-right").textContent = `${s.username} — ${s.server_url}`;
  if (!QUICK) {
    await loadGroups();
    await loadEntries();
  }
  // Raccourci global pressé pendant que le coffre était verrouillé.
  if (atPending) {
    const w = atPending.window;
    atPending = null;
    openAutotypePicker(w);
  }
}

// ---------------------------------------------------------------- configuration

/** Chemins de fichiers clés choisis (jamais leur contenu, lu par Rust). */
const setupKey = { path: null };
const unlockKey = { path: null };

function renderKeyPath(prefix, path, none) {
  const span = $(prefix + "-keyfile-path");
  span.textContent = path ?? none;
  span.title = path ?? "";
  span.classList.toggle("muted", path == null);
  $(prefix + "-keyfile-clear").hidden = path == null;
}

async function pickPath(purpose) {
  try {
    return await invoke("pick_file", { purpose });
  } catch (e) {
    await ask(errorText(e), { ok: "Fermer" });
    return null;
  }
}

/** Crée un fichier clé (emplacement choisi dans la boîte du système). */
async function newKeyFile() {
  try {
    const path = await invoke("generate_key_file");
    if (path) await ask(`Fichier clé créé : ${path}. Sauvegardez-le en lieu sûr : sans lui, le coffre ne peut plus être ouvert.`, { ok: "Compris" });
    return path;
  } catch (e) {
    await ask(errorText(e), { ok: "Fermer" });
    return null;
  }
}

$("setup-keyfile-pick").addEventListener("click", async () => {
  const p = await pickPath("key_file");
  if (p) renderKeyPath("setup", (setupKey.path = p), "Aucun");
});
$("setup-keyfile-new").addEventListener("click", async () => {
  const p = await newKeyFile();
  if (p) renderKeyPath("setup", (setupKey.path = p), "Aucun");
});
$("setup-keyfile-clear").addEventListener("click", () => renderKeyPath("setup", (setupKey.path = null), "Aucun"));
$("unlock-keyfile-pick").addEventListener("click", async () => {
  const p = await pickPath("key_file");
  if (p) {
    renderKeyPath("unlock", (unlockKey.path = p), "Aucun");
    $("unlock-form").password.focus();
  }
});
$("unlock-keyfile-clear").addEventListener("click", () => {
  renderKeyPath("unlock", (unlockKey.path = null), "Aucun");
  $("unlock-keyfile-remember").checked = false;
});

const setupForm = $("setup-form");
setupForm.addEventListener("change", () => {
  document.body.classList.toggle("join", setupForm.mode.value === "join");
});

setupForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = setupForm;
  $("setup-error").textContent = "";
  if (f.mode.value === "create" && f.password.value !== f.confirm.value) {
    $("setup-error").textContent = "Les deux mots de passe ne correspondent pas.";
    return;
  }
  const req = {
    mode: f.mode.value,
    server_url: f.server_url.value.trim(),
    username: f.username.value.trim(),
    password: f.password.value,
    invite: f.mode.value === "create" ? f.invite.value.trim() || null : null,
    totp: f.totp.value.trim() || null,
    device: f.device.value.trim(),
    key_file: setupKey.path,
    remember_key_file: setupKey.path != null && $("setup-keyfile-remember").checked,
  };
  try {
    const mustSetup2fa = await busy(f.querySelector("button[type=submit]"), () => invoke("setup", { req }));
    f.reset();
    renderKeyPath("setup", (setupKey.path = null), "Aucun");
    if (mustSetup2fa) await ask("Le serveur exige la 2FA : configurez-la avant d'accéder au coffre.", { ok: "Compris" });
    await refresh();
  } catch (e) {
    if (e.code === "totp_required") {
      $("setup-totp").hidden = false;
      f.totp.focus();
    }
    $("setup-error").textContent = errorText(e);
  }
});

// ---------------------------------------------------------------- verrouillage

$("unlock-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("unlock-error").textContent = "";
  try {
    const args = { password: f.password.value, keyFile: unlockKey.path, remember: unlockKey.path != null && $("unlock-keyfile-remember").checked };
    await busy(f.querySelector("button[type=submit]"), () => invoke("unlock_with_key_file", args));
    f.reset();
    await refresh();
    emit("unlocked").catch(() => {});
    if (QUICK) return quickIdle();
    // Après la synchro, dont le message remplacerait celui de l'agent SSH.
    syncNow(false).finally(reportSshUnlock);
  } catch (e) {
    $("unlock-error").textContent =
      e.code === "invalid_password"
        ? unlockKey.path
          ? "Mot de passe ou fichier clé incorrect."
          : "Mot de passe incorrect (ce coffre demande peut-être un fichier clé)."
        : errorText(e);
    f.password.select();
  }
});

/** Efface de l'écran tout ce qui vient du coffre (champs d'édition compris). */
function wipeScreen() {
  clearInterval(state.totpTimer);
  closeEditor(true);
  dropBrowserPrompts();
  $("gen-output").value = "";
  if ($("gen-dialog").open) $("gen-dialog").close();
  wipeReports();
  wipeVaultDialog();
  wipeAutotype();
  wipeSsh();
  $("tree").replaceChildren();
  $("taglist").replaceChildren();
  $("entries-body").replaceChildren();
  $("search").value = "";
  Object.assign(state, { group: null, root: null, items: [], selected: null, view: null, historyIndex: null });
  showPreview(null);
}

async function lockNow() {
  wipeScreen();
  await invoke("lock");
  await refresh();
}
$("btn-lock").addEventListener("click", lockNow);
// Déverrouillé dans l'autre fenêtre.
listen("unlocked", async () => {
  if (!$("view-main").hidden) return;
  await refresh();
  if (QUICK) quickIdle();
  else syncNow(false).finally(reportSshUnlock);
});
listen("locked", () => {
  wipeScreen();
  refresh();
});

// Toute activité repousse le verrouillage automatique (au plus une fois / 10 s).
let lastTouch = 0;
for (const ev of ["keydown", "mousedown", "mousemove", "wheel"]) {
  window.addEventListener(ev, () => {
    const now = Date.now();
    if (now - lastTouch > 10000 && !$("view-main").hidden) {
      lastTouch = now;
      invoke("touch");
    }
  }, { passive: true });
}

// ---------------------------------------------------------------- groupes

// Groupe ouvert au démarrage (par appareil) : choisi avec le bouton 🏠 du
// panneau des groupes. Sans choix, ou s'il n'existe plus : la racine.
const START_GROUP_KEY = "kittypass.start-group";
function startGroup() {
  try { return localStorage.getItem(START_GROUP_KEY); } catch { return null; }
}

async function loadGroups() {
  state.root = await invoke("groups");
  state.binId = null;
  if (!state.group) {
    const start = startGroup();
    if (start && findGroup(state.root, start)) state.group = start;
  }
  if (!state.group || !findGroup(state.root, state.group)) state.group = state.root.id;
  $("tree").replaceChildren(renderNode(state.root, 0));
  const tags = await invoke("tags");
  $("taglist").replaceChildren(
    ...tags.map(([name, count]) => {
      const li = el("li", { title: `Rechercher tag:${name}` }, icon("tag"), el("span", {}, name), el("span", { className: "count" }, count));
      li.addEventListener("click", () => {
        $("search").value = `tag:"${name.replace(/"/g, "")}"`;
        loadEntries();
      });
      return li;
    }),
  );
  $("ed-tag-suggestions").replaceChildren(...tags.map(([name]) => el("option", { value: name })));
  updateGroupButtons();
}

function findGroup(node, id, parent = null) {
  if (node.id === id) return { node, parent };
  for (const c of node.children) {
    const r = findGroup(c, id, node);
    if (r) return r;
  }
  return null;
}

function inBin(id) {
  if (!state.binId) return false;
  const bin = findGroup(state.root, state.binId);
  return Boolean(bin && findGroup(bin.node, id));
}

function renderNode(g, depth) {
  if (g.is_recycle_bin) state.binId = g.id;
  const li = el("li", { role: "treeitem" });
  const hasKids = g.children.length > 0;
  const collapsed = state.collapsed.has(g.id);
  const twisty = el("span", { className: "twisty" }, hasKids ? (collapsed ? "▶" : "▼") : "");
  const name = depth === 0 ? g.name || "Racine" : g.name;
  const row = el(
    "div",
    { className: "node", ariaSelected: String(g.id === state.group), title: name, draggable: depth > 0 && !g.is_recycle_bin ? "true" : "false" },
    twisty,
    icon(g.is_recycle_bin ? "trash" : "folder"),
    el("span", { className: "name" }, name),
    g.id === startGroup() && depth > 0 ? el("span", { className: "start-mark", title: "Ouvert au démarrage" }, icon("home")) : "",
    el("span", { className: "count" }, g.entry_count || ""),
  );
  twisty.addEventListener("click", (ev) => {
    ev.stopPropagation();
    if (collapsed) state.collapsed.delete(g.id);
    else state.collapsed.add(g.id);
    $("tree").replaceChildren(renderNode(state.root, 0));
  });
  row.addEventListener("click", () => selectGroup(g.id));
  // Glisser-déposer : une entrée ou un groupe déposé ici y est déplacé.
  row.addEventListener("dragstart", (ev) => ev.dataTransfer.setData("application/x-kittypass-group", g.id));
  row.addEventListener("dragover", (ev) => {
    const t = ev.dataTransfer.types;
    if (t.includes("application/x-kittypass-entry") || t.includes("application/x-kittypass-group")) {
      ev.preventDefault();
      row.classList.add("drop");
    }
  });
  row.addEventListener("dragleave", () => row.classList.remove("drop"));
  row.addEventListener("drop", async (ev) => {
    ev.preventDefault();
    row.classList.remove("drop");
    const entry = ev.dataTransfer.getData("application/x-kittypass-entry");
    const group = ev.dataTransfer.getData("application/x-kittypass-group");
    try {
      if (entry) await invoke("move_entry", { id: entry, group: g.id });
      else if (group && group !== g.id) await invoke("move_group", { id: group, parent: g.id });
      await loadGroups();
      await loadEntries();
    } catch (e) {
      setStatus(errorText(e));
    }
  });
  li.append(row);
  if (hasKids && !collapsed) {
    li.append(el("ul", { role: "group" }, ...g.children.map((c) => renderNode(c, depth + 1))));
  }
  return li;
}

async function selectGroup(id) {
  closeDetail(false);
  state.group = id;
  if ($("search").value && !$("search-in-group").checked) $("search").value = "";
  for (const n of $("tree").querySelectorAll(".node")) n.setAttribute("aria-selected", "false");
  $("tree").replaceChildren(renderNode(state.root, 0));
  updateGroupButtons();
  await loadEntries();
}

function updateGroupButtons() {
  const isRoot = state.root && state.group === state.root.id;
  const isBin = state.group === state.binId;
  $("btn-group-rename").disabled = !state.group;
  $("btn-group-delete").disabled = isRoot;
  $("btn-group-add").disabled = inBin(state.group);
  $("btn-empty-bin").hidden = !isBin;
  $("btn-new").disabled = inBin(state.group);
  const isStart = state.group === (startGroup() || state.root?.id);
  $("btn-group-start").disabled = inBin(state.group);
  $("btn-group-start").setAttribute("aria-pressed", String(isStart));
  $("btn-group-start").title = isStart ? "Ce groupe s'ouvre au démarrage" : "Ouvrir ce groupe au démarrage";
}

$("btn-group-start").addEventListener("click", () => {
  if (!state.root || inBin(state.group)) return;
  try {
    if (state.group === state.root.id) localStorage.removeItem(START_GROUP_KEY);
    else localStorage.setItem(START_GROUP_KEY, state.group);
  } catch {}
  $("tree").replaceChildren(renderNode(state.root, 0));
  updateGroupButtons();
  const g = findGroup(state.root, state.group);
  setStatus(`Au démarrage, KittyPass ouvrira « ${g && g.parent ? g.node.name : "Racine"} ».`);
});

$("btn-group-add").addEventListener("click", async () => {
  const name = await ask("Nom du nouveau groupe :", { input: "", ok: "Créer" });
  if (!name || !name.trim()) return;
  try {
    state.group = await invoke("add_group", { parent: state.group, name: name.trim() });
    await loadGroups();
    await loadEntries();
  } catch (e) {
    setStatus(errorText(e));
  }
});

$("btn-group-rename").addEventListener("click", async () => {
  const g = findGroup(state.root, state.group);
  if (!g) return;
  const name = await ask("Nouveau nom du groupe :", { input: g.node.name, ok: "Renommer" });
  if (!name || !name.trim() || name === g.node.name) return;
  try {
    await invoke("rename_group", { id: state.group, name: name.trim() });
    await loadGroups();
  } catch (e) {
    setStatus(errorText(e));
  }
});

$("btn-group-delete").addEventListener("click", async () => {
  const g = findGroup(state.root, state.group);
  if (!g || !g.parent) return;
  const permanent = inBin(state.group);
  const ok = await ask(
    permanent
      ? `Supprimer définitivement « ${g.node.name} » et tout son contenu ?`
      : `Mettre « ${g.node.name} » et tout son contenu à la corbeille ?`,
    { ok: permanent ? "Supprimer définitivement" : "Mettre à la corbeille", danger: permanent },
  );
  if (!ok) return;
  try {
    await invoke("delete_group", { id: state.group });
    state.group = g.parent.id;
    await loadGroups();
    await loadEntries();
  } catch (e) {
    setStatus(errorText(e));
  }
});

$("btn-empty-bin").addEventListener("click", async () => {
  if (!(await ask("Vider la corbeille ? Son contenu sera supprimé définitivement.", { ok: "Vider", danger: true }))) return;
  try {
    const n = await invoke("empty_recycle_bin");
    setStatus(`${n} entrée(s) supprimée(s) définitivement.`);
    await loadGroups();
    await loadEntries();
  } catch (e) {
    setStatus(errorText(e));
  }
});

// ---------------------------------------------------------------- liste

const columns = ["title", "username", "url", "modified", "expires"];

async function loadEntries() {
  const query = $("search").value.trim();
  const group = query && !$("search-in-group").checked ? null : state.group;
  let res;
  try {
    res = await invoke("entries", { query, group });
  } catch (e) {
    setStatus(errorText(e));
    return;
  }
  state.items = res.items;
  $("search-banner").hidden = !query;
  $("search-count").textContent = `${res.items.length} résultat(s) pour « ${query} »`;
  renderEntries();
  setStatus(`${res.items.length} entrée(s)${res.truncated ? " (liste tronquée : affinez la recherche)" : ""}`);
  if (state.selected && !state.items.some((i) => i.id === state.selected)) selectEntry(null);
  else if (state.selected) await selectEntry(state.selected, true);
}

function sortedItems() {
  const { key, dir } = state.sort;
  const val = (it) => {
    const v = it[key];
    return v == null ? (key === "expires" ? Infinity : "") : typeof v === "string" ? v.toLowerCase() : v;
  };
  return [...state.items].sort((a, b) => (val(a) < val(b) ? -dir : val(a) > val(b) ? dir : 0));
}

// ---------------------------------------------------------------- icônes des sites

const FAVICON_KEY = "kittypass.favicons";
const faviconCache = new Map(); // URL -> Promise<data URL | null>

function faviconsEnabled() {
  try {
    return localStorage.getItem(FAVICON_KEY) !== "off";
  } catch (_) {
    return true;
  }
}

/** Pastille avec l'initiale, remplacée par l'icône du site si elle arrive. */
function siteIcon(it) {
  const letter = ((it.title || it.url || "?").trim()[0] || "?").toUpperCase();
  const box = el("span", { className: "site-icon", ariaHidden: "true" }, letter);
  let hue = 0;
  for (const c of it.title || "") hue = (hue * 31 + c.charCodeAt(0)) % 360;
  box.style.setProperty("--hue", hue);
  if (it.url && faviconsEnabled()) {
    if (!faviconCache.has(it.url)) faviconCache.set(it.url, invoke("favicon", { url: it.url }).catch(() => null));
    faviconCache.get(it.url).then((src) => {
      if (!src) return;
      const img = el("img", { src, alt: "" });
      img.addEventListener("load", () => box.replaceChildren(img), { once: true });
      box.classList.add("has-img");
    });
  }
  return box;
}

$("favicons-toggle").checked = faviconsEnabled();
$("favicons-toggle").addEventListener("change", (ev) => {
  try {
    localStorage.setItem(FAVICON_KEY, ev.target.checked ? "on" : "off");
  } catch (_) {}
  renderEntries();
});

$("favicons-all").addEventListener("click", (ev) =>
  busy(ev.currentTarget, async () => {
    const out = $("favicons-progress");
    try {
      const { items } = await invoke("entries", { query: "", group: null });
      const urls = items.map((it) => it.url).filter(Boolean);
      out.textContent = `Recherche des icônes de ${urls.length} entrées…`;
      const r = await invoke("favicons_fetch_all", { urls, retry: $("favicons-retry").checked });
      out.textContent = `${r.found} site(s) sur ${r.total} ont une icône.`;
      faviconCache.clear();
      if (faviconsEnabled()) renderEntries();
    } catch (e) {
      out.textContent = `Impossible : ${errorText(e)}`;
    }
  }),
);
listen("favicon_progress", (ev) => {
  const p = ev.payload;
  if ($("favicons-all").disabled) $("favicons-progress").textContent = `${p.done} / ${p.total} sites… (${p.found} icônes trouvées)`;
});

// ---------------------------------------------------------------- mises à jour

const UPDATE_KEY = "kittypass.updates"; // « off » : pas de recherche au démarrage
let updateInfo = null;

function updatesAuto() {
  try {
    return localStorage.getItem(UPDATE_KEY) !== "off";
  } catch (_) {
    return true;
  }
}

function showUpdate(info) {
  updateInfo = info;
  $("upd-current").textContent = `Version installée : ${info.current}`;
  const btn = $("upd-install");
  btn.hidden = !info.latest;
  $("upd-notes").textContent = info.latest ? info.notes || "" : "";
  if (info.latest) {
    $("upd-state").textContent = `KittyPass ${info.latest} est disponible.`;
    btn.textContent = info.installable ? "Installer et redémarrer" : "Télécharger";
  } else {
    $("upd-state").textContent = "KittyPass est à jour.";
  }
}

async function renderUpdates() {
  $("upd-auto").checked = updatesAuto();
  if (updateInfo) return showUpdate(updateInfo);
  $("upd-state").textContent = "";
  try {
    $("upd-current").textContent = `Version installée : ${await window.__TAURI__.app.getVersion()}`;
  } catch (_) {
    $("upd-current").textContent = "";
  }
}

$("upd-auto").addEventListener("change", (ev) => {
  try {
    localStorage.setItem(UPDATE_KEY, ev.target.checked ? "on" : "off");
  } catch (_) {}
});
$("upd-check").addEventListener("click", (ev) =>
  busy(ev.currentTarget, async () => {
    $("upd-state").textContent = "Recherche…";
    try {
      showUpdate(await invoke("update_check"));
    } catch (e) {
      $("upd-state").textContent = `Impossible : ${errorText(e)}`;
    }
  }),
);
$("upd-install").addEventListener("click", (ev) =>
  busy(ev.currentTarget, async () => {
    try {
      if (!updateInfo?.installable) return await invoke("update_open_page");
      $("upd-state").textContent = "Téléchargement…";
      await invoke("update_install"); // redémarre l'appli si tout va bien
    } catch (e) {
      $("upd-state").textContent = `Impossible : ${errorText(e)}`;
    }
  }),
);
listen("update_progress", (ev) => {
  const { done, total } = ev.payload;
  $("upd-state").textContent = total ? `Téléchargement… ${Math.min(100, Math.round((done * 100) / total))} %` : "Téléchargement…";
});
// Recherche discrète au démarrage (fenêtre principale seulement).
if (!QUICK && updatesAuto()) {
  setTimeout(async () => {
    try {
      const info = await invoke("update_check");
      updateInfo = info;
      if (info.latest) setStatus(`KittyPass ${info.latest} est disponible : Paramètres → Mises à jour.`);
    } catch (_) {}
  }, 8000);
}

function renderEntries() {
  const rows = sortedItems().map((it) => {
    const tr = el(
      "tr",
      { ariaSelected: String(it.id === state.selected), draggable: "true", className: it.expired ? "expired" : "" },
      el("td", { className: "title", title: it.title }, el("div", { className: "title-cell" }, siteIcon(it), el("span", {}, it.title || "(sans titre)"))),
      el("td", { title: it.username }, it.username),
      el("td", { title: it.url }, it.url),
      el("td", {}, fmtDate(it.modified)),
      el("td", { className: it.expired ? "expired-text" : "" }, fmtDate(it.expires)),
    );
    tr.dataset.id = it.id;
    tr.addEventListener("click", () => selectEntry(it.id));
    tr.addEventListener("dblclick", (ev) => {
      // Comme KeePassXC : double-clic sur l'identifiant ou l'URL = copie.
      const col = [...tr.children].indexOf(ev.target.closest("td"));
      if (col === 1) copyField("username");
      else if (col === 2) copyField("url");
      else openDetail(it.id);
    });
    tr.addEventListener("contextmenu", (ev) => {
      ev.preventDefault();
      openEntryMenu(it.id, ev.clientX, ev.clientY);
    });
    tr.addEventListener("dragstart", (ev) => ev.dataTransfer.setData("application/x-kittypass-entry", it.id));
    return tr;
  });
  $("entries-body").replaceChildren(...rows);
  $("entries-empty").hidden = rows.length > 0;
  if (!rows.length) {
    // Groupe vide mais qui a des sous-groupes : le dire (sur téléphone, le
    // panneau des groupes est caché derrière le bouton 📁).
    const g = state.root && findGroup(state.root, state.group);
    const subs = g && g.node.children && g.node.children.length;
    $("entries-empty").textContent = subs && !$("search").value
      ? "Aucune entrée dans ce groupe. Les entrées sont dans ses sous-groupes : ouvrez le panneau des groupes (📁)."
      : "Aucune entrée.";
  }
  for (const th of document.querySelectorAll("#entries th")) {
    th.setAttribute("aria-sort", th.dataset.sort === state.sort.key ? (state.sort.dir > 0 ? "ascending" : "descending") : "none");
  }
}

for (const th of document.querySelectorAll("#entries th.sortable")) {
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : 1 };
    renderEntries();
  });
}

let searchTimer;
$("search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  closeDetail(false);
  searchTimer = setTimeout(loadEntries, 150);
});
$("search").addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") {
    $("search").value = "";
    loadEntries();
  } else if (ev.key === "ArrowDown" || ev.key === "Enter") {
    ev.preventDefault();
    const first = sortedItems()[0];
    if (first) {
      selectEntry(first.id);
      $("entries-body").querySelector("tr")?.focus();
    }
  }
});
$("search-in-group").addEventListener("change", loadEntries);
$("btn-search-help").addEventListener("click", () => $("help-dialog").showModal());
$("help-close").addEventListener("click", () => $("help-dialog").close());

// ---------------------------------------------------------------- sélection et aperçu

async function selectEntry(id, keepPreviewTab = false) {
  state.selected = id;
  for (const tr of $("entries-body").children) tr.setAttribute("aria-selected", String(tr.dataset.id === id));
  const has = Boolean(id);
  for (const b of ["btn-edit", "btn-delete", "btn-copy-user", "btn-copy-pass", "btn-copy-url", "btn-autotype"]) $(b).disabled = !has;
  if (!id) {
    state.view = null;
    $("btn-copy-totp").disabled = true;
    showPreview(null);
    return;
  }
  try {
    state.view = await invoke("entry", { id });
  } catch (e) {
    setStatus(errorText(e));
    return;
  }
  $("btn-copy-totp").disabled = !state.view.has_totp;
  $("btn-delete").title = state.view.in_recycle_bin ? "Supprimer définitivement (Suppr)" : "Mettre à la corbeille (Suppr)";
  showPreview(state.view, keepPreviewTab);
}

function showPreview(v, keepTab = false) {
  clearInterval(state.totpTimer);
  $("preview-empty").hidden = Boolean(v);
  $("preview-body").hidden = !v;
  $("pv-password").textContent = MASK;
  $("pv-reveal").dataset.shown = "";
  if (!v) return;
  if (!keepTab) selectTab("pv", "general");
  $("pv-title").textContent = v.title || "(sans titre)";
  $("pv-username").textContent = v.username;
  $("pv-url").replaceChildren(urlNode(v.url));
  $("pv-notes").textContent = v.notes;
  const expired = v.expires != null && v.expires <= nowSecs();
  $("pv-expires").replaceChildren(
    v.expires == null ? el("span", { className: "muted" }, "Jamais") : el("span", { className: expired ? "expired-text" : "" }, fmtDate(v.expires) + (expired ? " (expirée)" : "")),
  );
  $("pv-tags").replaceChildren(...v.tags.map((t) => el("span", { className: "chip" }, t)));
  $("btn-restore-entry").hidden = !v.in_recycle_bin;

  $("pv-totp-label").hidden = $("pv-totp-row").hidden = !v.has_totp;
  if (v.has_totp) {
    const id = v.id;
    const tick = async () => {
      try {
        const t = await invoke("totp", { id });
        if (state.selected !== id) return;
        $("pv-totp").textContent = t.code.replace(/^(\d{3})(\d{3})$/, "$1 $2");
        $("pv-totp-left").textContent = `${t.remaining} s`;
      } catch (err) {
        $("pv-totp").textContent = errorText(err);
        clearInterval(state.totpTimer);
      }
    };
    tick();
    state.totpTimer = setInterval(tick, 1000);
  }

  // Onglet « Avancé » : attributs (valeur protégée masquée) et pièces jointes.
  const dl = $("pv-custom");
  dl.replaceChildren();
  for (const c of v.custom) {
    const value = el(c.protected ? "code" : "span", { className: "sel" }, c.protected ? MASK : c.value);
    const dd = el("dd", {}, value);
    if (c.protected) {
      const reveal = el("button", { className: "mini", title: "Afficher" }, icon("eye"));
      reveal.addEventListener("click", async () => {
        if (value.textContent !== MASK) {
          value.textContent = MASK;
          return;
        }
        value.textContent = await invoke("reveal", { id: v.id, field: { custom: c.key }, history: null });
      });
      dd.append(reveal);
    }
    const copy = el("button", { className: "mini", title: "Copier" }, icon("copy"));
    copy.addEventListener("click", () => copyField({ custom: c.key }));
    dd.append(copy);
    dl.append(el("dt", {}, c.key), dd);
  }
  $("pv-custom-empty").hidden = v.custom.length > 0;
  renderAttachments($("pv-attachments"), v, false);
  $("pv-attachments-empty").hidden = v.attachments.length > 0;
}

function renderAttachments(ul, v, editable) {
  ul.replaceChildren(
    ...v.attachments.map((a) => {
      const save = el("button", { type: "button", className: "mini", title: "Enregistrer sous…" }, icon("copy"));
      save.addEventListener("click", async () => {
        try {
          if (await invoke("export_attachment", { id: v.id, name: a.name })) setStatus(`« ${a.name} » enregistré.`);
        } catch (e) {
          setStatus(errorText(e));
        }
      });
      const li = el("li", {}, icon("folder"), el("span", {}, a.name), el("span", { className: "size" }, fmtSize(a.size)), save);
      if (editable) {
        const rm = el("button", { type: "button", className: "mini", title: "Retirer" }, icon("delete"));
        rm.addEventListener("click", async () => {
          if (!(await ask(`Retirer la pièce jointe « ${a.name} » ? Elle restera dans l'historique.`, { ok: "Retirer" }))) return;
          try {
            await invoke("remove_attachment", { id: v.id, name: a.name });
            await refreshEditorAttachments();
          } catch (e) {
            $("ed-error").textContent = errorText(e);
          }
        });
        li.append(rm);
      }
      return li;
    }),
  );
}

setupTabs("pv");

$("pv-reveal").addEventListener("click", async () => {
  const box = $("pv-password");
  if ($("pv-reveal").dataset.shown) {
    box.textContent = MASK;
    $("pv-reveal").dataset.shown = "";
    return;
  }
  box.textContent = await invoke("reveal", { id: state.selected, field: "password", history: null });
  $("pv-reveal").dataset.shown = "1";
});

for (const btn of document.querySelectorAll("#preview [data-copy]")) {
  btn.addEventListener("click", () => copyField(btn.dataset.copy));
}

async function copyField(field) {
  if (!state.selected) return;
  try {
    const secs = await invoke("copy", { id: state.selected, field, history: null });
    const what = typeof field === "string" ? { username: "Identifiant", password: "Mot de passe", url: "URL", totp: "Code 2FA" }[field] : field.custom;
    setStatus(`${what} copié. Le presse-papiers sera vidé dans ${secs} s.`);
  } catch (e) {
    setStatus(errorText(e));
  }
}

$("btn-copy-user").addEventListener("click", () => copyField("username"));
$("btn-copy-pass").addEventListener("click", () => copyField("password"));
$("btn-copy-url").addEventListener("click", () => copyField("url"));
$("btn-copy-totp").addEventListener("click", () => copyField("totp"));

async function deleteSelected() {
  if (!state.selected || !state.view) return;
  const permanent = state.view.in_recycle_bin;
  const ok = await ask(
    permanent ? `Supprimer définitivement « ${state.view.title} » ?` : `Mettre « ${state.view.title} » à la corbeille ?`,
    { ok: permanent ? "Supprimer définitivement" : "Mettre à la corbeille", danger: permanent },
  );
  if (!ok) return;
  try {
    await invoke("delete_entry", { id: state.selected });
    selectEntry(null);
    await loadGroups();
    await loadEntries();
  } catch (e) {
    setStatus(errorText(e));
  }
}
$("btn-delete").addEventListener("click", deleteSelected);

$("btn-restore-entry").addEventListener("click", async () => {
  try {
    await invoke("restore_entry", { id: state.selected });
    setStatus("Entrée restaurée.");
    await loadGroups();
    await loadEntries();
  } catch (e) {
    setStatus(errorText(e));
  }
});

// ---------------------------------------------------------------- éditeur

const ed = $("editor");
const edTags = [];

function closeEditor(wipe = false) {
  ed.reset();
  // Annule une estimation de robustesse en cours.
  clearTimeout(meterTimer);
  meterSeq++;
  clearMeter($("ed-meter"), $("ed-meter-text"));
  $("ed-attrs").replaceChildren();
  $("ed-history").replaceChildren();
  $("ed-history-detail").hidden = true;
  $("hd-password").textContent = MASK;
  edTags.length = 0;
  renderTags();
  state.editing = null;
  state.historyIndex = null;
  ed.hidden = true;
  $("browse").hidden = false;
  if (!wipe) $("entries-body").querySelector("tr[aria-selected=true]")?.focus();
}

async function openEditor(id) {
  let view = null;
  let password = "";
  try {
    if (id) {
      view = await invoke("entry", { id });
      password = await invoke("reveal", { id, field: "password", history: null });
    }
  } catch (e) {
    setStatus(errorText(e));
    return;
  }
  clearInterval(state.totpTimer);
  ed.reset();
  state.editing = { id, view };
  $("ed-error").textContent = "";
  $("ed-heading").textContent = id ? `Modifier « ${view.title || "(sans titre)"} »` : "Nouvelle entrée";
  $("ed-title").value = view?.title ?? "";
  $("ed-username").value = view?.username ?? "";
  $("ed-password").value = password;
  $("ed-password").type = "password";
  $("ed-url").value = view?.url ?? "";
  $("ed-notes").value = view?.notes ?? "";
  edTags.length = 0;
  edTags.push(...(view?.tags ?? []));
  renderTags();
  setExpiry(view?.expires ?? null);
  $("ed-otp").value = "";
  $("ed-otp").placeholder = view?.has_totp ? "(inchangé)" : "otpauth://totp/…";
  $("ed-otp-remove-row").hidden = !view?.has_totp;
  $("ed-attrs").replaceChildren(...(view?.custom ?? []).map((c) => attrRow(c)));
  // Pièces jointes et historique : seulement pour une entrée existante.
  $("ed-attach").disabled = !id;
  $("ed-att-hint").textContent = id
    ? "Les pièces jointes sont enregistrées immédiatement."
    : "Enregistrez d'abord l'entrée pour y joindre des fichiers.";
  renderAttachments($("ed-attachments"), view ?? { attachments: [] }, true);
  renderHistory(view);
  loadEntryBrowser(id);
  loadEntryAutotype(id);
  loadEntrySsh(id);
  updateEditorMeter(true);
  selectTab("ed", "entry");
  $("browse").hidden = true;
  ed.hidden = false;
  $("ed-title").focus();
}

$("btn-new").addEventListener("click", () => openEditor(null));
$("btn-edit").addEventListener("click", () => state.selected && openEditor(state.selected));
$("ed-cancel").addEventListener("click", () => closeEditor());
setupTabs("ed");

$("ed-toggle-pw").addEventListener("click", () => {
  const f = $("ed-password");
  f.type = f.type === "password" ? "text" : "password";
});
for (const f of ["ed-password", "ed-title", "ed-username", "ed-url"]) $(f).addEventListener("input", () => updateEditorMeter());
$("ed-generate").addEventListener("click", () => openGenerator(true));

// --- étiquettes
function renderTags() {
  const box = $("ed-tags");
  for (const c of [...box.querySelectorAll(".chip")]) c.remove();
  const input = $("ed-tag-input");
  for (const [i, t] of edTags.entries()) {
    const rm = el("button", { type: "button", title: "Retirer", ariaLabel: `Retirer ${t}` }, "×");
    rm.addEventListener("click", () => {
      edTags.splice(i, 1);
      renderTags();
    });
    box.insertBefore(el("span", { className: "chip" }, t, rm), input);
  }
}

function addTagFromInput() {
  const input = $("ed-tag-input");
  for (const raw of input.value.split(/[;,]/)) {
    const t = raw.trim();
    if (t && !edTags.some((x) => x.toLowerCase() === t.toLowerCase())) edTags.push(t);
  }
  input.value = "";
  renderTags();
}
$("ed-tag-input").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" || ev.key === "," || ev.key === ";") {
    ev.preventDefault();
    addTagFromInput();
  } else if (ev.key === "Backspace" && !ev.target.value && edTags.length) {
    edTags.pop();
    renderTags();
  }
});
$("ed-tag-input").addEventListener("change", addTagFromInput);

// --- expiration
function toLocalInput(ts) {
  const d = new Date(ts * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function setExpiry(ts) {
  $("ed-expires-on").checked = ts != null;
  $("ed-expires").value = ts != null ? toLocalInput(ts) : "";
  $("ed-expires").disabled = $("ed-expires-preset").disabled = ts == null;
}

$("ed-expires-on").addEventListener("change", () => {
  const on = $("ed-expires-on").checked;
  setExpiry(on ? nowSecs() + 365 * 86400 : null);
});
$("ed-expires-preset").addEventListener("change", () => {
  const days = Number($("ed-expires-preset").value);
  if (days) setExpiry(nowSecs() + days * 86400);
  $("ed-expires-preset").value = "";
});

function readExpiry() {
  if (!$("ed-expires-on").checked) return null;
  const t = new Date($("ed-expires").value).getTime();
  if (Number.isNaN(t)) throw new Error("Date d'expiration invalide.");
  return Math.floor(t / 1000);
}

// --- attributs
function attrRow(c = { key: "", value: "", protected: false }, isNew = false) {
  const tr = el("tr");
  // Valeur protégée existante : jamais reçue, « null » = garder.
  tr.dataset.original = isNew ? "" : c.key;
  tr.dataset.keep = !isNew && c.protected ? "1" : "";
  const key = el("input", { value: c.key, placeholder: "Nom", spellcheck: false, ariaLabel: "Nom de l'attribut" });
  const value = el("input", {
    value: c.protected ? "" : c.value ?? "",
    type: c.protected ? "password" : "text",
    placeholder: tr.dataset.keep ? "(inchangé)" : "Valeur",
    spellcheck: false,
    ariaLabel: "Valeur de l'attribut",
  });
  value.addEventListener("input", () => (tr.dataset.keep = ""));
  const prot = el("input", { type: "checkbox", checked: c.protected, ariaLabel: "Protégé" });
  prot.addEventListener("change", () => (value.type = prot.checked ? "password" : "text"));
  const reveal = el("button", { type: "button", className: "mini", title: "Afficher" }, icon("eye"));
  reveal.addEventListener("click", async () => {
    if (tr.dataset.keep && state.editing?.id) {
      try {
        value.value = await invoke("reveal", { id: state.editing.id, field: { custom: tr.dataset.original }, history: null });
        tr.dataset.keep = "";
      } catch (e) {
        $("ed-error").textContent = errorText(e);
      }
    }
    value.type = value.type === "password" ? "text" : "password";
  });
  const rm = el("button", { type: "button", className: "mini", title: "Supprimer l'attribut" }, icon("delete"));
  rm.addEventListener("click", () => tr.remove());
  tr.append(el("td", {}, key), el("td", {}, value), el("td", {}, prot), el("td", {}, reveal, rm));
  tr.readInput = () => ({
    key: key.value.trim(),
    value: tr.dataset.keep ? null : value.value,
    protected: prot.checked,
    original_key: tr.dataset.original || null,
  });
  return tr;
}
$("ed-attr-add").addEventListener("click", () => {
  const row = attrRow(undefined, true);
  $("ed-attrs").append(row);
  row.querySelector("input").focus();
});

// --- pièces jointes (enregistrées immédiatement)
async function refreshEditorAttachments() {
  const id = state.editing?.id;
  if (!id) return;
  const v = await invoke("entry", { id });
  state.editing.view.attachments = v.attachments;
  renderAttachments($("ed-attachments"), v, true);
  renderHistory(v);
  renderEntrySsh();
}
$("ed-attach").addEventListener("click", async () => {
  const id = state.editing?.id;
  if (!id) return;
  try {
    const name = await invoke("attach_file", { id });
    if (name) setStatus(`« ${name} » joint.`);
    await refreshEditorAttachments();
  } catch (e) {
    $("ed-error").textContent = errorText(e);
  }
});

// --- historique
function renderHistory(view) {
  const list = view?.history ?? [];
  $("ed-history").replaceChildren(
    ...list.map((h) => {
      const tr = el(
        "tr",
        { ariaSelected: "false" },
        el("td", {}, fmtDate(h.modified)),
        el("td", { title: h.title }, h.title),
        el("td", { title: h.username }, h.username),
        el("td", { title: h.url }, h.url),
      );
      tr.addEventListener("click", () => showHistory(h.index, tr));
      return tr;
    }),
  );
  $("ed-history-empty").hidden = list.length > 0;
  $("ed-history-detail").hidden = true;
}

async function showHistory(index, tr) {
  for (const r of $("ed-history").children) r.setAttribute("aria-selected", String(r === tr));
  state.historyIndex = index;
  try {
    const h = await invoke("history_entry", { id: state.editing.id, index });
    $("hd-password").textContent = MASK;
    $("hd-url").replaceChildren(urlNode(h.url));
    $("hd-notes").textContent = h.notes;
    $("ed-history-detail").hidden = false;
  } catch (e) {
    $("ed-error").textContent = errorText(e);
  }
}

$("hd-reveal").addEventListener("click", async () => {
  const box = $("hd-password");
  if (box.textContent !== MASK) {
    box.textContent = MASK;
    return;
  }
  box.textContent = await invoke("reveal", { id: state.editing.id, field: "password", history: state.historyIndex });
});

$("hd-restore").addEventListener("click", async () => {
  if (state.historyIndex == null) return;
  if (!(await ask("Restaurer cette version ? La version actuelle sera conservée dans l'historique.", { ok: "Restaurer" }))) return;
  const id = state.editing.id;
  try {
    await invoke("restore_history", { id, index: state.historyIndex });
    closeEditor();
    await loadEntries();
    await selectEntry(id);
    setStatus("Version restaurée.");
  } catch (e) {
    $("ed-error").textContent = errorText(e);
  }
});

// --- enregistrement
ed.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("ed-error").textContent = "";
  addTagFromInput();
  const editing = state.editing;
  try {
    const otp = $("ed-otp").value.trim() || null;
    const remove = $("ed-otp-remove").checked;
    const input = {
      title: $("ed-title").value,
      username: $("ed-username").value,
      password: $("ed-password").value,
      url: $("ed-url").value.trim(),
      notes: $("ed-notes").value,
      otp: remove ? null : otp,
      // Champ 2FA vide en modification : on garde le lien existant (il n'est
      // jamais envoyé à l'interface), sauf demande explicite de retrait.
      keep_otp: Boolean(editing.view?.has_totp) && otp === null && !remove,
      tags: [...edTags],
      expires: readExpiry(),
      custom: [...$("ed-attrs").children].map((tr) => tr.readInput()).filter((c) => c.key || c.value),
    };
    let id = editing.id;
    if (id) {
      await invoke("update_entry", { id, input });
      await saveEntryBrowser(id);
      await saveEntryAutotype(id);
      await saveEntrySsh(id);
    }
    else id = await invoke("add_entry", { group: inBin(state.group) ? null : state.group, input });
    closeEditor();
    await loadGroups();
    await loadEntries();
    await selectEntry(id);
    setStatus("Entrée enregistrée.");
  } catch (e) {
    $("ed-error").textContent = errorText(e);
  }
});

// ---------------------------------------------------------------- générateur

const GEN_KEY = "kittypass.generator";
let genApply = false;

// Qualité : mêmes niveaux et seuils que KeePassXC (et que le cœur Rust).
const QUALITY = {
  bad: ["Mauvais", "var(--danger)", 5],
  poor: ["Médiocre", "var(--danger)", 25],
  weak: ["Faible", "var(--warn)", 50],
  good: ["Bon", "var(--ok)", 75],
  excellent: ["Excellent", "var(--ok)", 100],
};

function qualityOf(bits) {
  if (!(bits > 0)) return "bad";
  if (bits < 40) return "poor";
  if (bits < 75) return "weak";
  if (bits < 100) return "good";
  return "excellent";
}

function clearMeter(meter, text) {
  meter.querySelector("span").style.setProperty("--w", "0%");
  text.textContent = "";
}

function setMeter(meter, text, bits, quality = qualityOf(bits)) {
  const [label, color, pct] = QUALITY[quality] ?? QUALITY.bad;
  const bar = meter.querySelector("span");
  bar.style.setProperty("--w", `${pct}%`);
  bar.style.setProperty("--c", color);
  text.textContent = `${label} — entropie ${bits.toFixed(1)} bits`;
}

/**
 * Jauge de l'éditeur : estimation zxcvbn côté Rust (comme KeePassXC), avec
 * le titre, l'identifiant et l'URL comme contexte. Les réponses arrivées
 * dans le désordre sont ignorées.
 */
let meterSeq = 0;
let meterTimer = null;
function updateEditorMeter(now = false) {
  clearTimeout(meterTimer);
  const seq = ++meterSeq;
  const password = $("ed-password").value;
  if (!password) return clearMeter($("ed-meter"), $("ed-meter-text"));
  const run = async () => {
    try {
      const input = { password, title: $("ed-title").value, username: $("ed-username").value, url: $("ed-url").value };
      const r = await invoke("strength", { input });
      if (seq === meterSeq && !ed.hidden) setMeter($("ed-meter"), $("ed-meter-text"), r.bits, r.quality);
    } catch {
      if (seq === meterSeq) clearMeter($("ed-meter"), $("ed-meter-text"));
    }
  };
  if (now) run();
  else meterTimer = setTimeout(run, 150);
}

function genOptions() {
  const passphrase = $("gen-dialog").querySelector("[data-gentab=passphrase]").getAttribute("aria-selected") === "true";
  if (passphrase) {
    return { kind: "passphrase", words: Number($("gen-words").value), separator: $("gen-separator").value, case: $("gen-case").value };
  }
  return {
    kind: "password",
    length: Number($("gen-length").value),
    lower: $("gen-lower").checked,
    upper: $("gen-upper").checked,
    digits: $("gen-digits").checked,
    symbols: $("gen-symbols").checked,
    extended: $("gen-extended").checked,
    exclude_ambiguous: $("gen-ambiguous").checked,
    every_group: $("gen-every").checked,
    include: $("gen-include").value,
    exclude: $("gen-exclude").value,
  };
}

function saveGenOptions() {
  try {
    localStorage.setItem(GEN_KEY, JSON.stringify(genOptions()));
  } catch {
    /* stockage indisponible : réglages non mémorisés */
  }
}

function loadGenOptions() {
  let o = null;
  try {
    o = JSON.parse(localStorage.getItem(GEN_KEY) || "null");
  } catch {
    o = null;
  }
  if (!o || typeof o !== "object") return;
  if (o.kind === "passphrase") {
    selectTab("gen", "passphrase");
    $("gen-words").value = $("gen-words-range").value = Number(o.words) || 7;
    $("gen-separator").value = typeof o.separator === "string" ? o.separator : " ";
    if (["lower", "upper", "title"].includes(o.case)) $("gen-case").value = o.case;
  } else if (o.kind === "password") {
    $("gen-length").value = $("gen-length-range").value = Number(o.length) || 20;
    for (const k of ["lower", "upper", "digits", "symbols", "extended"]) $("gen-" + k).checked = Boolean(o[k]);
    $("gen-ambiguous").checked = Boolean(o.exclude_ambiguous);
    $("gen-every").checked = o.every_group !== false;
    $("gen-include").value = typeof o.include === "string" ? o.include : "";
    $("gen-exclude").value = typeof o.exclude === "string" ? o.exclude : "";
  }
}

async function regenerate() {
  $("gen-error").textContent = "";
  try {
    const g = await invoke("generate", { opts: genOptions() });
    $("gen-output").value = g.value;
    setMeter($("gen-meter"), $("gen-meter-text"), g.entropy);
    saveGenOptions();
  } catch (e) {
    $("gen-output").value = "";
    $("gen-error").textContent = errorText(e);
  }
}

function openGenerator(apply) {
  genApply = apply;
  $("gen-apply").hidden = !apply;
  loadGenOptions();
  $("gen-dialog").showModal();
  regenerate();
}

setupTabs("gen", regenerate);
for (const [range, num] of [["gen-length-range", "gen-length"], ["gen-words-range", "gen-words"]]) {
  $(range).addEventListener("input", () => {
    $(num).value = $(range).value;
    regenerate();
  });
  $(num).addEventListener("change", () => {
    $(range).value = $(num).value;
    regenerate();
  });
}
for (const id of ["gen-upper", "gen-lower", "gen-digits", "gen-symbols", "gen-extended", "gen-ambiguous", "gen-every", "gen-case"]) {
  $(id).addEventListener("change", regenerate);
}
for (const id of ["gen-include", "gen-exclude", "gen-separator"]) $(id).addEventListener("input", regenerate);
$("gen-regen").addEventListener("click", regenerate);
$("gen-copy").addEventListener("click", async () => {
  if (!$("gen-output").value) return;
  try {
    const secs = await invoke("copy_value", { value: $("gen-output").value });
    setStatus(`Copié. Le presse-papiers sera vidé dans ${secs} s.`);
  } catch (e) {
    $("gen-error").textContent = errorText(e);
  }
});
function closeGenerator() {
  $("gen-output").value = "";
  $("gen-dialog").close();
}
$("gen-close").addEventListener("click", closeGenerator);
$("gen-dialog").addEventListener("cancel", (ev) => {
  ev.preventDefault();
  closeGenerator();
});
$("gen-apply").addEventListener("click", () => {
  if (genApply && $("gen-output").value) {
    $("ed-password").value = $("gen-output").value;
    updateEditorMeter(true);
  }
  closeGenerator();
});
$("btn-generator").addEventListener("click", () => openGenerator(!ed.hidden));

// ---------------------------------------------------------------- rapports de sécurité

const countFmt = new Intl.NumberFormat("fr-FR");
// `gen` change au verrouillage : une réponse arrivée après est ignorée.
const reports = { health: null, hibp: null, changed: false, gen: 0 };

/** Chemin du groupe sans la racine : « Perso / Banques ». */
function groupPath(id) {
  const walk = (node, path) => {
    if (node.id === id) return path;
    for (const c of node.children) {
      const r = walk(c, [...path, c.name]);
      if (r) return r;
    }
    return null;
  };
  return (state.root && walk(state.root, [])?.join(" / ")) || (state.root?.id === id ? state.root.name : "");
}

function qualityBadge(q) {
  return el("span", { className: "quality " + (QUALITY[q] ? q : "bad") }, (QUALITY[q] ?? QUALITY.bad)[0]);
}

function healthProblems(i) {
  const p = [];
  if (i.quality === "bad" || i.quality === "poor" || i.quality === "weak") {
    p.push(`Mot de passe ${QUALITY[i.quality][0].toLowerCase()} (${Math.round(i.bits)} bits)`);
  }
  if (i.reused) p.push(i.reused === 1 ? "Réutilisé dans 1 autre entrée" : `Réutilisé dans ${i.reused} autres entrées`);
  if (i.expired) p.push("Expiré");
  return p.join(" · ");
}

function reportRow(item, cells) {
  const tr = el("tr", { className: item.excluded ? "excluded" : "", title: "Double-cliquer pour ouvrir l'entrée" });
  for (const c of cells) tr.append(el("td", { title: typeof c === "string" ? c : "" }, c));
  const btn = el("button", { type: "button", className: "small" }, item.excluded ? "Réintégrer" : "Exclure");
  btn.title = item.excluded
    ? "Inclure de nouveau cette entrée dans les rapports"
    : "Exclure cette entrée des rapports (risque connu et accepté)";
  btn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    toggleExcluded(btn, item.entry.id, !item.excluded);
  });
  tr.append(el("td", {}, btn));
  tr.addEventListener("dblclick", () => openFromReport(item.entry));
  return tr;
}

async function toggleExcluded(btn, id, excluded) {
  $("reports-error").textContent = "";
  await busy(btn, async () => {
    try {
      await invoke("set_excluded_from_reports", { id, excluded });
      reports.changed = true;
      for (const i of reports.hibp?.items ?? []) if (i.entry.id === id) i.excluded = excluded;
      renderHibp();
      await loadHealth();
    } catch (e) {
      $("reports-error").textContent = errorText(e);
    }
  });
}

async function loadHealth() {
  const gen = reports.gen;
  try {
    const r = await invoke("health_report");
    if (gen !== reports.gen) return;
    reports.health = r;
  } catch (e) {
    if (gen !== reports.gen) return;
    reports.health = null;
    $("reports-error").textContent = errorText(e);
  }
  renderHealth();
}

function renderHealth() {
  const r = reports.health;
  const rows = r ? r.items.filter((i) => $("health-show-excluded").checked || !i.excluded) : [];
  const todo = r ? r.items.filter((i) => !i.excluded).length : 0;
  $("health-summary").textContent = r
    ? `${r.checked} entrée(s) analysée(s) · ${todo} à améliorer` + (r.excluded ? ` · ${r.excluded} exclue(s) des rapports` : "")
    : "";
  $("health-body").replaceChildren(
    ...rows.map((i) => reportRow(i, [qualityBadge(i.quality), i.entry.title, groupPath(i.entry.group_id), healthProblems(i)])),
  );
  $("health-table").hidden = rows.length === 0;
  $("health-empty").hidden = !r || rows.length > 0;
}

function renderHibp() {
  const r = reports.hibp;
  const rows = r ? r.items.filter((i) => $("hibp-show-excluded").checked || !i.excluded) : [];
  const pwned = r ? r.items.filter((i) => !i.excluded).length : 0;
  $("hibp-summary").textContent = r ? `${r.checked} mot(s) de passe vérifié(s) · ${pwned} compromis` : "";
  $("hibp-body").replaceChildren(
    ...rows.map((i) =>
      reportRow(i, [
        i.entry.title,
        groupPath(i.entry.group_id),
        el("span", { className: "pwned-count", title: `${countFmt.format(i.count)} fois dans des fuites connues` }, countFmt.format(i.count)),
      ]),
    ),
  );
  $("hibp-table").hidden = rows.length === 0;
  $("hibp-empty").hidden = !r || rows.length > 0;
}

async function openReports() {
  $("reports-error").textContent = "";
  reports.changed = false;
  $("reports-dialog").showModal();
  renderHibp();
  await loadHealth();
}

function closeReports() {
  $("reports-dialog").close();
  if (reports.changed) {
    reports.changed = false;
    loadEntries();
    if (state.selected) selectEntry(state.selected, true);
  }
}

async function openFromReport(entry) {
  closeReports();
  if (!ed.hidden) return;
  $("search").value = "";
  await selectGroup(entry.group_id);
  await selectEntry(entry.id);
  $("entries-body").querySelector(`tr[data-id="${CSS.escape(entry.id)}"]`)?.scrollIntoView({ block: "nearest" });
}

/** Vide les rapports (verrouillage). */
function wipeReports() {
  Object.assign(reports, { health: null, hibp: null, changed: false, gen: reports.gen + 1 });
  $("reports-error").textContent = "";
  if ($("reports-dialog").open) $("reports-dialog").close();
  renderHealth();
  renderHibp();
}

setupTabs("rep");
$("btn-reports").addEventListener("click", openReports);
$("reports-close").addEventListener("click", closeReports);
$("reports-dialog").addEventListener("cancel", (ev) => {
  ev.preventDefault();
  closeReports();
});
$("health-show-excluded").addEventListener("change", renderHealth);
$("hibp-show-excluded").addEventListener("change", renderHibp);
$("hibp-run").addEventListener("click", async () => {
  const ok = await ask(
    "Envoyer à api.pwnedpasswords.com les 5 premiers caractères de l'empreinte SHA-1 de chaque mot de passe ? " +
      "Les mots de passe eux-mêmes ne quittent pas cet appareil.",
    { ok: "Vérifier" },
  );
  if (!ok) return;
  const btn = $("hibp-run");
  const gen = reports.gen;
  $("reports-error").textContent = "";
  btn.textContent = "Vérification…";
  try {
    const r = await busy(btn, () => invoke("hibp_check"));
    if (gen === reports.gen) reports.hibp = r;
  } catch (e) {
    if (gen === reports.gen) $("reports-error").textContent = "Vérification impossible : " + errorText(e);
  } finally {
    btn.textContent = "Lancer la vérification";
  }
  renderHibp();
});

// ---------------------------------------------------------------- coffre : import, export, fichier clé

/** Chemins choisis dans la boîte « Coffre » ; `gen` ignore les réponses tardives après verrouillage. */
const vd = { importPath: null, importKey: null, exportKey: null, keyPath: null, dest: null, imported: null, gen: 0 };

const IMPORT_PICK = { csv: "csv", kdbx: "kdbx", bitwarden: "bitwarden", "1pux": "1pux" };
const EXPORT_NOTES = {
  csv: "CSV au format KeePassXC. Ni les attributs ni les pièces jointes ne sont exportés. Un tableur peut interpréter une valeur commençant par = + - @ comme une formule : ouvrez-le plutôt dans un éditeur de texte.",
  xml: "XML KeePass 2.x : importable par KeePass et KeePassXC, attributs et pièces jointes compris (pas l'historique).",
  html: "Page à imprimer pour une sauvegarde papier. Les pièces jointes ne sont pas incluses.",
};

function setPath(id, path, none) {
  const span = $(id);
  span.textContent = path ?? none;
  span.title = path ?? "";
  span.classList.toggle("muted", path == null);
}

function renderImport() {
  const f = $("import-form");
  const kdbx = f.format.value === "kdbx";
  $("import-kdbx").hidden = !kdbx;
  setPath("import-path", vd.importPath, "Aucun fichier choisi");
  setPath("import-keyfile-path", vd.importKey, "Sans fichier clé");
  $("import-keyfile-clear").hidden = vd.importKey == null;
  $("import-run").disabled = vd.importPath == null;
  $("import-dest").textContent = "Destination : " + (vd.dest ? groupPath(vd.dest) || state.root.name : "");
}

function renderExport() {
  const f = $("export-form");
  const fmt = f.format.value;
  $("export-kdbx").hidden = fmt !== "kdbx";
  $("export-clear").hidden = fmt === "kdbx";
  $("export-note").textContent = EXPORT_NOTES[fmt] ?? "";
  setPath("export-keyfile-path", vd.exportKey, "Sans fichier clé");
  $("export-keyfile-clear").hidden = vd.exportKey == null;
}

async function renderKeyfile() {
  const f = $("keyfile-form");
  const remove = f.action.value === "remove";
  $("keyfile-choose").hidden = remove;
  $("keyfile-remember-row").hidden = remove;
  setPath("keyfile-path", vd.keyPath, "Aucun fichier choisi");
  const gen = vd.gen;
  const s = await invoke("status");
  if (gen !== vd.gen) return;
  $("keyfile-status").textContent = s.has_key_file
    ? "Ce coffre est protégé par le mot de passe maître et un fichier clé" + (s.key_file ? ` (${s.key_file}).` : ".")
    : "Ce coffre est protégé par le mot de passe maître seul.";
}

/** Paramètres ; coffre verrouillé : seulement ce qui ne le concerne pas. */
function openSettings(tab = "appearance") {
  const unlocked = !$("view-main").hidden;
  for (const t of document.querySelectorAll("[data-vdtab][data-needs-vault]")) t.hidden = !unlocked;
  if (!unlocked && document.querySelector(`[data-vdtab="${tab}"]`)?.hidden) tab = "appearance";
  // Destination figée à l'ouverture : des imports successifs restent côte à
  // côte au lieu de s'emboîter dans le groupe tout juste créé.
  vd.dest = state.group && !inBin(state.group) ? state.group : state.root?.id;
  vd.imported = null;
  for (const id of ["import-error", "export-error", "export-done", "keyfile-error", "br-error", "at-error", "at-done", "shortcuts-error", "ssh-error", "ssh-done"]) {
    $(id).textContent = "";
  }
  $("settings-dialog").showModal();
  selectTab("vd", tab, onVaultTab);
  document.querySelector(`[data-vdtab="${tab}"]`)?.focus();
}

function onVaultTab(name) {
  stopRecording();
  if (name === "appearance") renderAppearance();
  else if (name === "shortcuts") renderShortcuts();
  else if (name === "autotype") renderAutotypeSettings();
  else if (name === "ssh") renderSshSettings();
  else if (name === "import") renderImport();
  else if (name === "export") renderExport();
  else if (name === "browser") renderBrowser();
  else if (name === "account") renderAccount();
  else if (name === "updates") renderUpdates();
  else renderKeyfile();
}

function closeVaultDialog() {
  for (const f of ["import-form", "export-form", "keyfile-form", "pw-form", "tfa-disable-form", "bio-form"]) {
    for (const i of $(f).querySelectorAll("input[type=password]")) i.value = "";
  }
  wipeAccount();
  stopRecording();
  if ($("settings-dialog").open) $("settings-dialog").close();
  // Pas de cadre de focus laissé sur le bouton ⚙ après la fermeture.
  if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
  // Montre le dernier groupe importé une fois la boîte fermée.
  if (vd.imported) selectGroup(vd.imported);
  vd.imported = null;
}

/** Verrouillage : oublie chemins, résultats et mots de passe saisis. */
function wipeVaultDialog() {
  Object.assign(vd, { importPath: null, importKey: null, exportKey: null, keyPath: null, dest: null, imported: null, gen: vd.gen + 1 });
  closeVaultDialog();
  for (const f of ["import-form", "export-form", "keyfile-form"]) $(f).reset();
  $("import-result").hidden = true;
  $("import-summary").textContent = "";
  $("import-warnings").replaceChildren();
  for (const [id, none] of [["import-path", "Aucun fichier choisi"], ["import-keyfile-path", "Sans fichier clé"], ["export-keyfile-path", "Sans fichier clé"], ["keyfile-path", "Aucun fichier choisi"]]) {
    setPath(id, null, none);
  }
  $("keyfile-status").textContent = "";
  $("export-done").textContent = "";
}

setupTabs("vd", onVaultTab);
$("btn-settings").addEventListener("click", () => openSettings());
$("btn-theme-float").addEventListener("click", () => openSettings("appearance"));
for (const b of document.querySelectorAll(".vd-close")) b.addEventListener("click", closeVaultDialog);
$("settings-dialog").addEventListener("cancel", (ev) => {
  ev.preventDefault();
  // Échap pendant l'enregistrement d'un raccourci : annule seulement celui-ci.
  if (recording) return stopRecording();
  closeVaultDialog();
});

// --- import
$("import-form").format.addEventListener("change", () => {
  vd.importPath = null;
  renderImport();
});
$("import-pick").addEventListener("click", async () => {
  const gen = vd.gen;
  const p = await pickPath(IMPORT_PICK[$("import-form").format.value]);
  if (p && gen === vd.gen) {
    vd.importPath = p;
    renderImport();
  }
});
$("import-keyfile-pick").addEventListener("click", async () => {
  const gen = vd.gen;
  const p = await pickPath("key_file");
  if (p && gen === vd.gen) {
    vd.importKey = p;
    renderImport();
  }
});
$("import-keyfile-clear").addEventListener("click", () => {
  vd.importKey = null;
  renderImport();
});
$("import-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  if (!vd.importPath) return;
  const gen = vd.gen;
  $("import-error").textContent = "";
  $("import-result").hidden = true;
  const kdbx = f.format.value === "kdbx";
  const req = {
    format: f.format.value,
    path: vd.importPath,
    parent: vd.dest ?? state.root.id,
    name: f.name.value.trim() || null,
    password: kdbx ? f.password.value : null,
    key_file: kdbx ? vd.importKey : null,
  };
  const btn = $("import-run");
  btn.textContent = "Import…";
  try {
    const r = await busy(btn, () => invoke("import_file", { req }));
    if (gen !== vd.gen) return;
    f.password.value = "";
    vd.importPath = null;
    $("import-summary").textContent =
      `${countFmt.format(r.imported)} entrée(s) importée(s)` + (r.skipped ? `, ${countFmt.format(r.skipped)} ignorée(s)` : "") + ".";
    $("import-warnings").replaceChildren(...r.warnings.map((w) => el("li", {}, w)));
    $("import-result").hidden = false;
    vd.imported = r.group_id;
    await loadGroups();
  } catch (e) {
    if (gen !== vd.gen) return;
    $("import-error").textContent =
      e.code === "invalid_password" ? "Mot de passe ou fichier clé du coffre à importer incorrect." : "Import impossible : " + errorText(e);
  } finally {
    btn.textContent = "Importer";
    if (gen === vd.gen) renderImport();
  }
});

// --- export
for (const r of $("export-form").format) r.addEventListener("change", renderExport);
$("export-keyfile-pick").addEventListener("click", async () => {
  const gen = vd.gen;
  const p = await pickPath("key_file");
  if (p && gen === vd.gen) {
    vd.exportKey = p;
    renderExport();
  }
});
$("export-keyfile-new").addEventListener("click", async () => {
  const gen = vd.gen;
  const p = await newKeyFile();
  if (p && gen === vd.gen) {
    vd.exportKey = p;
    renderExport();
  }
});
$("export-keyfile-clear").addEventListener("click", () => {
  vd.exportKey = null;
  renderExport();
});
$("export-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const fmt = f.format.value;
  const gen = vd.gen;
  $("export-error").textContent = "";
  $("export-done").textContent = "";
  if (fmt === "kdbx") {
    if (f.password.value.length < 10) return ($("export-error").textContent = "Le mot de passe de la copie doit faire au moins 10 caractères.");
    if (f.password.value !== f.confirm.value) return ($("export-error").textContent = "Les deux mots de passe ne correspondent pas.");
  } else {
    if (!f.understood.checked) return ($("export-error").textContent = "Cochez la case pour confirmer l'export en clair.");
    const ok = await ask("Exporter tous les mots de passe en clair dans un fichier non chiffré ?", { ok: "Exporter en clair", danger: true });
    if (!ok || gen !== vd.gen) return;
  }
  const req = { format: fmt, password: fmt === "kdbx" ? f.password.value : null, key_file: fmt === "kdbx" ? vd.exportKey : null };
  try {
    const saved = await busy($("export-run"), () => invoke("export_file", { req }));
    if (gen !== vd.gen || !saved) return;
    f.password.value = f.confirm.value = "";
    f.understood.checked = false;
    $("export-done").textContent = fmt === "kdbx" ? "Copie enregistrée." : "Export enregistré. Supprimez ce fichier dès qu'il n'est plus utile.";
  } catch (e) {
    if (gen === vd.gen) $("export-error").textContent = "Export impossible : " + errorText(e);
  }
});

// --- fichier clé du coffre
for (const r of $("keyfile-form").action) r.addEventListener("change", renderKeyfile);
$("keyfile-pick").addEventListener("click", async () => {
  const gen = vd.gen;
  const p = await pickPath("key_file");
  if (p && gen === vd.gen) {
    vd.keyPath = p;
    renderKeyfile();
  }
});
$("keyfile-new").addEventListener("click", async () => {
  const gen = vd.gen;
  const p = await newKeyFile();
  if (p && gen === vd.gen) {
    vd.keyPath = p;
    renderKeyfile();
  }
});
$("keyfile-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const remove = f.action.value === "remove";
  const gen = vd.gen;
  $("keyfile-error").textContent = "";
  if (!remove && !vd.keyPath) return ($("keyfile-error").textContent = "Choisissez ou créez d'abord un fichier clé.");
  const ok = await ask(
    remove
      ? "Retirer le fichier clé ? Le coffre ne sera plus protégé que par le mot de passe maître, sur tous les appareils."
      : "Protéger le coffre avec ce fichier clé ? Il sera demandé sur tous les appareils. Gardez-en une copie de sauvegarde.",
    { ok: remove ? "Retirer" : "Utiliser ce fichier", danger: remove },
  );
  if (!ok || gen !== vd.gen) return;
  const change = { password: f.password.value, key_file: remove ? null : vd.keyPath, remember: !remove && f.remember.checked };
  try {
    await busy($("keyfile-run"), () => invoke("set_key_file", { change }));
    if (gen !== vd.gen) return;
    f.password.value = "";
    vd.keyPath = null;
    setStatus(remove ? "Fichier clé retiré." : "Fichier clé ajouté.");
    renderKeyfile();
  } catch (e) {
    if (gen !== vd.gen) return;
    $("keyfile-error").textContent = e.code === "invalid_password" ? "Mot de passe maître incorrect." : "Changement impossible : " + errorText(e);
    // Seule la 2FA se règle ici ; hors ligne, rien n'a changé (le message
    // général « modifications gardées localement » serait faux).
    if (e.code === "totp_required") handleSyncError(e, false);
  }
});

// ---------------------------------------------------------------- thème

const THEMES = ["light", "pastel", "dark", "system"];
const ACCENTS = ["green", "emerald", "teal", "blue", "indigo", "violet", "pink", "orange", "amber", "graphite"];

/** Préférence d'affichage (`theme` ou `accent`), gardée localement. */
function setAppearance(kind, value) {
  if (!(kind === "theme" ? THEMES : ACCENTS).includes(value)) return;
  document.documentElement.dataset[kind] = value;
  try {
    localStorage.setItem("kittypass." + kind, value);
  } catch (_) {}
  if (kind === "accent") showAccentName();
}

function showAccentName() {
  const current = [...$("theme-form").accent].find((r) => r.value === document.documentElement.dataset.accent);
  $("accent-name").textContent = current ? current.getAttribute("aria-label") : "";
}

function renderAppearance() {
  const { theme, accent } = document.documentElement.dataset;
  for (const r of $("theme-form").theme) r.checked = r.value === theme;
  for (const r of $("theme-form").accent) r.checked = r.value === accent;
  showAccentName();
}

for (const r of $("theme-form").theme) r.addEventListener("change", () => setAppearance("theme", r.value));
for (const r of $("theme-form").accent) r.addEventListener("change", () => setAppearance("accent", r.value));

// ---------------------------------------------------------------- séparateurs redimensionnables

function dragSplitter(handle, onMove) {
  handle.addEventListener("pointerdown", (ev) => {
    ev.preventDefault();
    handle.setPointerCapture(ev.pointerId);
    const move = (e) => onMove(e);
    const up = () => {
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", up);
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
  });
}
const rootStyle = document.documentElement.style;
dragSplitter($("splitter-v"), (e) => {
  const w = Math.min(Math.max(e.clientX, 150), window.innerWidth * 0.6);
  rootStyle.setProperty("--sidebar-w", `${w}px`);
});
dragSplitter($("splitter-h"), (e) => {
  const box = $("browse").getBoundingClientRect();
  const h = Math.min(Math.max(box.bottom - e.clientY, 80), box.height - 80);
  rootStyle.setProperty("--preview-h", `${h}px`);
});

// ---------------------------------------------------------------- raccourcis clavier

/**
 * Raccourcis réglables : [action, libellé, raccourci par défaut (ceux de
 * KeePassXC), utilisable depuis un champ de saisie].
 */
const SHORTCUT_ACTIONS = [
  ["search", "Rechercher", "Ctrl+F", true],
  ["new", "Nouvelle entrée", "Ctrl+N", true],
  ["edit", "Modifier l'entrée", "Ctrl+E", true],
  ["delete", "Supprimer l'entrée", "Delete", false],
  ["copy_user", "Copier l'identifiant", "Ctrl+B", true],
  ["copy_pass", "Copier le mot de passe", "Ctrl+C", false],
  ["copy_url", "Copier l'URL", "Ctrl+U", true],
  ["copy_totp", "Copier le code 2FA", "Ctrl+T", true],
  ["autotype", "Saisie automatique dans la fenêtre précédente", "Ctrl+Shift+V", true],
  ["generator", "Générateur de mots de passe", "Ctrl+G", true],
  ["reports", "Rapports de sécurité", "Ctrl+R", true],
  ["sync", "Synchroniser", "", true],
  ["lock", "Verrouiller", "Ctrl+L", true],
  ["settings", "Paramètres", "Ctrl+,", true],
];
const SHORTCUTS_KEY = "kittypass.shortcuts";
/** Combinaisons laissées à l'édition de texte et au navigateur. */
const RESERVED = new Set(["Ctrl+A", "Ctrl+V", "Ctrl+X", "Ctrl+Z", "Ctrl+Y", "Ctrl+Shift+Z", "Ctrl+S", "Ctrl+Shift+I"]);
const NAMED_KEYS = new Set(["Delete", "Insert", "Home", "End", "PageUp", "PageDown"]);
const KEY_LABELS = { Ctrl: "Ctrl", Alt: "Alt", Shift: "Maj", Delete: "Suppr", Insert: "Inser", PageUp: "Page préc.", PageDown: "Page suiv.", Home: "Début", End: "Fin" };

/** Touche principale d'un événement clavier, ou null (modificateur seul…). */
function eventKey(ev) {
  const k = ev.key;
  if (!k || ["Control", "Shift", "Alt", "Meta", "AltGraph", "Dead", "Unidentified", "Process"].includes(k)) return null;
  if (/^F([1-9]|1[0-2])$/.test(k) || NAMED_KEYS.has(k)) return k;
  // Lettres et chiffres : position physique, pour que Maj ne change pas la
  // touche (Maj+1 reste « 1 » sur un clavier AZERTY).
  const code = /^Key([A-Z])$/.exec(ev.code) ?? /^Digit([0-9])$/.exec(ev.code);
  if (code && (ev.ctrlKey || ev.metaKey || ev.altKey)) return code[1];
  if (k.length === 1 && k !== " ") return k.toUpperCase();
  return null;
}

/** Combinaison d'un événement, au format `Ctrl+Alt+Shift+X`. */
function comboOf(ev) {
  const key = eventKey(ev);
  if (!key) return null;
  const parts = [];
  if (ev.ctrlKey || ev.metaKey) parts.push("Ctrl");
  if (ev.altKey) parts.push("Alt");
  if (ev.shiftKey) parts.push("Shift");
  parts.push(key);
  return parts.join("+");
}

/** Combinaison acceptable : Ctrl ou Alt, sauf touches de fonction et Suppr… */
function shortcutProblem(combo) {
  if (RESERVED.has(combo)) return "réservé à l'édition de texte";
  const key = combo.split("+").pop();
  const withMod = /(^|\+)(Ctrl|Alt)\+/.test(combo);
  if (!withMod && !/^F\d+$/.test(key) && !NAMED_KEYS.has(key)) return "il faut Ctrl ou Alt (sauf F1–F12, Suppr…)";
  return null;
}

function comboLabel(combo) {
  return combo ? combo.split("+").map((p) => KEY_LABELS[p] ?? p).join("+") : "Aucun";
}

function loadShortcuts() {
  let saved = {};
  try {
    saved = JSON.parse(localStorage.getItem(SHORTCUTS_KEY) || "{}") ?? {};
  } catch (_) {}
  const map = {};
  const used = new Set();
  for (const [action, , def] of SHORTCUT_ACTIONS) {
    let c = Object.hasOwn(saved, action) ? saved[action] : def;
    if (typeof c !== "string" || (c && (shortcutProblem(c) || used.has(c)))) c = def && !used.has(def) ? def : "";
    map[action] = c;
    if (c) used.add(c);
  }
  return map;
}

let shortcuts = loadShortcuts();

function saveShortcuts() {
  try {
    localStorage.setItem(SHORTCUTS_KEY, JSON.stringify(shortcuts));
  } catch (_) {}
  showShortcutHints();
}

/** Raccourcis rappelés dans les infobulles de la barre d'outils. */
const SHORTCUT_BUTTONS = {
  new: "btn-new", edit: "btn-edit", delete: "btn-delete", copy_user: "btn-copy-user", copy_pass: "btn-copy-pass",
  copy_url: "btn-copy-url", copy_totp: "btn-copy-totp", autotype: "btn-autotype", generator: "btn-generator",
  reports: "btn-reports", sync: "btn-sync", lock: "btn-lock", settings: "btn-settings",
};
function showShortcutHints() {
  for (const [action, id] of Object.entries(SHORTCUT_BUTTONS)) {
    const b = $(id);
    b.dataset.label ??= b.title.replace(/ \([^)]*\)$/, "");
    b.title = shortcuts[action] ? `${b.dataset.label} (${comboLabel(shortcuts[action])})` : b.dataset.label;
  }
  const touch = /Android/i.test(navigator.userAgent) || window.matchMedia("(max-width: 640px)").matches;
  $("search").placeholder = shortcuts.search && !touch ? `Rechercher… (${comboLabel(shortcuts.search)})` : "Rechercher…";
}
showShortcutHints();

// --- enregistrement d'un raccourci (Paramètres)
let recording = null; // { button, onDone }

/** Arrête l'enregistrement ; `restore` remet le libellé d'avant (annulation). */
function stopRecording(restore = true) {
  if (!recording) return;
  recording.button.classList.remove("recording");
  if (restore) recording.button.textContent = recording.label;
  recording = null;
}

/** Attend une combinaison sur `button` ; `onDone(combo | "")` peut refuser en renvoyant un message. */
function recordShortcut(button, onDone) {
  stopRecording();
  recording = { button, onDone, label: button.textContent };
  button.classList.add("recording");
  button.textContent = "Appuyez sur les touches…";
}

document.addEventListener(
  "keydown",
  (ev) => {
    if (!recording) return;
    if (ev.key === "Escape") return; // géré par « cancel » de la boîte
    ev.preventDefault();
    ev.stopPropagation();
    if (ev.key === "Backspace" && !ev.ctrlKey && !ev.altKey && !ev.metaKey) {
      const r = recording;
      stopRecording(false);
      r.onDone("");
      return;
    }
    const combo = r_combo(ev);
    if (!combo) return;
    const r = recording;
    const problem = r.onDone(combo, ev);
    if (problem) {
      r.button.textContent = `${comboLabel(combo)} : ${problem}`;
      r.button.classList.add("conflict");
      setTimeout(() => r.button.classList.remove("conflict"), 1500);
      return;
    }
    stopRecording(false);
  },
  true,
);
// Le raccourci global accepte aussi Super (touche Windows).
function r_combo(ev) {
  return recording?.global ? globalComboOf(ev) : comboOf(ev);
}

function renderShortcuts() {
  $("shortcuts-error").textContent = "";
  $("shortcut-list").replaceChildren(
    ...SHORTCUT_ACTIONS.map(([action, label, def]) => {
      const key = el("button", { type: "button", className: "key-capture" }, comboLabel(shortcuts[action]));
      key.addEventListener("click", () =>
        recordShortcut(key, (combo) => {
          if (combo) {
            const problem = shortcutProblem(combo);
            if (problem) return problem;
            const other = SHORTCUT_ACTIONS.find(([a]) => a !== action && shortcuts[a] === combo);
            if (other) return `déjà pris par « ${other[1]} »`;
          }
          shortcuts[action] = combo;
          saveShortcuts();
          renderShortcuts();
          return null;
        }),
      );
      const reset = el("button", { type: "button", className: "small", title: `Par défaut : ${comboLabel(def)}` }, "Défaut");
      reset.disabled = shortcuts[action] === def;
      reset.addEventListener("click", () => {
        const other = def && SHORTCUT_ACTIONS.find(([a]) => a !== action && shortcuts[a] === def);
        if (other) {
          $("shortcuts-error").textContent = `${comboLabel(def)} est déjà pris par « ${other[1]} ».`;
          return;
        }
        shortcuts[action] = def;
        saveShortcuts();
        renderShortcuts();
      });
      return el("tr", {}, el("td", {}, label), el("td", {}, key), el("td", {}, reset));
    }),
  );
}

$("shortcuts-reset").addEventListener("click", () => {
  stopRecording();
  shortcuts = Object.fromEntries(SHORTCUT_ACTIONS.map(([a, , d]) => [a, d]));
  saveShortcuts();
  renderShortcuts();
});

// --- exécution
const SHORTCUT_RUN = {
  search: () => {
    $("search").focus();
    $("search").select();
  },
  new: () => !$("btn-new").disabled && openEditor(null),
  edit: () => state.selected && openEditor(state.selected),
  delete: () => state.selected && deleteSelected(),
  copy_user: () => copyField("username"),
  copy_pass: () => copyField("password"),
  copy_url: () => copyField("url"),
  copy_totp: () => state.view?.has_totp && copyField("totp"),
  autotype: () => state.selected && autotypeSelected(),
  generator: () => openGenerator(false),
  reports: () => openReports(),
  sync: () => syncNow(),
  lock: () => lockNow(),
  settings: () => openSettings(),
};

document.addEventListener("keydown", (ev) => {
  // Jamais de rechargement de la page (Ctrl+R, F5), quel que soit l'écran.
  if (((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "r") || ev.key === "F5") ev.preventDefault();
  if (recording) return;
  // Paramètres : aussi depuis l'écran de déverrouillage.
  const combo = comboOf(ev);
  if (combo && combo === shortcuts.settings && !document.querySelector("dialog[open]") && ed.hidden) {
    ev.preventDefault();
    openSettings();
    return;
  }
  if ($("view-main").hidden || document.querySelector("dialog[open]")) return;
  const ctrl = ev.ctrlKey || ev.metaKey;
  const inField = ev.target instanceof Element && ev.target.closest("input, textarea, select");
  const editing = !ed.hidden;
  if (editing) {
    if (ev.key === "Escape") {
      ev.preventDefault();
      closeEditor();
    } else if (ctrl && ev.key.toLowerCase() === "s") {
      ev.preventDefault();
      ed.requestSubmit();
    }
    return;
  }
  const action = combo && SHORTCUT_ACTIONS.find(([a]) => shortcuts[a] === combo);
  if (action) {
    const [name, , , fromField] = action;
    // Copie et suppression : le texte sélectionné et les champs gardent
    // leur comportement habituel.
    const textBusy = inField || (name === "copy_pass" && window.getSelection().toString());
    if (!textBusy || fromField) {
      ev.preventDefault();
      SHORTCUT_RUN[name]();
      return;
    }
  }
  if (!inField && (ev.key === "ArrowDown" || ev.key === "ArrowUp") && !ctrl) {
    ev.preventDefault();
    const list = sortedItems();
    const i = list.findIndex((x) => x.id === state.selected);
    const next = list[Math.min(Math.max(i + (ev.key === "ArrowDown" ? 1 : -1), 0), list.length - 1)];
    if (next) {
      selectEntry(next.id);
      $("entries-body").querySelector(`tr[data-id="${CSS.escape(next.id)}"]`)?.scrollIntoView({ block: "nearest" });
    }
  } else if (!inField && ev.key === "Enter" && state.selected) {
    ev.preventDefault();
    openEditor(state.selected);
  }
});

// ---------------------------------------------------------------- saisie automatique

/** Modificateurs encore enfoncés (pour ne pas les mêler à la saisie). */
const heldKeys = new Set();
window.addEventListener("keydown", (ev) => {
  if (["Control", "Shift", "Alt", "Meta", "AltGraph"].includes(ev.key)) heldKeys.add(ev.key);
}, true);
window.addEventListener("keyup", (ev) => heldKeys.delete(ev.key), true);
window.addEventListener("blur", () => heldKeys.clear());

function keysReleased(timeout = 2000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const check = () => {
      if (!heldKeys.size || Date.now() - start > timeout) resolve(!heldKeys.size);
      else setTimeout(check, 20);
    };
    check();
  });
}

async function autotypeEntry(id, window = null) {
  if (!(await keysReleased())) {
    setStatus("Saisie annulée : relâchez les touches du raccourci.");
    return;
  }
  setStatus("Saisie automatique…");
  try {
    await invoke("autotype_entry", { id, window });
    setStatus("Saisie automatique effectuée.");
  } catch (e) {
    setStatus("Saisie automatique impossible : " + errorText(e));
  }
}
$("btn-autotype").addEventListener("click", () => state.selected && autotypeEntry(state.selected));
function autotypeSelected() {
  return autotypeEntry(state.selected);
}

// --- choix de l'entrée (raccourci global)
let atPending = null;
const atPick = { window: null, items: [], matches: new Set(), index: -1, gen: 0 };

function wipeAutotype() {
  atPending = null;
  Object.assign(atPick, { window: null, items: [], matches: new Set(), index: -1, gen: atPick.gen + 1 });
  $("at-list").replaceChildren();
  $("at-search").value = "";
  if ($("at-dialog").open) $("at-dialog").close();
  Object.assign(edAt, { id: null, view: null, initial: null });
  $("ed-at-assoc").replaceChildren();
}

function renderAtList() {
  const list = $("at-list");
  if (!atPick.items.length) {
    list.replaceChildren(el("li", { className: "empty" }, $("at-search").value.trim() ? "Aucune entrée trouvée" : "Tapez pour rechercher une entrée"));
  } else {
    list.replaceChildren(
      ...atPick.items.map((it, i) => {
        const li = el("li", { role: "option" }, el("span", {}, it.title || "(sans titre)"), el("small", {}, [it.username, it.url].filter(Boolean).join(" — ")));
        li.setAttribute("aria-selected", String(i === atPick.index));
        if (atPick.matches.has(it.id)) li.classList.add("match");
        li.addEventListener("click", () => {
          atPick.index = i;
          renderAtList();
        });
        li.addEventListener("dblclick", () => {
          atPick.index = i;
          $("at-form").requestSubmit();
        });
        return li;
      }),
    );
    list.children[atPick.index]?.scrollIntoView({ block: "nearest" });
  }
  $("at-type").disabled = atPick.index < 0;
}

async function searchAt() {
  const gen = ++atPick.gen;
  const q = $("at-search").value.trim();
  let items = [];
  try {
    const matches = atPick.window && !q ? await invoke("autotype_matches", { window: atPick.window }) : [];
    atPick.matches = new Set(matches.map((m) => m.id));
    items = q ? (await invoke("entries", { query: q, group: null })).items.slice(0, 200) : matches;
  } catch (e) {
    $("at-pick-error").textContent = errorText(e);
  }
  if (gen !== atPick.gen) return;
  atPick.items = items;
  atPick.index = items.length ? 0 : -1;
  renderAtList();
}

function openAutotypePicker(window) {
  if ($("view-main").hidden) {
    // Verrouillé : on choisira après le déverrouillage.
    atPending = { window };
    return;
  }
  for (const d of document.querySelectorAll("dialog[open]")) if (d.id !== "at-dialog" && d.id !== "bp-dialog") d.close();
  atPick.window = window;
  $("at-window").textContent = window ? `Fenêtre : ${window}` : "Choisissez l'entrée à taper dans la fenêtre précédente.";
  $("at-pick-error").textContent = "";
  $("at-search").value = "";
  atPick.items = [];
  atPick.index = -1;
  renderAtList();
  if (!$("at-dialog").open) $("at-dialog").showModal();
  $("at-search").focus();
  searchAt();
}

let atTimer = null;
$("at-search").addEventListener("input", () => {
  clearTimeout(atTimer);
  atTimer = setTimeout(searchAt, 150);
});
$("at-search").addEventListener("keydown", (ev) => {
  if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp") return;
  ev.preventDefault();
  if (!atPick.items.length) return;
  atPick.index = Math.min(Math.max(atPick.index + (ev.key === "ArrowDown" ? 1 : -1), 0), atPick.items.length - 1);
  renderAtList();
});
$("at-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const it = atPick.items[atPick.index];
  if (!it) return;
  const window = atPick.window;
  $("at-dialog").close();
  autotypeEntry(it.id, window);
});
$("at-cancel").addEventListener("click", () => $("at-dialog").close());
$("at-dialog").addEventListener("close", () => {
  setTimeout(quickIdle, 0);
  atPick.gen++;
  atPick.items = [];
  $("at-list").replaceChildren();
});

listen("autotype_global", async (ev) => {
  if (!PROMPTS_HERE) return;
  // La fenêtre rapide, cachée, peut avoir manqué un déverrouillage.
  if (QUICK) await refresh().catch(() => {});
  openAutotypePicker(typeof ev.payload?.window === "string" ? ev.payload.window : null);
});
listen("autotype_error", (ev) => {
  const msg = String(ev.payload?.message ?? "erreur");
  setStatus(msg);
  if ($("settings-dialog").open) $("at-error").textContent = msg;
});

// --- réglages (Paramètres › Saisie auto)
const atCfg = { config: null, global: "" };

/** Combinaison du raccourci global (Super autorisé). */
function globalComboOf(ev) {
  const key = eventKey(ev);
  if (!key || !(/^[A-Z0-9]$/.test(key) || /^F([1-9]|1[0-2])$/.test(key))) return null;
  const parts = [];
  if (ev.ctrlKey) parts.push("Ctrl");
  if (ev.altKey) parts.push("Alt");
  if (ev.shiftKey) parts.push("Shift");
  if (ev.metaKey) parts.push("Super");
  parts.push(key);
  return parts.join("+");
}

const METHOD_LABEL = { portal: "portail du bureau (Wayland)", x11: "X11 (XTest)", send_input: "SendInput (Windows)" };

async function renderAutotypeSettings() {
  let st;
  try {
    st = await invoke("autotype_status");
  } catch (e) {
    $("at-error").textContent = errorText(e);
    return;
  }
  const f = $("autotype-form");
  atCfg.config = st.config;
  atCfg.global = st.config.global_shortcut ?? "";
  f.method.value = st.config.method;
  f.default_sequence.value = st.config.default_sequence;
  f.start_delay_ms.value = st.config.start_delay_ms;
  f.key_delay_ms.value = st.config.key_delay_ms;
  $("at-global").textContent = comboLabel(atCfg.global).replace("Super", "Super");
  $("at-state").textContent = st.effective
    ? `Saisie par ${METHOD_LABEL[st.effective]}.` + (st.effective === "portal" ? " À la première saisie, le bureau demande l'autorisation de contrôler le clavier." : "")
    : "Aucun moyen d'émuler le clavier avec cette méthode sur ce système.";
}

$("at-global").addEventListener("click", () => {
  recordShortcut($("at-global"), (combo) => {
    if (combo && !/(^|\+)(Ctrl|Alt|Super)\+/.test(combo)) return "il faut Ctrl, Alt ou Super";
    atCfg.global = combo;
    $("at-global").textContent = comboLabel(combo);
    $("at-done").textContent = "";
    return null;
  });
  recording.global = true;
});
$("at-global-clear").addEventListener("click", () => {
  stopRecording();
  atCfg.global = "";
  $("at-global").textContent = comboLabel("");
});

$("autotype-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  stopRecording();
  const f = $("autotype-form");
  $("at-error").textContent = "";
  $("at-done").textContent = "";
  const config = {
    method: f.method.value,
    default_sequence: f.default_sequence.value,
    start_delay_ms: Number(f.start_delay_ms.value) || 0,
    key_delay_ms: Number(f.key_delay_ms.value) || 0,
    global_shortcut: atCfg.global || null,
  };
  try {
    await invoke("save_autotype_config", { config });
    await renderAutotypeSettings();
    $("at-done").textContent = "Réglages enregistrés.";
  } catch (e) {
    $("at-error").textContent = errorText(e);
  }
});

// --- onglet « Saisie auto » de l'éditeur
const edAt = { id: null, view: null, initial: null };

function renderEntryAutotype() {
  const v = edAt.view;
  $("ed-at-new").hidden = Boolean(v);
  $("ed-at").hidden = !v;
  if (!v) return;
  $("ed-at-enabled").checked = v.enabled;
  $("ed-at-sequence").value = v.sequence ?? "";
  $("ed-at-assoc").replaceChildren(
    ...v.associations.map((a, i) => {
      const w = el("input", { value: a.window, maxLength: 512, spellcheck: false, placeholder: "Titre de fenêtre (*)", ariaLabel: "Titre de fenêtre" });
      const q = el("input", { value: a.sequence ?? "", maxLength: 1024, spellcheck: false, placeholder: "Séquence de l'entrée", ariaLabel: "Séquence" });
      w.addEventListener("input", () => (a.window = w.value));
      q.addEventListener("input", () => (a.sequence = q.value || null));
      const del = el("button", { type: "button", className: "small", title: "Retirer" }, "Retirer");
      del.addEventListener("click", () => {
        v.associations.splice(i, 1);
        renderEntryAutotype();
      });
      return el("li", {}, w, q, del);
    }),
  );
}

async function loadEntryAutotype(id) {
  Object.assign(edAt, { id, view: null, initial: null });
  if (id) {
    try {
      const v = await invoke("entry_autotype", { id });
      if (edAt.id !== id) return;
      edAt.view = v;
      edAt.initial = JSON.stringify(v);
    } catch (e) {
      setStatus(errorText(e));
    }
  }
  renderEntryAutotype();
}

$("ed-at-enabled").addEventListener("change", () => {
  if (edAt.view) edAt.view.enabled = $("ed-at-enabled").checked;
});
$("ed-at-sequence").addEventListener("input", () => {
  if (edAt.view) edAt.view.sequence = $("ed-at-sequence").value || null;
});
$("ed-at-add").addEventListener("click", () => {
  if (!edAt.view) return;
  edAt.view.associations.push({ window: "", sequence: null });
  renderEntryAutotype();
  $("ed-at-assoc").lastElementChild?.querySelector("input")?.focus();
});

async function saveEntryAutotype(id) {
  if (edAt.id !== id || !edAt.view || JSON.stringify(edAt.view) === edAt.initial) return;
  // Lignes laissées vides : ignorées plutôt que refusées.
  const view = { ...edAt.view, associations: edAt.view.associations.filter((a) => a.window.trim()) };
  await invoke("set_entry_autotype", { id, view });
}

// ---------------------------------------------------------------- agent SSH

const SSH_SETTINGS = "KeeAgent.settings";
const edSsh = { id: null, view: null, initial: null };

function wipeSsh() {
  Object.assign(edSsh, { id: null, view: null, initial: null });
  $("ed-ssh-attachment").replaceChildren();
  $("ed-ssh-key-fp").textContent = "";
  $("ed-ssh-key-comment").textContent = "";
  $("ssh-keys").replaceChildren();
  $("ssh-unlock-errors").replaceChildren();
}

/** Réglages modifiés depuis le dernier enregistrement. */
function sshDirty() {
  return edSsh.view && JSON.stringify(edSsh.view.settings) !== edSsh.initial;
}

function renderEntrySsh() {
  const v = edSsh.view;
  $("ed-ssh-new").hidden = Boolean(v);
  $("ed-ssh").hidden = !v;
  if (!v) return;
  const s = v.settings;
  $("ed-ssh-allow").checked = s.allow;
  $("ed-ssh-opts").hidden = !s.allow;
  $("ed-ssh-source").value = s.use_attachment ? "attachment" : "file";
  $("ed-ssh-attachment-row").hidden = !s.use_attachment;
  $("ed-ssh-file-row").hidden = s.use_attachment;
  const names = (state.editing?.view?.attachments ?? []).map((a) => a.name).filter((n) => n !== SSH_SETTINGS);
  if (s.attachment_name && !names.includes(s.attachment_name)) names.unshift(s.attachment_name);
  $("ed-ssh-attachment").replaceChildren(
    ...(names.length ? names.map((n) => el("option", { value: n }, n)) : [el("option", { value: "" }, "Aucune pièce jointe")]),
  );
  $("ed-ssh-attachment").value = s.attachment_name;
  $("ed-ssh-file").value = s.file_name;
  $("ed-ssh-add-open").checked = s.add_at_open;
  $("ed-ssh-remove-close").checked = s.remove_at_close;
  $("ed-ssh-confirm").checked = s.confirm;
  $("ed-ssh-lifetime-on").checked = s.use_lifetime;
  $("ed-ssh-lifetime").value = s.lifetime_secs;
  $("ed-ssh-lifetime").disabled = !s.use_lifetime;
  // La clé décrite est celle des réglages enregistrés.
  const dirty = sshDirty();
  $("ed-ssh-key").hidden = !v.key || dirty;
  if (v.key) {
    $("ed-ssh-key-type").textContent = v.key.algorithm + (v.key.encrypted ? " (protégée par phrase de passe)" : "");
    $("ed-ssh-key-fp").textContent = v.key.fingerprint;
    $("ed-ssh-key-comment").textContent = v.key.comment || "—";
  }
  $("ed-ssh-key-error").hidden = !v.key_error || dirty;
  $("ed-ssh-key-error").textContent = v.key_error ?? "";
  for (const b of ["ed-ssh-add", "ed-ssh-remove", "ed-ssh-copy-pub"]) $(b).disabled = dirty || !v.key;
  $("ed-ssh-state").textContent = dirty
    ? "Enregistrez l'entrée pour appliquer ces réglages."
    : v.in_agent
      ? "Clé ajoutée à l'agent par KittyPass."
      : "";
}

async function loadEntrySsh(id) {
  Object.assign(edSsh, { id, view: null, initial: null });
  if (id) {
    try {
      const v = await invoke("entry_ssh", { id });
      if (edSsh.id !== id) return;
      edSsh.view = v;
      edSsh.initial = JSON.stringify(v.settings);
    } catch (e) {
      // Réglages illisibles (autre logiciel, autre appareil) : repartir des valeurs par défaut.
      if (edSsh.id !== id) return;
      edSsh.view = { settings: { ...SSH_DEFAULTS }, key: null, key_error: errorText(e), in_agent: false };
      edSsh.initial = null;
    }
  }
  renderEntrySsh();
}

const SSH_DEFAULTS = {
  allow: false,
  add_at_open: false,
  remove_at_close: false,
  confirm: false,
  use_lifetime: false,
  lifetime_secs: 600,
  use_attachment: false,
  attachment_name: "",
  file_name: "",
  save_attachment_to_temp_file: false,
};

function sshEdit(change) {
  if (!edSsh.view) return;
  change(edSsh.view.settings);
  renderEntrySsh();
}

$("ed-ssh-allow").addEventListener("change", () =>
  sshEdit((s) => {
    s.allow = $("ed-ssh-allow").checked;
    // Première activation : réglages conseillés, comme KeePassXC.
    if (s.allow && JSON.stringify(s) === JSON.stringify({ ...SSH_DEFAULTS, allow: true })) {
      const first = (state.editing?.view?.attachments ?? []).find((a) => a.name !== SSH_SETTINGS);
      Object.assign(s, { add_at_open: true, remove_at_close: true, use_attachment: Boolean(first), attachment_name: first?.name ?? "" });
    }
  }),
);
$("ed-ssh-source").addEventListener("change", () => sshEdit((s) => (s.use_attachment = $("ed-ssh-source").value === "attachment")));
$("ed-ssh-attachment").addEventListener("change", () => sshEdit((s) => (s.attachment_name = $("ed-ssh-attachment").value)));
$("ed-ssh-file").addEventListener("change", () => sshEdit((s) => (s.file_name = $("ed-ssh-file").value.trim())));
$("ed-ssh-add-open").addEventListener("change", () => sshEdit((s) => (s.add_at_open = $("ed-ssh-add-open").checked)));
$("ed-ssh-remove-close").addEventListener("change", () => sshEdit((s) => (s.remove_at_close = $("ed-ssh-remove-close").checked)));
$("ed-ssh-confirm").addEventListener("change", () => sshEdit((s) => (s.confirm = $("ed-ssh-confirm").checked)));
$("ed-ssh-lifetime-on").addEventListener("change", () => sshEdit((s) => (s.use_lifetime = $("ed-ssh-lifetime-on").checked)));
$("ed-ssh-lifetime").addEventListener("change", () =>
  sshEdit((s) => {
    const n = Math.round(Number($("ed-ssh-lifetime").value));
    s.lifetime_secs = Number.isFinite(n) ? Math.max(1, Math.min(2592000, n)) : 600;
  }),
);

async function sshAction(btn, command, done) {
  const id = edSsh.id;
  if (!id) return;
  try {
    await busy(btn, () => invoke(command, { id }));
    await loadEntrySsh(id);
    $("ed-ssh-state").textContent = done;
  } catch (e) {
    $("ed-ssh-state").textContent = errorText(e);
  }
}
$("ed-ssh-add").addEventListener("click", () => sshAction($("ed-ssh-add"), "ssh_add", "Clé ajoutée à l'agent."));
$("ed-ssh-remove").addEventListener("click", () => sshAction($("ed-ssh-remove"), "ssh_remove", "Clé retirée de l'agent."));
$("ed-ssh-copy-pub").addEventListener("click", async () => {
  const key = edSsh.view?.key;
  if (!key) return;
  try {
    await invoke("copy_value", { value: key.public_key });
    $("ed-ssh-state").textContent = "Clé publique copiée.";
  } catch (e) {
    $("ed-ssh-state").textContent = errorText(e);
  }
});

async function saveEntrySsh(id) {
  if (edSsh.id !== id || !edSsh.view || !sshDirty()) return;
  const s = { ...edSsh.view.settings };
  if (!s.allow && edSsh.initial === null) return;
  await invoke("set_entry_ssh", { id, settings: s });
}

// --- Paramètres › Agent SSH
async function renderSshSettings() {
  let st;
  try {
    st = await invoke("ssh_status");
  } catch (e) {
    $("ssh-error").textContent = errorText(e);
    return;
  }
  const f = $("ssh-form");
  f.enabled.checked = st.config.enabled;
  f.socket.value = st.config.socket ?? "";
  f.socket.placeholder = st.socket && !st.config.socket ? `SSH_AUTH_SOCK : ${st.socket}` : "Celui de SSH_AUTH_SOCK";
  $("ssh-state").textContent = !st.config.enabled
    ? "Désactivé : KittyPass ne touche pas à l'agent SSH."
    : st.available
      ? `Agent joignable (${st.socket}).`
      : `Agent injoignable : ${st.error ?? "aucun agent"}.`;
  const box = $("ssh-unlock-errors");
  box.hidden = !st.unlock_errors.length;
  box.replaceChildren(
    ...(st.unlock_errors.length
      ? [el("strong", {}, "Clés non ajoutées au déverrouillage :"), el("ul", {}, ...st.unlock_errors.map((m) => el("li", {}, m)))]
      : []),
  );
  const title = (id) => state.items.find((i) => i.id === id)?.title;
  $("ssh-keys").replaceChildren(
    ...(st.keys.length
      ? st.keys.map((k) =>
          el(
            "li",
            {},
            el("code", {}, k.fingerprint),
            ` ${k.comment}`,
            k.entry ? el("small", { className: "muted" }, ` — KittyPass${title(k.entry) ? ` : ${title(k.entry)}` : ""}`) : "",
          ),
        )
      : [el("li", { className: "muted" }, st.config.enabled && st.available ? "Aucune clé." : "—")]),
  );
}

$("ssh-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = $("ssh-form");
  $("ssh-error").textContent = "";
  $("ssh-done").textContent = "";
  const config = { enabled: f.enabled.checked, socket: f.socket.value.trim() || null };
  try {
    await busy(f.querySelector("button[type=submit]"), () => invoke("save_ssh_config", { config }));
    await renderSshSettings();
    $("ssh-done").textContent = "Réglages enregistrés.";
    if (edSsh.id) loadEntrySsh(edSsh.id);
  } catch (e) {
    $("ssh-error").textContent = errorText(e);
  }
});

/** Après le déverrouillage : signale les clés que l'agent n'a pas reçues. */
async function reportSshUnlock() {
  try {
    const st = await invoke("ssh_status");
    if (st.unlock_errors.length) {
      setStatus(`Agent SSH : ${st.unlock_errors.length} clé(s) non ajoutée(s) (Paramètres › Agent SSH).`);
    }
  } catch {
    // Sans effet sur le déverrouillage.
  }
}

// ---------------------------------------------------------------- compte

const acct = { gen: 0 };

function acctErrors() {
  for (const id of ["lock-error", "pw-error", "tfa-error", "sess-error", "ver-error", "ver-done", "admin-error"]) $(id).textContent = "";
}

/** Oublie tout ce qui est affiché ou saisi (fermeture, verrouillage). */
function wipeAccount() {
  acct.gen++;
  acctErrors();
  $("pw-form").reset();
  $("bio-form").reset();
  $("tfa-disable-form").reset();
  $("tfa-enable-form").reset();
  $("tfa-setup").hidden = true;
  $("tfa-secret").textContent = "";
  const c = $("tfa-qr");
  c.getContext("2d").clearRect(0, 0, c.width, c.height);
  $("tfa-codes").hidden = true;
  $("tfa-codes-list").replaceChildren();
  $("tfa-disable-form").hidden = true;
  hideInvite();
  $("admin-section").hidden = true;
  $("users-list").replaceChildren();
}

async function renderAccount() {
  wipeAccount();
  renderBiometric();
  renderAutofill();
  const gen = acct.gen;
  const lc = await invoke("lock_config");
  const f = $("lock-form");
  f.on.checked = lc.auto_lock_secs != null;
  f.minutes.value = Math.max(1, Math.round((lc.auto_lock_secs ?? 300) / 60));
  f.minutes.disabled = !f.on.checked;
  $("acct-summary").textContent = "Chargement du compte…";
  try {
    const a = await invoke("account");
    if (gen !== acct.gen) return;
    $("acct-summary").textContent = `Compte « ${a.username} ».`;
    renderTfa(a);
    $("admin-section").hidden = !a.is_admin;
    if (a.is_admin) renderUsers();
  } catch (e) {
    if (gen !== acct.gen) return;
    $("acct-summary").textContent = "Serveur injoignable : " + errorText(e);
    $("tfa-actions").hidden = true;
    $("tfa-state").textContent = "";
    return;
  }
  renderSessions();
  renderVersions();
}

function renderTfa(a) {
  $("tfa-actions").hidden = false;
  $("tfa-state").textContent = a.totp_enabled
    ? "Active : un code est demandé à chaque connexion d'un appareil." + (a.require_2fa ? " Imposée par le serveur." : "")
    : "Inactive : le mot de passe suffit pour connecter un nouvel appareil.";
  $("tfa-start").hidden = a.totp_enabled;
  $("tfa-stop").hidden = !a.totp_enabled || a.require_2fa;
}

$("lock-form").on.addEventListener("change", (ev) => ($("lock-form").minutes.disabled = !ev.target.checked));
$("lock-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = $("lock-form");
  $("lock-error").textContent = "";
  const min = Number(f.minutes.value);
  if (f.on.checked && !(Number.isInteger(min) && min >= 1 && min <= 1440)) {
    return ($("lock-error").textContent = "Entre 1 et 1440 minutes.");
  }
  try {
    await busy(f.querySelector("button[type=submit]"), () => invoke("save_lock_config", { config: { auto_lock_secs: f.on.checked ? min * 60 : null } }));
    setStatus(f.on.checked ? `Verrouillage après ${min} min d'inactivité.` : "Verrouillage automatique désactivé.");
  } catch (e) {
    $("lock-error").textContent = errorText(e);
  }
});

$("pw-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = $("pw-form");
  $("pw-error").textContent = "";
  if (f.new.value !== f.confirm.value) return ($("pw-error").textContent = "Les deux nouveaux mots de passe diffèrent.");
  if (f.new.value === f.current.value) return ($("pw-error").textContent = "Le nouveau mot de passe est identique à l'actuel.");
  const ok = await ask("Changer le mot de passe maître ? Les autres appareils seront déconnectés et demanderont le nouveau.", { ok: "Changer" });
  if (!ok) return;
  const gen = acct.gen;
  try {
    await busy($("pw-run"), () => invoke("change_master_password", { current: f.current.value, new: f.new.value }));
    f.reset();
    setStatus("Mot de passe maître changé.");
    if (gen === acct.gen) renderSessions();
  } catch (e) {
    $("pw-error").textContent =
      e.code === "invalid_password" || e.code === "invalid_credentials" ? "Mot de passe actuel incorrect." : "Changement impossible : " + errorText(e);
    if (e.code === "totp_required") handleSyncError(e, false);
  }
});

function drawQr(size, modules) {
  const c = $("tfa-qr");
  const quiet = 2;
  const scale = Math.max(2, Math.floor(184 / (size + 2 * quiet)));
  c.width = c.height = (size + 2 * quiet) * scale;
  const g = c.getContext("2d");
  g.fillStyle = "#fff";
  g.fillRect(0, 0, c.width, c.height);
  g.fillStyle = "#000";
  modules.forEach((dark, i) => {
    if (dark) g.fillRect(((i % size) + quiet) * scale, (Math.floor(i / size) + quiet) * scale, scale, scale);
  });
}

$("tfa-start").addEventListener("click", async () => {
  $("tfa-error").textContent = "";
  const gen = acct.gen;
  try {
    const s = await busy($("tfa-start"), () => invoke("setup_2fa"));
    if (gen !== acct.gen) return;
    drawQr(s.qr_size, s.qr);
    $("tfa-secret").textContent = s.secret.replace(/(.{4})/g, "$1 ").trim();
    $("tfa-setup").hidden = false;
    $("tfa-start").hidden = true;
    $("tfa-enable-form").code.focus();
  } catch (e) {
    $("tfa-error").textContent = errorText(e);
  }
});

$("tfa-enable-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = $("tfa-enable-form");
  $("tfa-error").textContent = "";
  const gen = acct.gen;
  try {
    const codes = await busy(f.querySelector("button"), () => invoke("enable_2fa", { code: f.code.value.trim() }));
    if (gen !== acct.gen) return;
    wipeAccount();
    $("tfa-codes-list").replaceChildren(...codes.map((c) => el("li", {}, c)));
    $("tfa-codes").hidden = false;
    renderTfa({ totp_enabled: true, require_2fa: false });
    setStatus("2FA activée. Les autres appareils devront se reconnecter avec un code.");
    renderSessions();
  } catch (e) {
    $("tfa-error").textContent = e.code === "invalid_totp" ? "Code incorrect : vérifiez l'heure du téléphone et réessayez." : errorText(e);
    f.code.select();
  }
});

$("tfa-codes-done").addEventListener("click", () => {
  $("tfa-codes-list").replaceChildren();
  $("tfa-codes").hidden = true;
});

$("tfa-stop").addEventListener("click", () => {
  $("tfa-disable-form").hidden = false;
  $("tfa-stop").hidden = true;
  $("tfa-disable-form").password.focus();
});

$("tfa-disable-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = $("tfa-disable-form");
  $("tfa-error").textContent = "";
  try {
    await busy(f.querySelector("button"), () => invoke("disable_2fa", { password: f.password.value, code: f.code.value.trim() }));
    f.reset();
    f.hidden = true;
    renderTfa({ totp_enabled: false, require_2fa: false });
    setStatus("2FA désactivée.");
  } catch (e) {
    $("tfa-error").textContent = e.code === "invalid_credentials" ? "Mot de passe ou code incorrect." : errorText(e);
  }
});

// --- administration (comptes admin)
function hideInvite() {
  $("invite-result").hidden = true;
  $("invite-code").textContent = "";
  $("invite-info").textContent = "";
}

$("invite-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = $("invite-form");
  $("admin-error").textContent = "";
  hideInvite();
  try {
    const inv = await busy(f.querySelector("button[type=submit]"), () =>
      invoke("create_invite", { admin: f.admin.checked, hours: Number(f.hours.value) }));
    $("invite-code").textContent = inv.code;
    const days = inv.expires_in_hours >= 24 ? `${Math.round(inv.expires_in_hours / 24)} j` : `${inv.expires_in_hours} h`;
    $("invite-info").textContent = `${inv.admin ? "Compte administrateur. " : ""}Valable ${days}, une seule fois. Adresse du serveur à donner aussi : ${inv.server_url}`;
    $("invite-result").hidden = false;
    f.reset();
  } catch (e) {
    $("admin-error").textContent = errorText(e);
  }
});
$("invite-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("invite-code").textContent);
    setStatus("Code d'invitation copié.");
  } catch {
    $("admin-error").textContent = "Copie impossible : sélectionnez le code et copiez-le à la main.";
  }
});
$("invite-done").addEventListener("click", hideInvite);

async function renderUsers() {
  const gen = acct.gen;
  try {
    const list = await invoke("users");
    if (gen !== acct.gen) return;
    $("users-list").replaceChildren(
      ...list.map((u) => {
        const info = el("span", {}, el("strong", {}, u.username),
          u.is_admin ? el("span", { className: "badge" }, "admin") : "",
          u.current ? " (vous)" : "",
          el("br"), el("small", { className: "muted" },
            `Créé le ${fmtDate(u.created_at)} · 2FA ${u.totp_enabled ? "active" : "inactive"}${u.disabled ? " · désactivé" : ""}`));
        if (u.current) return el("li", {}, info);
        const b = el("button", { type: "button", className: u.disabled ? "small" : "small danger" }, u.disabled ? "Réactiver" : "Désactiver");
        b.addEventListener("click", async () => {
          if (!u.disabled && !(await ask(`Désactiver le compte « ${u.username} » ? Ses appareils sont déconnectés et il ne peut plus se connecter (ses données restent sur le serveur).`, { ok: "Désactiver", danger: true }))) return;
          try {
            await busy(b, () => invoke("set_user_disabled", { username: u.username, disabled: !u.disabled }));
            renderUsers();
          } catch (e) {
            $("admin-error").textContent = errorText(e);
          }
        });
        return el("li", {}, info, b);
      }),
    );
  } catch (e) {
    if (gen === acct.gen) $("admin-error").textContent = errorText(e);
  }
}

async function renderSessions() {
  const gen = acct.gen;
  try {
    const list = await invoke("sessions");
    if (gen !== acct.gen) return;
    $("sess-others").disabled = !list.some((s) => !s.current);
    $("sess-list").replaceChildren(
      ...list.map((s) => {
        const info = el("span", {}, el("strong", {}, s.device || "Appareil sans nom"), s.current ? " (cet appareil)" : "",
          el("br"), el("small", { className: "muted" }, `Connecté le ${fmtDate(s.created_at)}, vu le ${fmtDate(s.last_seen)}`));
        if (s.current) return el("li", {}, info);
        const b = el("button", { type: "button", className: "small" }, "Déconnecter");
        b.addEventListener("click", async () => {
          if (!(await ask(`Déconnecter « ${s.device} » ?`, { ok: "Déconnecter", danger: true }))) return;
          try {
            await busy(b, () => invoke("revoke_session", { id: s.id }));
            renderSessions();
          } catch (e) {
            $("sess-error").textContent = errorText(e);
          }
        });
        return el("li", {}, info, b);
      }),
    );
  } catch (e) {
    if (gen === acct.gen) $("sess-error").textContent = errorText(e);
  }
}

$("sess-others").addEventListener("click", async () => {
  if (!(await ask("Déconnecter tous les autres appareils ?", { ok: "Déconnecter", danger: true }))) return;
  $("sess-error").textContent = "";
  try {
    const n = await busy($("sess-others"), () => invoke("revoke_other_sessions"));
    setStatus(`${n} appareil(s) déconnecté(s).`);
    renderSessions();
  } catch (e) {
    $("sess-error").textContent = errorText(e);
  }
});

async function renderVersions() {
  const gen = acct.gen;
  try {
    const list = await invoke("vault_versions");
    if (gen !== acct.gen) return;
    $("ver-list").replaceChildren(
      ...(list.length
        ? list.map((v, i) => {
            const get = el("button", { type: "button", className: "small" }, "Récupérer");
            const save = el("button", { type: "button", className: "small" }, "Enregistrer…");
            get.addEventListener("click", () => restoreVersion(v, get));
            save.addEventListener("click", () => saveVersion(v, save));
            return el("li", {},
              el("span", {}, `Version ${v.version}`, el("small", { className: "muted" }, `${fmtDate(v.created_at)} · ${fmtSize(v.size)}${i === 0 ? " · actuelle" : ""}`)),
              el("span", { className: "btns" }, get, save));
          })
        : [el("li", { className: "muted" }, "Aucune version.")]),
    );
  } catch (e) {
    if (gen === acct.gen) $("ver-error").textContent = errorText(e);
  }
}

async function restoreVersion(v, btn) {
  $("ver-error").textContent = "";
  $("ver-done").textContent = "";
  const name = `Version ${v.version} du ${fmtDate(v.created_at)}`;
  const req = { version: v.version, parent: state.root.id, name, password: null, key_file: null };
  try {
    let r;
    try {
      r = await busy(btn, () => invoke("restore_version", { req }));
    } catch (e) {
      if (e.code !== "invalid_password") throw e;
      // Version d'avant un changement de mot de passe : l'ancien est demandé.
      const old = await ask("Cette version est chiffrée avec un ancien mot de passe maître. Entrez-le :", { input: "", ok: "Récupérer", secret: true });
      if (old == null) return;
      r = await busy(btn, () => invoke("restore_version", { req: { ...req, password: old } }));
    }
    $("ver-done").textContent = `${r.imported} entrée(s) copiée(s) dans le groupe « ${name} ».`;
    vd.imported = r.group_id;
    await loadGroups();
  } catch (e) {
    $("ver-error").textContent = e.code === "invalid_password" ? "Mot de passe incorrect." : "Récupération impossible : " + errorText(e);
  }
}

async function saveVersion(v, btn) {
  $("ver-error").textContent = "";
  $("ver-done").textContent = "";
  try {
    if (await busy(btn, () => invoke("save_version", { version: v.version }))) {
      $("ver-done").textContent = `Version ${v.version} enregistrée (fichier KeePass chiffré).`;
    }
  } catch (e) {
    $("ver-error").textContent = errorText(e);
  }
}

/** Mot de passe maître changé ailleurs : demande le nouveau. Vrai si adopté. */
function askNewPassword() {
  const dlg = $("adopt-dialog");
  const form = $("adopt-form");
  if (dlg.open) return Promise.resolve(false);
  form.reset();
  $("adopt-error").textContent = "";
  dlg.showModal();
  form.password.focus();
  return new Promise((resolve) => {
    let totp = null;
    const done = (v) => {
      form.removeEventListener("submit", onSubmit);
      $("adopt-cancel").removeEventListener("click", onCancel);
      dlg.removeEventListener("cancel", onCancel);
      form.reset();
      dlg.close();
      resolve(v);
    };
    const onSubmit = async (ev) => {
      ev.preventDefault();
      const password = form.password.value;
      $("adopt-error").textContent = "";
      try {
        await invoke("adopt_master_password", { password, totp });
        setStatus("Nouveau mot de passe maître adopté.");
        done(true);
      } catch (e) {
        if (e.code === "totp_required") {
          dlg.close();
          const ok = await askTotp((code) => invoke("adopt_master_password", { password, totp: code }));
          form.reset();
          if (ok) setStatus("Nouveau mot de passe maître adopté.");
          return done(ok);
        }
        $("adopt-error").textContent = e.code === "invalid_credentials" ? "Mot de passe refusé par le serveur." : errorText(e);
        form.password.select();
      }
    };
    const onCancel = (ev) => {
      ev.preventDefault();
      done(false);
    };
    form.addEventListener("submit", onSubmit);
    $("adopt-cancel").addEventListener("click", onCancel);
    dlg.addEventListener("cancel", onCancel);
  });
}

// ---------------------------------------------------------------- synchronisation

async function syncNow(verbose = true) {
  const btn = $("btn-sync");
  try {
    setStatus("Synchronisation…");
    const r = await busy(btn, () => invoke("sync"));
    setStatus(`Synchronisé (version ${r.version}${r.pulled ? `, ${r.pulled} changement(s) reçu(s)` : ""}).`);
    if (r.pulled && ed.hidden) {
      await loadGroups();
      await loadEntries();
    }
  } catch (e) {
    await handleSyncError(e, verbose);
  }
}

/**
 * Demande un code 2FA et le fait vérifier par `verify`. En cas de code refusé,
 * le dialogue reste ouvert avec l'erreur. Résout à true si accepté, false si annulé.
 */
let totpPending = null;
function askTotp(verify) {
  // Déjà ouverte (synchro et changement en même temps) : une seule saisie,
  // dont le résultat sert aux deux demandes.
  if (totpPending) return totpPending;
  totpPending = askTotpOnce(verify).finally(() => (totpPending = null));
  return totpPending;
}

function askTotpOnce(verify) {
  const dlg = $("totp-dialog");
  const form = $("totp-form");
  const error = $("totp-error");
  form.reset();
  error.textContent = "";
  dlg.showModal();
  form.code.focus();
  return new Promise((resolve) => {
    let pending = false;
    const done = (value) => {
      form.removeEventListener("submit", onSubmit);
      $("totp-cancel").removeEventListener("click", onCancel);
      dlg.removeEventListener("cancel", onCancel);
      form.reset();
      error.textContent = "";
      dlg.close();
      resolve(value);
    };
    const onSubmit = async (ev) => {
      ev.preventDefault();
      const code = form.code.value.trim();
      if (!code || pending) return;
      pending = true;
      error.textContent = "";
      try {
        await verify(code);
        done(true);
      } catch (err) {
        error.textContent = errorText(err);
        form.code.select();
      } finally {
        pending = false;
      }
    };
    const onCancel = (ev) => {
      ev.preventDefault();
      done(false);
    };
    form.addEventListener("submit", onSubmit);
    $("totp-cancel").addEventListener("click", onCancel);
    dlg.addEventListener("cancel", onCancel); // touche Échap
  });
}

async function handleSyncError(e, verbose) {
  if (e.code === "invalid_credentials") {
    const adopted = await askNewPassword();
    if (adopted) await syncNow();
    else setStatus("Synchronisation en attente du nouveau mot de passe maître.");
    return;
  }
  if (e.code === "totp_required") {
    const accepted = await askTotp((totp) => invoke("relogin", { totp }));
    if (!accepted) return setStatus("Synchronisation en attente du code 2FA.");
    await syncNow();
    return;
  }
  if (e.code === "rollback_detected") {
    await ask(
      "Alerte de sécurité : le serveur a renvoyé une version plus ancienne du coffre que celle déjà vue. " +
        "La synchronisation est bloquée. Vérifiez votre serveur.",
      { ok: "Compris" },
    );
  }
  if (e.code === "network" && !verbose) return setStatus("Hors ligne : modifications gardées localement.");
  setStatus("Synchronisation impossible : " + errorText(e));
}

$("btn-sync").addEventListener("click", () => syncNow(true));
listen("synced", (ev) => {
  if (QUICK) return;
  if (ev.payload.pulled && ed.hidden) {
    loadGroups().then(loadEntries);
  }
  setStatus(`Synchronisé automatiquement (version ${ev.payload.version}).`);
});
// Seule la fenêtre principale gère la synchro (sinon deux demandes de reconnexion).
listen("sync_error", (ev) => !QUICK && handleSyncError(ev.payload, false));

refresh().catch((e) => setStatus(errorText(e)));

// ---------------------------------------------------------------- navigateur

// --- réglages de l'entrée (onglet « Navigateur » de l'éditeur)
const edBr = { id: null, view: null, initial: null };

function siteList(ul, hosts, onForget) {
  ul.replaceChildren(
    ...(hosts.length
      ? hosts.map((h) => {
          const b = el("button", { type: "button", className: "small" }, "Oublier");
          b.addEventListener("click", () => onForget(h));
          return el("li", {}, el("span", {}, h), b);
        })
      : [el("li", { className: "muted" }, "Aucun")]),
  );
}

function renderEntryBrowser() {
  const v = edBr.view;
  $("ed-br-new").hidden = Boolean(v);
  $("ed-br").hidden = !v;
  if (!v) return;
  $("ed-br-hidden").checked = v.hidden;
  siteList($("ed-br-allow"), v.allow, (h) => {
    v.allow = v.allow.filter((x) => x !== h);
    renderEntryBrowser();
  });
  siteList($("ed-br-deny"), v.deny, (h) => {
    v.deny = v.deny.filter((x) => x !== h);
    renderEntryBrowser();
  });
}

async function loadEntryBrowser(id) {
  Object.assign(edBr, { id, view: null, initial: null });
  if (id) {
    try {
      const v = await invoke("entry_browser", { id });
      if (edBr.id !== id) return;
      edBr.view = v;
      edBr.initial = JSON.stringify(v);
    } catch (e) {
      setStatus(errorText(e));
    }
  }
  renderEntryBrowser();
}

$("ed-br-hidden").addEventListener("change", () => {
  if (edBr.view) edBr.view.hidden = $("ed-br-hidden").checked;
});

async function saveEntryBrowser(id) {
  if (edBr.id !== id || !edBr.view || JSON.stringify(edBr.view) === edBr.initial) return;
  await invoke("set_entry_browser", { id, view: edBr.view });
}

// --- interrupteur et associations (onglet « Navigateur » de la boîte Coffre)
const OWNER = { kitty_pass: "KittyPass", kee_pass_xc: "KeePassXC", other: "un autre programme", none: "personne" };

async function renderBrowser() {
  const gen = vd.gen;
  let st;
  try {
    st = await invoke("browser_status");
  } catch (e) {
    $("br-error").textContent = errorText(e);
    return;
  }
  if (gen !== vd.gen) return;
  $("br-enabled").checked = st.enabled;
  $("br-state").textContent = st.enabled
    ? st.running
      ? "Activé : l'extension s'adresse à KittyPass."
      : "Activé, mais le service n'a pas pu démarrer."
    : "Désactivé : l'extension s'adresse à KeePassXC.";
  const list = st.hosts?.browsers ?? [];
  $("br-browsers").replaceChildren(
    ...(list.length
      ? list.map((b) => el("li", { className: b.owner === "kitty_pass" ? "ok" : "" }, el("strong", {}, b.browser), ` : répond ${OWNER[b.owner] ?? b.owner}`))
      : [el("li", { className: "muted" }, "Aucun navigateur compatible trouvé pour cet utilisateur.")]),
  );
  $("br-override").hidden = !(st.enabled && st.hosts?.keepassxc_overrides);
  await renderAssociations(gen);
}

async function renderAssociations(gen) {
  let list = [];
  try {
    list = await invoke("browser_associations");
  } catch (e) {
    $("br-error").textContent = errorText(e);
  }
  if (gen !== vd.gen) return;
  $("br-assoc").replaceChildren(
    ...(list.length
      ? list.map((a) => {
          const b = el("button", { type: "button", className: "small danger" }, "Révoquer");
          b.addEventListener("click", async () => {
            if (!(await ask(`Révoquer « ${a.id} » ? Ce navigateur devra être associé de nouveau.`, { ok: "Révoquer", danger: true }))) return;
            try {
              await invoke("browser_revoke", { id: a.id });
            } catch (e) {
              $("br-error").textContent = errorText(e);
            }
            renderAssociations(vd.gen);
          });
          const when = a.created ? el("small", { className: "muted" }, ` — ${fmtDate(a.created)}`) : "";
          return el("li", {}, el("span", {}, a.id, when), b);
        })
      : [el("li", { className: "muted" }, "Aucun")]),
  );
}

$("br-enabled").addEventListener("change", async () => {
  const box = $("br-enabled");
  const enabled = box.checked;
  $("br-error").textContent = "";
  box.disabled = true;
  try {
    await invoke("browser_set_enabled", { enabled });
  } catch (e) {
    $("br-error").textContent = errorText(e);
  } finally {
    box.disabled = false;
  }
  renderBrowser();
});

// --- demandes de l'extension
const bp = { queue: [], current: null };

function bpAnswer(answer) {
  const cur = bp.current;
  if (!cur) return;
  bp.current = null;
  $("bp-name").value = "";
  if ($("bp-dialog").open) $("bp-dialog").close();
  invoke("browser_answer", { id: cur.id, answer }).catch(() => {});
  nextBrowserPrompt();
  quickIdle();
}

/** Verrouillage : toute demande en cours ou en attente est refusée. */
function dropBrowserPrompts() {
  const all = [...(bp.current ? [bp.current] : []), ...bp.queue];
  bp.queue = [];
  bp.current = null;
  if ($("bp-dialog").open) $("bp-dialog").close();
  $("bp-name").value = "";
  for (const p of all) invoke("browser_answer", { id: p.id, answer: null }).catch(() => {});
}

function entryChoice(e, type, name, checked) {
  const input = el("input", { type, name, value: e.id, checked });
  const meta = [e.username || "(sans identifiant)", e.group].filter(Boolean).join(" · ");
  return el("li", {}, el("label", {}, input, el("span", {}, el("strong", {}, e.title || "(sans titre)"), el("small", { className: "muted" }, meta))));
}

function nextBrowserPrompt() {
  if (bp.current || !bp.queue.length) return;
  bp.current = bp.queue.shift();
  const p = bp.current.prompt;
  const name = $("bp-name");
  const entries = $("bp-entries");
  const warn = $("bp-warning");
  name.hidden = true;
  warn.hidden = true;
  entries.replaceChildren();
  $("bp-remember-row").hidden = true;
  $("bp-remember").checked = false;
  $("bp-deny").textContent = "Refuser";
  let title, message, ok;
  switch (p.kind) {
    case "associate":
      title = "Connexion d'un navigateur";
      message = "Un navigateur demande à utiliser KittyPass avec l'extension KeePassXC-Browser. Donnez-lui un nom pour le reconnaître. Si vous n'êtes pas à l'origine de cette demande, refusez.";
      name.hidden = false;
      name.value = "Navigateur";
      ok = "Associer";
      break;
    case "access":
      title = "Accès aux identifiants";
      message = `${p.host} demande ${p.entries.length > 1 ? "ces identifiants" : "cet identifiant"} :`;
      if (p.submit_host) {
        warn.hidden = false;
        warn.textContent = `Attention : le formulaire de cette page envoie les données à un autre site, ${p.submit_host}.`;
      }
      entries.replaceChildren(...p.entries.map((e) => entryChoice(e, "checkbox", "bp-entry", true)));
      $("bp-remember-row").hidden = false;
      ok = "Autoriser la sélection";
      break;
    case "update_login":
      title = "Mise à jour d'un identifiant";
      message = `${p.host} veut remplacer le mot de passe de « ${p.entry.title || "(sans titre)"} » (${p.entry.username || "sans identifiant"})` +
        (p.username && p.username !== p.entry.username ? ` et changer l'identifiant en « ${p.username} ».` : ".") +
        " L'ancienne version reste dans l'historique.";
      ok = "Mettre à jour";
      break;
    case "create_passkey":
      title = "Nouvelle passkey";
      message = `Créer une passkey pour ${p.rp_id}` + (p.rp_name && p.rp_name !== p.rp_id ? ` (« ${p.rp_name} »)` : "") +
        ` avec le compte « ${p.user_name || "sans nom"} » ? Elle sera enregistrée dans le coffre et synchronisée.`;
      ok = "Créer";
      $("bp-deny").textContent = "Annuler";
      break;
    case "use_passkey":
      title = "Connexion par passkey";
      message = `${p.rp_id} demande une passkey. Compte à utiliser :`;
      entries.replaceChildren(...p.entries.map((e, i) => entryChoice(e, "radio", "bp-entry", i === 0)));
      ok = "Se connecter";
      $("bp-deny").textContent = "Annuler";
      break;
    default:
      bpAnswer(null);
      return;
  }
  $("bp-title").textContent = title;
  $("bp-message").textContent = message;
  $("bp-ok").textContent = ok;
  $("bp-dialog").showModal();
  (name.hidden ? $("bp-ok") : name).focus();
  if (!name.hidden) name.select();
}

$("bp-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const cur = bp.current;
  if (!cur) return;
  const checked = [...$("bp-entries").querySelectorAll("input:checked")].map((i) => i.value);
  switch (cur.prompt.kind) {
    case "associate": {
      const name = $("bp-name").value.trim();
      if (!name) return $("bp-name").focus();
      return bpAnswer({ kind: "associate", name });
    }
    case "access":
      return bpAnswer({ kind: "access", allowed: checked, remember: $("bp-remember").checked });
    case "use_passkey":
      return bpAnswer(checked.length ? { kind: "choose", id: checked[0] } : null);
    default:
      return bpAnswer({ kind: "confirm", ok: true });
  }
});

function bpDeny() {
  const cur = bp.current;
  if (!cur) return;
  const kind = cur.prompt.kind;
  if (kind === "access") bpAnswer({ kind: "access", allowed: [], remember: $("bp-remember").checked });
  else if (kind === "update_login" || kind === "create_passkey") bpAnswer({ kind: "confirm", ok: false });
  else bpAnswer(null);
}
$("bp-deny").addEventListener("click", bpDeny);
$("bp-dialog").addEventListener("cancel", (ev) => {
  ev.preventDefault();
  bpDeny();
});

listen("browser_prompt", (ev) => {
  if (!PROMPTS_HERE) return;
  if (QUICK && $("view-main").hidden) refresh().catch(() => {});
  bp.queue.push(ev.payload);
  nextBrowserPrompt();
});
// Demande abandonnée côté application (délai dépassé, navigateur fermé).
listen("browser_prompt_closed", (ev) => {
  const id = ev.payload;
  bp.queue = bp.queue.filter((p) => p.id !== id);
  if (bp.current?.id === id) {
    bp.current = null;
    $("bp-name").value = "";
    if ($("bp-dialog").open) $("bp-dialog").close();
    nextBrowserPrompt();
    quickIdle();
  }
});
// Fenêtre rapide fermée par l'utilisateur : tout ce qu'elle montrait est refusé.
listen("quick_closed", () => {
  if (!QUICK) return;
  dropBrowserPrompts();
  atPending = null;
  if ($("at-dialog").open) $("at-dialog").close();
});
listen("browser_unlock_requested", () => {
  if (!PROMPTS_HERE) return;
  refresh().then(quickIdle, () => {});
  setStatus("Le navigateur demande le déverrouillage du coffre.");
});
listen("browser_error", (ev) => setStatus(`Intégration navigateur : ${ev.payload?.message ?? ""}`));


// ---------------------------------------------------------------- fiche en plein écran (double-clic)

/** Comme KeePassXC : le double-clic ouvre la fiche à la place de la liste. */
async function openDetail(id) {
  await selectEntry(id);
  if (!state.view) return;
  $("browse").classList.add("detail");
  $("pv-back").focus();
}

function closeDetail(focusRow = true) {
  if (!$("browse").classList.contains("detail")) return;
  $("browse").classList.remove("detail");
  if (focusRow) $("entries-body").querySelector('tr[aria-selected="true"]')?.focus();
}

$("pv-back").addEventListener("click", () => closeDetail());
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && $("browse").classList.contains("detail") && !document.querySelector("dialog[open]") && $("ctx-menu").hidden) {
    ev.preventDefault();
    closeDetail();
  } else if (ev.key === "Enter" && ev.target instanceof HTMLTableRowElement && ev.target.closest("#entries-body")) {
    ev.preventDefault();
    openDetail(ev.target.dataset.id);
  }
});

// ---------------------------------------------------------------- menu contextuel des entrées

function closeEntryMenu() {
  $("ctx-menu").hidden = true;
  $("ctx-menu").replaceChildren();
}

function menuItem(label, iconName, action, { shortcut = null, disabled = false, sub = null } = {}) {
  const li = el("li", { role: "menuitem", className: sub ? "has-sub" : "", ariaDisabled: String(disabled) });
  if (sub) li.addEventListener("click", (ev) => ev.stopPropagation());
  li.append(iconName ? icon(iconName) : el("span", { className: "ico-space" }), el("span", { className: "lbl" }, label));
  if (shortcut) li.append(el("span", { className: "kbd" }, comboLabel(shortcut)));
  if (sub) {
    li.append(el("span", { className: "arrow" }, "›"));
    const ul = el("ul", { className: "ctx-sub", role: "menu" }, ...sub);
    li.append(ul);
  } else if (!disabled) {
    li.addEventListener("click", (ev) => {
      ev.stopPropagation();
      closeEntryMenu();
      action();
    });
  }
  return li;
}

const sep = () => el("li", { className: "sep", role: "separator" });

async function openEntryMenu(id, x, y) {
  await selectEntry(id);
  const v = state.view;
  if (!v) return;
  const allTags = (await invoke("tags").catch(() => [])).map((t) => (Array.isArray(t) ? t[0] : t.name ?? t));
  const attrs = v.custom.map((c) => menuItem(c.key, null, () => copyField({ custom: c.key })));
  const tagItems = allTags.map((t) => {
    const on = v.tags.includes(t);
    return menuItem((on ? "✓ " : "") + t, "tag", async () => {
      const tags = on ? v.tags.filter((x) => x !== t) : [...v.tags, t];
      try {
        await invoke("set_entry_tags", { id, tags });
        await loadGroups();
        await loadEntries();
        await selectEntry(id, true);
      } catch (e) {
        setStatus(errorText(e));
      }
    });
  });
  const run = (fn) => async () => {
    try {
      await fn();
    } catch (e) {
      setStatus(errorText(e));
    }
  };
  const items = [
    menuItem("Copier le nom d'utilisateur", "user", () => copyField("username"), { shortcut: shortcuts.copy_user, disabled: !v.username }),
    menuItem("Copier le mot de passe", "key", () => copyField("password"), { shortcut: shortcuts.copy_pass }),
    menuItem("Copier l'URL", "link", () => copyField("url"), { shortcut: shortcuts.copy_url, disabled: !v.url }),
    menuItem("Copier l'attribut", "copy", null, { sub: attrs, disabled: !attrs.length }),
    menuItem("TOTP", "clock", null, {
      sub: [
        menuItem("Copier le code TOTP", "copy", () => copyField("totp"), { shortcut: shortcuts.copy_totp, disabled: !v.has_totp }),
        menuItem("Configurer TOTP…", "edit", () => openEditor(id)),
      ],
    }),
    menuItem("Étiquettes", "tag", null, { sub: tagItems, disabled: !tagItems.length }),
    sep(),
    menuItem("Ouvrir la fiche", "eye", () => openDetail(id)),
    menuItem("Modifier l'entrée…", "edit", () => openEditor(id), { shortcut: shortcuts.edit }),
    menuItem("Faire expirer l'entrée…", "clock", run(async () => {
      if (!(await ask(`Faire expirer « ${v.title} » maintenant ?`, { ok: "Faire expirer" }))) return;
      await invoke("expire_entry", { id });
      await loadEntries();
      await selectEntry(id, true);
    }), { disabled: v.in_recycle_bin }),
    menuItem("Cloner l'entrée…", "copy", run(async () => {
      const nid = await invoke("clone_entry", { id });
      await loadGroups();
      await loadEntries();
      await selectEntry(nid);
      setStatus("Entrée clonée.");
    }), { disabled: v.in_recycle_bin }),
    menuItem(v.in_recycle_bin ? "Supprimer définitivement…" : "Supprimer l'entrée…", "delete", deleteSelected, { shortcut: shortcuts.delete }),
    menuItem("Nouvelle entrée…", "add", () => $("btn-new").click(), { shortcut: shortcuts.new }),
    sep(),
    menuItem("Ouvrir l'URL", "link", run(() => invoke("open_entry_url", { id })), { disabled: !v.url }),
    menuItem("Saisie automatique", "keyboard", () => autotypeSelected(), { shortcut: shortcuts.autotype }),
    menuItem("Télécharger une favicône", "sync", run(async () => {
      await invoke("forget_favicon", { url: v.url });
      for (const k of [...faviconCache.keys()]) if (k === v.url) faviconCache.delete(k);
      renderEntries();
    }), { disabled: !v.url || !faviconsEnabled() }),
  ];
  const menu = $("ctx-menu");
  menu.replaceChildren(el("ul", { role: "none" }, ...items));
  menu.hidden = false;
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.max(4, Math.min(x, innerWidth - r.width - 4)) + "px";
  menu.style.top = Math.max(4, Math.min(y, innerHeight - r.height - 4)) + "px";
  menu.classList.toggle("subs-left", x + r.width + 220 > innerWidth);
}

document.addEventListener("click", (ev) => {
  if (!$("ctx-menu").hidden && !$("ctx-menu").contains(ev.target)) closeEntryMenu();
});
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && !$("ctx-menu").hidden) {
    ev.stopPropagation();
    closeEntryMenu();
  }
}, true);
window.addEventListener("blur", closeEntryMenu);
$("entries-body").closest(".table-wrap").addEventListener("scroll", closeEntryMenu);


// ---------------------------------------------------------------- empreinte digitale

listen("biometric-progress", (ev) => {
  const msg = String(ev.payload ?? "");
  $("unlock-bio-msg").textContent = msg;
  $("bio-msg").textContent = msg;
});

async function showBioUnlock() {
  $("unlock-bio").hidden = true;
  $("unlock-bio-msg").textContent = "";
  try {
    const st = await invoke("biometric_status");
    if (st.label) $("unlock-bio-label").textContent = `Déverrouiller avec ${st.label}`;
    $("unlock-bio").hidden = !(st.available && st.enabled);
  } catch (_) {}
}

$("unlock-bio").addEventListener("click", async () => {
  $("unlock-error").textContent = "";
  try {
    await busy($("unlock-bio"), () => invoke("biometric_unlock"));
    $("unlock-bio-msg").textContent = "";
    $("unlock-form").reset();
    await refresh();
    emit("unlocked").catch(() => {});
    syncNow(false).finally(reportSshUnlock);
  } catch (e) {
    $("unlock-bio-msg").textContent = "";
    $("unlock-error").textContent = errorText(e);
    showBioUnlock();
  }
});

async function renderAutofill() {
  let st;
  try {
    st = await invoke("autofill_status");
  } catch (_) {
    st = { supported: false };
  }
  $("autofill-section").hidden = !st.supported;
  $("autofill-state").textContent = st.enabled
    ? "Activé : KittyPass est le service de remplissage d'Android."
    : "Désactivé : choisissez KittyPass comme service de saisie automatique.";
}

$("autofill-open").addEventListener("click", async () => {
  try {
    await invoke("autofill_settings");
  } catch (e) {
    $("autofill-state").textContent = errorText(e);
  }
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && !$("autofill-section").hidden) renderAutofill();
});

async function renderBiometric() {
  $("bio-error").textContent = "";
  $("bio-msg").textContent = "";
  $("bio-form").reset();
  let st;
  try {
    st = await invoke("biometric_status");
  } catch (e) {
    st = { available: false, enabled: false, reason: errorText(e) };
  }
  const label = st.label ?? "l'empreinte";
  if (st.title) $("bio-title").textContent = st.title;
  if (st.hint) $("bio-hint").textContent = st.hint;
  $("bio-on").textContent = `Activer ${label}`;
  $("bio-off").textContent = `Désactiver ${label}`;
  $("bio-state").textContent = st.enabled
    ? `Activé : le bouton « Déverrouiller avec ${label} » apparaît sur l'écran de verrouillage.`
    : st.available
      ? "Désactivé. Saisissez le mot de passe maître puis confirmez votre identité pour l'activer."
      : `Indisponible : ${st.reason ?? "aucun lecteur"}.`;
  $("bio-form").hidden = st.enabled || !st.available;
  $("bio-off").hidden = !st.enabled;
}

$("bio-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("bio-error").textContent = "";
  try {
    await busy(f.querySelector("button[type=submit]"), () => invoke("biometric_enable", { password: f.password.value }));
    f.reset();
    $("bio-msg").textContent = "Activé.";
    renderBiometric();
  } catch (e) {
    f.password.value = "";
    $("bio-msg").textContent = "";
    $("bio-error").textContent = e.code === "invalid_password" ? "Mot de passe incorrect." : errorText(e);
  }
});

$("bio-off").addEventListener("click", async () => {
  await invoke("biometric_disable");
  renderBiometric();
});


// ---------------------------------------------------------------- téléphone

const phone = window.matchMedia("(max-width: 640px)");
const coarse = window.matchMedia("(pointer: coarse)");
function showGroups(on) {
  document.body.classList.toggle("show-groups", on);
  $("side-scrim").hidden = !on;
}
$("btn-groups").addEventListener("click", () => showGroups(!document.body.classList.contains("show-groups")));
$("side-scrim").addEventListener("click", () => showGroups(false));
// Choisir un groupe ou une étiquette referme le panneau.
for (const id of ["tree", "taglist"]) {
  $(id).addEventListener("click", (ev) => {
    if (phone.matches && ev.target.closest("li")) setTimeout(() => showGroups(false), 0);
  });
}
// Écran tactile : un appui ouvre la fiche (pas de double-clic au doigt).
$("entries-body").addEventListener("click", (ev) => {
  const tr = ev.target.closest("tr");
  if (tr && (coarse.matches || phone.matches)) openDetail(tr.dataset.id);
});

// Nom d'appareil proposé : « Téléphone » sous Android.
if (/Android/i.test(navigator.userAgent)) {
  document.body.classList.add("android");
  const dev = document.querySelector('input[name="device"]');
  if (dev && dev.value === "Ordinateur") dev.value = "Téléphone";
}

// macOS et iOS : effet « Liquid Glass » (style.css, body.apple).
if (/Macintosh|iPhone|iPad|iPod/.test(navigator.userAgent)) document.body.classList.add("apple");

// Barre de navigation du bas (téléphone) : relaie vers les boutons de la barre d'outils.
for (const b of document.querySelectorAll(".bottom-nav [data-nav]")) {
  b.addEventListener("click", () => $(b.dataset.nav).click());
}
$("pv-edit").addEventListener("click", () => $("btn-edit").click());
$("pv-delete").addEventListener("click", () => $("btn-delete").click());

// Hauteur de la barre d'outils (bureau) : le contenu défile dessous.
new ResizeObserver(([e]) => {
  document.documentElement.style.setProperty("--tb-h", `${Math.round(e.borderBoxSize?.[0]?.blockSize ?? e.target.offsetHeight)}px`);
}).observe(document.querySelector(".toolbar"));
