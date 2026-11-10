"""Pilote WebDriver minimal pour la vraie appli (version de développement).

Prérequis : paquet webkit2gtk-driver, `cargo install tauri-driver`, puis
  XDG_DATA_HOME=<profil jetable> KITTYPASS_TEST_DIALOG=<fichier réponse> tauri-driver --port 4444
Les boîtes « Ouvrir / Enregistrer » ne sont pas pilotables : `pick` écrit la
réponse dans le fichier désigné par KITTYPASS_TEST_DIALOG (défaut :
ui-test/.wd-pick), lu par la version de développement seulement.

Utilisation : python3 -I wd.py start | js '<code async>' | shot <fichier.png> | pick <chemin|''> | stop
Le code JS dispose de `$` et `sleep` ; sa valeur de retour est affichée.
"""
import base64, json, os, sys, urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:4444"
HERE = Path(__file__).parent
SID = HERE / ".wd-session"
PICK = Path(os.environ.get("KITTYPASS_TEST_DIALOG", HERE / ".wd-pick"))
APP = str(HERE.parents[1] / "target" / "debug" / "kittypass-desktop")


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read() or b"{}").get("value")
    except urllib.error.HTTPError as e:
        raise SystemExit(f"HTTP {e.code}: {e.read().decode()[:800]}")


PRELUDE = """
const done = arguments[arguments.length - 1];
const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
%s
})().then((v) => done(v === undefined ? null : v), (e) => done("EXCEPTION: " + (e && (e.message || JSON.stringify(e)))));
"""


def main():
    cmd = sys.argv[1]
    if cmd == "start":
        v = call("POST", "/session", {"capabilities": {"alwaysMatch": {"tauri:options": {"application": APP}}}})
        SID.write_text(v["sessionId"])
        call("POST", f"/session/{v['sessionId']}/timeouts", {"script": 120000})
        print("session", v["sessionId"])
    elif cmd == "pick":
        PICK.write_text(sys.argv[2] if len(sys.argv) > 2 else "")
    else:
        sid = SID.read_text()
        if cmd == "js":
            r = call("POST", f"/session/{sid}/execute/async", {"script": PRELUDE % sys.argv[2], "args": []})
            print(json.dumps(r, ensure_ascii=False, indent=1) if not isinstance(r, str) else r)
        elif cmd == "shot":
            png = call("GET", f"/session/{sid}/screenshot")
            Path(sys.argv[2]).write_bytes(base64.b64decode(png))
            print("ok", sys.argv[2])
        elif cmd == "stop":
            call("DELETE", f"/session/{sid}")
            print("stopped")


main()
