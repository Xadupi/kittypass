#!/usr/bin/env python3
"""Régénère ui-test/harness.html depuis ui/index.html, avec la fausse API (mock.js)."""
from pathlib import Path

here = Path(__file__).resolve().parent
src = (here.parent / "ui" / "index.html").read_text(encoding="utf-8")
out = src.replace("<title>KittyPass</title>", "<title>KittyPass — banc de test</title>", 1)
out = out.replace('href="style.css"', 'href="../ui/style.css"', 1)
out = out.replace('<script src="theme.js"></script>', '<script src="../ui/theme.js"></script>', 1)
out = out.replace('<script src="app.js"></script>', '<script src="mock.js"></script>\n  <script src="../ui/app.js"></script>', 1)
out = out.replace('src="logo.svg"', 'src="../ui/logo.svg"')
assert out.count("mock.js") == 1 and out.count("../ui/style.css") == 1 and out.count("../ui/theme.js") == 1, "index.html a changé de structure"
banner = "<!-- Généré depuis ui/index.html (mock.js injecté) : ne pas modifier à la main. -->\n"
(here / "harness.html").write_text(banner + out, encoding="utf-8")
