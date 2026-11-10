// Applique le thème et la couleur d'accent choisis avant l'affichage (évite
// un flash de l'ancienne apparence). Préférences d'affichage seulement : rien
// du coffre n'est stocké ici.
(function () {
  const THEMES = ["light", "pastel", "dark", "system"];
  const ACCENTS = ["green", "emerald", "teal", "blue", "indigo", "violet", "pink", "orange", "amber", "graphite"];
  let theme = "light";
  let accent = "green";
  try {
    let saved = localStorage.getItem("kittypass.theme");
    if (saved === "mint") saved = "pastel"; // ancien nom
    if (THEMES.includes(saved)) theme = saved;
    const a = localStorage.getItem("kittypass.accent");
    if (ACCENTS.includes(a)) accent = a;
  } catch (_) {}
  document.documentElement.dataset.theme = theme;
  document.documentElement.dataset.accent = accent;
})();
