package org.kittypass.app

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.util.Log
import androidx.annotation.RequiresApi
import app.tauri.plugin.JSObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Service de remplissage automatique d'Android.
 *
 * Le coffre n'existe que dans KittyPass ouvert et déverrouillé (côté Rust) :
 * le service y demande les identifiants qui correspondent au site (domaine
 * donné par le navigateur) ou à l'appli (`androidapp://paquet`). Rust répond
 * directement au service, sans passer par la page web de l'appli.
 *
 * KittyPass fermé ou verrouillé : une seule ligne « Ouvrir KittyPass », qui
 * lance l'appli ; une fois déverrouillée, un nouvel appui sur le champ
 * propose les identifiants.
 */
@RequiresApi(26)
class KittyAutofillService : AutofillService() {

  class Fields(
    val username: AutofillId?,
    val password: AutofillId?,
    val webDomain: String?,
    val packageName: String,
  )

  /** Identifiant proposé (le mot de passe ne quitte le processus que vers le champ rempli). */
  class Item(val id: String, val title: String, val username: String, val password: String)

  companion object {
    private val nextId = AtomicLong(1)
    private val pending = ConcurrentHashMap<Long, (Boolean, List<Item>) -> Unit>()
    private val main = Handler(Looper.getMainLooper())
    private const val TIMEOUT_MS = 8000L

    /**
     * Envoie une demande à KittyPass (Rust) ; `done(locked, items)` est appelé
     * sur le fil principal, avec `locked = true` si pas de réponse à temps.
     * Renvoie false si l'appli ne tourne pas.
     */
    fun request(msg: JSObject, done: (Boolean, List<Item>) -> Unit): Boolean {
      val channel = KittySecurePlugin.autofillChannel ?: return false
      val id = nextId.getAndIncrement()
      pending[id] = done
      main.postDelayed({
        pending.remove(id)?.let {
          Log.w("KittyAutofill", "pas de réponse de KittyPass pour $id")
          it(true, emptyList())
        }
      }, TIMEOUT_MS)
      msg.put("id", id)
      return try {
        channel.send(msg)
        true
      } catch (_: Exception) {
        KittySecurePlugin.autofillChannel = null
        pending.remove(id)
        false
      }
    }

    /** Réponse de Rust (appelée par le plugin). */
    fun reply(id: Long, locked: Boolean, items: List<Item>) {
      val p = pending.remove(id)
      Log.i("KittyAutofill", "réponse $id : locked=$locked, ${items.size} entrée(s), attendue=${p != null}")
      if (p == null) return
      main.post { try { p(locked, items) } catch (_: Exception) {} }
    }

    fun line(ctx: android.content.Context, text: String): RemoteViews {
      val v = RemoteViews(ctx.packageName, R.layout.kp_autofill_item)
      v.setTextViewText(R.id.kp_text, text)
      return v
    }

    fun dataset(ctx: android.content.Context, f: Fields, it: Item): Dataset {
      val label = if (it.username.isNotEmpty()) "${it.title} (${it.username})" else it.title
      val d = Dataset.Builder()
      f.username?.let { u -> d.setValue(u, AutofillValue.forText(it.username), line(ctx, label)) }
      f.password?.let { p -> d.setValue(p, AutofillValue.forText(it.password), line(ctx, label)) }
      return d.build()
    }
  }

  override fun onFillRequest(request: FillRequest, cancel: CancellationSignal, callback: FillCallback) {
    val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess(null)
    val pkg = structure.activityComponent.packageName
    if (pkg == packageName) return callback.onSuccess(null)
    val fields = parse(structure, pkg) ?: return callback.onSuccess(null)
    Log.i("KittyAutofill", "demande : domaine=${fields.webDomain} paquet=${fields.packageName}")
    val msg = JSObject()
    if (fields.webDomain != null) msg.put("webDomain", fields.webDomain)
    msg.put("package", fields.packageName)
    var answered = false
    cancel.setOnCancelListener { answered = true }
    val sent = KittyAutofillService.request(msg) done@{ locked, items ->
      if (answered) return@done
      answered = true
      try {
        callback.onSuccess(if (locked) openAppResponse(fields, "KittyPass est verrouillé : appuyer pour l'ouvrir") else itemsResponse(fields, items))
      } catch (_: Exception) {}
    }
    if (!sent) callback.onSuccess(openAppResponse(fields, "Ouvrir KittyPass"))
  }

  override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
    callback.onSuccess()
  }

  private fun ids(f: Fields): Array<AutofillId> = listOfNotNull(f.username, f.password).toTypedArray()

  private fun line(text: String): RemoteViews = line(this, text)

  fun openAppResponse(f: Fields, label: String): FillResponse {
    val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    return FillResponse.Builder().setAuthentication(ids(f), pi.intentSender, line(label)).build()
  }

  fun itemsResponse(f: Fields, items: List<Item>): FillResponse {
    val r = FillResponse.Builder()
    for (it in items) r.addDataset(dataset(this, f, it))
    r.addDataset(searchDataset(f, items.isEmpty()))
    return r.build()
  }

  /** Dernière ligne : choisir soi-même une entrée (et retenir le site). */
  private fun searchDataset(f: Fields, none: Boolean): Dataset {
    val intent = Intent(this, AutofillPickActivity::class.java)
      .putExtra(AutofillPickActivity.EXTRA_USER, f.username)
      .putExtra(AutofillPickActivity.EXTRA_PASS, f.password)
      .putExtra(AutofillPickActivity.EXTRA_DOMAIN, f.webDomain)
      .putExtra(AutofillPickActivity.EXTRA_PACKAGE, f.packageName)
    val pi = PendingIntent.getActivity(this, nextId.getAndIncrement().toInt(), intent,
      (if (android.os.Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0) or PendingIntent.FLAG_CANCEL_CURRENT)
    val text = if (none) "Aucune entrée pour ce site — rechercher dans KittyPass…" else "Rechercher dans KittyPass…"
    val d = Dataset.Builder(line(this, text))
    for (id in ids(f)) d.setValue(id, null)
    d.setAuthentication(pi.intentSender)
    return d.build()
  }

  // ---------- analyse de l'écran ----------

  private fun parse(s: AssistStructure, pkg: String): Fields? {
    var user: AutofillId? = null
    var pass: AutofillId? = null
    var lastText: AutofillId? = null
    var userBeforePass: AutofillId? = null
    var domain: String? = null

    fun visit(n: AssistStructure.ViewNode) {
      if (domain == null && !n.webDomain.isNullOrEmpty()) domain = n.webDomain
      val id = n.autofillId
      if (id != null && n.autofillType == View.AUTOFILL_TYPE_TEXT) {
        when (kind(n)) {
          Kind.PASSWORD -> if (pass == null) { pass = id; userBeforePass = lastText }
          Kind.USERNAME -> if (user == null) user = id
          Kind.TEXT -> lastText = id
          Kind.OTHER -> {}
        }
      }
      for (i in 0 until n.childCount) visit(n.getChildAt(i))
    }
    for (i in 0 until s.windowNodeCount) visit(s.getWindowNodeAt(i).rootViewNode)

    if (user == null) user = userBeforePass
    if (user == null && pass == null) return null
    return Fields(user, pass, domain, pkg)
  }

  private enum class Kind { USERNAME, PASSWORD, TEXT, OTHER }

  private fun kind(n: AssistStructure.ViewNode): Kind {
    val hints = n.autofillHints?.map { it.lowercase() } ?: emptyList()
    if (hints.any { it.contains("password") }) return Kind.PASSWORD
    if (hints.any { it.contains("username") || it.contains("email") }) return Kind.USERNAME

    val html = n.htmlInfo
    if (html != null) {
      if (!html.tag.equals("input", true)) return Kind.OTHER
      val attrs = html.attributes?.associate { it.first.lowercase() to (it.second ?: "").lowercase() } ?: emptyMap()
      val type = attrs["type"] ?: "text"
      if (type == "password") return Kind.PASSWORD
      if (type == "email") return Kind.USERNAME
      if (type == "hidden" || type == "submit" || type == "button" || type == "checkbox" || type == "radio") return Kind.OTHER
      val ac = attrs["autocomplete"] ?: ""
      if (ac.contains("username") || ac.contains("email")) return Kind.USERNAME
      if (ac.contains("password")) return Kind.PASSWORD
      val name = (attrs["name"] ?: "") + " " + (attrs["id"] ?: "")
      if (looksLikeUser(name)) return Kind.USERNAME
      return if (type == "text" || type == "tel") Kind.TEXT else Kind.OTHER
    }

    val t = n.inputType
    if (t and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_TEXT) {
      val v = t and InputType.TYPE_MASK_VARIATION
      if (v == InputType.TYPE_TEXT_VARIATION_PASSWORD || v == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD || v == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD) return Kind.PASSWORD
      if (v == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || v == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS) return Kind.USERNAME
      val idName = (n.idEntry ?: "") + " " + (n.hint ?: "")
      if (looksLikeUser(idName)) return Kind.USERNAME
      return Kind.TEXT
    }
    if (t and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_NUMBER &&
      t and InputType.TYPE_MASK_VARIATION == InputType.TYPE_NUMBER_VARIATION_PASSWORD) return Kind.PASSWORD
    return Kind.OTHER
  }

  private fun looksLikeUser(s: String): Boolean {
    val l = s.lowercase()
    return listOf("user", "login", "email", "e-mail", "mail", "identifiant", "utilisateur", "account").any { l.contains(it) }
  }
}
