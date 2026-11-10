package org.kittypass.app

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import androidx.annotation.RequiresApi
import app.tauri.plugin.JSObject

/**
 * « Rechercher dans KittyPass… » : l'utilisateur choisit l'entrée à remplir
 * quand aucune ne correspond au site (ou pas la bonne). Option : associer le
 * site à l'entrée, pour qu'elle soit proposée directement la prochaine fois.
 *
 * Fenêtre native (pas la page web de l'appli) : elle s'ouvre par-dessus
 * l'appli à remplir, et les mots de passe restent dans le processus.
 */
@RequiresApi(26)
class AutofillPickActivity : Activity() {
  companion object {
    const val EXTRA_USER = "kp.user"
    const val EXTRA_PASS = "kp.pass"
    const val EXTRA_DOMAIN = "kp.domain"
    const val EXTRA_PACKAGE = "kp.package"
  }

  private lateinit var fields: KittyAutofillService.Fields
  private val items = mutableListOf<KittyAutofillService.Item>()
  private lateinit var status: TextView
  private lateinit var remember: CheckBox
  private lateinit var adapter: BaseAdapter
  private var generation = 0

  private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

  @Suppress("DEPRECATION")
  private fun idExtra(name: String): AutofillId? =
    if (android.os.Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(name, AutofillId::class.java) else intent.getParcelableExtra(name)

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    fields = KittyAutofillService.Fields(
      idExtra(EXTRA_USER), idExtra(EXTRA_PASS),
      intent.getStringExtra(EXTRA_DOMAIN), intent.getStringExtra(EXTRA_PACKAGE) ?: "",
    )
    val dark = (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
      android.content.res.Configuration.UI_MODE_NIGHT_YES
    val fg = if (dark) Color.parseColor("#E8EAED") else Color.parseColor("#202124")
    val muted = if (dark) Color.parseColor("#9AA0A6") else Color.parseColor("#5F6368")

    val root = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(dp(20), dp(16), dp(20), dp(12))
    }
    root.addView(TextView(this).apply {
      text = "Choisir une entrée"
      textSize = 20f
      setTextColor(fg)
    })
    val site = fields.webDomain ?: fields.packageName
    root.addView(TextView(this).apply {
      text = "Pour : $site"
      setTextColor(muted)
      setPadding(0, dp(4), 0, dp(8))
    })
    val search = EditText(this).apply {
      hint = "Rechercher (titre, identifiant, URL…)"
      setSingleLine()
      setTextColor(fg)
      setHintTextColor(muted)
    }
    root.addView(search)
    remember = CheckBox(this).apply {
      text = if (fields.webDomain != null) "Associer ${fields.webDomain} à l'entrée choisie" else ""
      setTextColor(fg)
      isChecked = fields.webDomain != null
      visibility = if (fields.webDomain != null) View.VISIBLE else View.GONE
    }
    root.addView(remember)
    status = TextView(this).apply { setTextColor(muted); setPadding(0, dp(8), 0, dp(4)) }
    root.addView(status)

    adapter = object : BaseAdapter() {
      override fun getCount() = items.size
      override fun getItem(p: Int) = items[p]
      override fun getItemId(p: Int) = p.toLong()
      override fun getView(p: Int, convert: View?, parent: ViewGroup): View {
        val it = items[p]
        val box = (convert as? LinearLayout) ?: LinearLayout(this@AutofillPickActivity).apply {
          orientation = LinearLayout.VERTICAL
          setPadding(0, dp(10), 0, dp(10))
          addView(TextView(context).apply { textSize = 16f; setTextColor(fg) })
          addView(TextView(context).apply { setTextColor(muted) })
        }
        (box.getChildAt(0) as TextView).text = it.title.ifEmpty { "(sans titre)" }
        (box.getChildAt(1) as TextView).text = it.username
        return box
      }
    }
    val list = ListView(this).apply {
      this.adapter = this@AutofillPickActivity.adapter
      setOnItemClickListener { _, _, p, _ -> choose(items[p]) }
    }
    root.addView(list, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
    root.addView(Button(this).apply {
      text = "Annuler"
      setOnClickListener { setResult(RESULT_CANCELED); finish() }
    }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { gravity = Gravity.END })
    setContentView(root)
    root.setBackgroundColor(if (dark) Color.parseColor("#202124") else Color.WHITE)

    // Recherche de départ : le nom du site sans « www. », « auth. »… ni l'extension.
    val start = fields.webDomain?.split('.')?.let { if (it.size >= 2) it[it.size - 2] else null } ?: ""
    search.setText(start)
    search.setSelection(start.length)
    search.addTextChangedListener(object : TextWatcher {
      override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
      override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
      override fun afterTextChanged(s: Editable?) { load(s?.toString() ?: "") }
    })
    load(start)
  }

  private fun load(q: String) {
    val gen = ++generation
    status.text = "Recherche…"
    val msg = JSObject()
    msg.put("query", q)
    val sent = KittyAutofillService.request(msg) done@{ locked, found ->
      if (gen != generation) return@done
      items.clear()
      if (locked) {
        status.text = "KittyPass est verrouillé : ouvrez-le, déverrouillez-le, puis revenez ici."
      } else {
        items.addAll(found)
        status.text = if (found.isEmpty()) "Aucune entrée trouvée." else ""
      }
      adapter.notifyDataSetChanged()
    }
    if (!sent) {
      status.text = "KittyPass n'est pas ouvert : ouvrez-le et déverrouillez-le, puis réessayez."
      status.setOnClickListener { startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
    }
  }

  private fun choose(it: KittyAutofillService.Item) {
    val domain = fields.webDomain
    if (remember.isChecked && domain != null) {
      val msg = JSObject()
      msg.put("remember", it.id)
      msg.put("webDomain", domain)
      KittyAutofillService.request(msg) { _, _ -> }
    }
    val data = Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, KittyAutofillService.dataset(this, fields, it))
    setResult(RESULT_OK, data)
    finish()
  }
}
