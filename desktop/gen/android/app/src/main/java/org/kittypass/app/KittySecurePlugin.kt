package org.kittypass.app

import android.app.Activity
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Secrets de KittyPass chiffrés par une clé AES du Keystore Android (jamais
 * extractible, protégée par le matériel quand l'appareil le permet).
 *
 * - `bio = false` : jeton de session ; la clé s'utilise sans authentification.
 * - `bio = true` : mot de passe maître pour le déverrouillage biométrique ; la
 *   clé exige une biométrie forte à chaque utilisation et devient invalide si
 *   une empreinte ou un visage est ajouté.
 *
 * Seul le texte chiffré (IV + données) est gardé dans les préférences de l'appli.
 */
@InvokeArg
class SealArgs {
  lateinit var key: String
  lateinit var value: String
  var bio: Boolean = false
  var title: String = "KittyPass"
}

@InvokeArg
class KeyArgs {
  lateinit var key: String
  var bio: Boolean = false
  var title: String = "KittyPass"
}

@InvokeArg
class RegisterArgs {
  lateinit var channel: Channel
}

@InvokeArg
class AutofillItemArg {
  var id: String = ""
  var title: String = ""
  var username: String = ""
  var password: String = ""
}

@InvokeArg
class ReplyArgs {
  var id: Long = 0
  var locked: Boolean = false
  var items: List<AutofillItemArg> = emptyList()
}

@TauriPlugin
class KittySecurePlugin(private val activity: Activity) : Plugin(activity) {
  companion object {
    /** Canal vers Rust pour les demandes du service de remplissage. */
    @Volatile var autofillChannel: Channel? = null
  }

  @Command
  fun registerAutofill(invoke: Invoke) {
    autofillChannel = invoke.parseArgs(RegisterArgs::class.java).channel
    invoke.resolve()
  }

  @Command
  fun autofillReply(invoke: Invoke) {
    val a = invoke.parseArgs(ReplyArgs::class.java)
    KittyAutofillService.reply(a.id, a.locked, a.items.map { KittyAutofillService.Item(it.id, it.title, it.username, it.password) })
    invoke.resolve()
  }

  @Command
  fun autofillStatus(invoke: Invoke) {
    val r = JSObject()
    if (android.os.Build.VERSION.SDK_INT >= 26) {
      val m = activity.getSystemService(android.view.autofill.AutofillManager::class.java)
      r.put("supported", m != null && m.isAutofillSupported)
      r.put("enabled", m != null && m.hasEnabledAutofillServices())
    } else {
      r.put("supported", false)
      r.put("enabled", false)
    }
    invoke.resolve(r)
  }

  @Command
  fun openAutofillSettings(invoke: Invoke) {
    if (android.os.Build.VERSION.SDK_INT < 26) return invoke.reject("Android 8 ou plus requis")
    val i = android.content.Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
    i.data = android.net.Uri.parse("package:" + activity.packageName)
    try {
      activity.startActivity(i)
    } catch (e: Exception) {
      // Certains fabricants (Samsung…) n'ont pas cet écran : réglages généraux.
      activity.startActivity(android.content.Intent(android.provider.Settings.ACTION_SETTINGS))
    }
    invoke.resolve()
  }

  private val prefs by lazy { activity.getSharedPreferences("kittypass-secure", Context.MODE_PRIVATE) }

  private fun alias(bio: Boolean) = if (bio) "kittypass-bio" else "kittypass-plain"

  private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

  private fun secretKey(bio: Boolean, create: Boolean): SecretKey? {
    val ks = keyStore()
    (ks.getKey(alias(bio), null) as? SecretKey)?.let { return it }
    if (!create) return null
    val spec = KeyGenParameterSpec.Builder(alias(bio), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
    if (bio) {
      spec.setUserAuthenticationRequired(true)
      spec.setInvalidatedByBiometricEnrollment(true)
      if (android.os.Build.VERSION.SDK_INT >= 30) {
        spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
      }
    }
    val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    gen.init(spec.build())
    return gen.generateKey()
  }

  private fun prefKey(key: String, bio: Boolean) = (if (bio) "bio:" else "plain:") + key

  private fun dropKey(bio: Boolean) {
    try { keyStore().deleteEntry(alias(bio)) } catch (_: Exception) {}
  }

  private fun biometricStatus(): Pair<Boolean, String?> =
    when (BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG)) {
      BiometricManager.BIOMETRIC_SUCCESS -> Pair(true, null)
      BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Pair(false, "aucune empreinte enregistrée dans les paramètres du téléphone")
      BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> Pair(false, "pas de capteur biométrique")
      BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> Pair(false, "capteur biométrique indisponible pour le moment")
      BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> Pair(false, "mise à jour de sécurité requise")
      else -> Pair(false, "biométrie indisponible")
    }

  @Command
  fun status(invoke: Invoke) {
    val (ok, reason) = biometricStatus()
    val r = JSObject()
    r.put("available", ok)
    if (reason != null) r.put("reason", reason)
    r.put("enabled", prefs.contains(prefKey("biometric-unlock", true)))
    invoke.resolve(r)
  }

  /** Demande la biométrie pour débloquer `cipher`, puis appelle `done`. */
  private fun withBiometric(title: String, cipher: Cipher, invoke: Invoke, done: (Cipher) -> Unit) {
    val act = activity as? FragmentActivity ?: return invoke.reject("activité incompatible")
    act.runOnUiThread {
      val prompt = BiometricPrompt(act, ContextCompat.getMainExecutor(act), object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          val c = result.cryptoObject?.cipher ?: return invoke.reject("biométrie sans clé")
          try { done(c) } catch (e: Exception) { invoke.reject(e.message ?: e.toString()) }
        }
        override fun onAuthenticationError(code: Int, msg: CharSequence) {
          val cancelled = code == BiometricPrompt.ERROR_USER_CANCELED || code == BiometricPrompt.ERROR_NEGATIVE_BUTTON || code == BiometricPrompt.ERROR_CANCELED
          invoke.reject(if (cancelled) "annulé" else msg.toString(), if (cancelled) "cancelled" else "biometric")
        }
      })
      val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setNegativeButtonText("Annuler")
        .setAllowedAuthenticators(BIOMETRIC_STRONG)
        .build()
      prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }
  }

  @Command
  fun seal(invoke: Invoke) {
    val a = invoke.parseArgs(SealArgs::class.java)
    try {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val init = {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey(a.bio, true))
      }
      try { init() } catch (e: KeyPermanentlyInvalidatedException) { dropKey(a.bio); init() }
      val finish = { c: Cipher ->
        val ct = c.doFinal(a.value.toByteArray(Charsets.UTF_8))
        val blob = Base64.encodeToString(c.iv + ct, Base64.NO_WRAP)
        prefs.edit().putString(prefKey(a.key, a.bio), blob).apply()
        invoke.resolve()
      }
      if (a.bio) withBiometric(a.title, cipher, invoke, finish) else finish(cipher)
    } catch (e: Exception) {
      invoke.reject(e.message ?: e.toString())
    }
  }

  @Command
  fun open(invoke: Invoke) {
    val a = invoke.parseArgs(KeyArgs::class.java)
    val blob = prefs.getString(prefKey(a.key, a.bio), null)
    val key = secretKey(a.bio, false)
    if (blob == null || key == null) {
      return invoke.resolve(JSObject())
    }
    try {
      val raw = Base64.decode(blob, Base64.NO_WRAP)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      try {
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, raw, 0, 12))
      } catch (e: KeyPermanentlyInvalidatedException) {
        // Nouvelle empreinte enregistrée : on oublie, il faudra réactiver.
        dropKey(a.bio)
        prefs.edit().remove(prefKey(a.key, a.bio)).apply()
        return invoke.reject("biométrie modifiée sur le téléphone : réactivez-la dans KittyPass", "invalidated")
      }
      val finish = { c: Cipher ->
        val pt = c.doFinal(raw, 12, raw.size - 12)
        invoke.resolve(JSObject().apply { put("value", String(pt, Charsets.UTF_8)) })
      }
      if (a.bio) withBiometric(a.title, cipher, invoke, finish) else finish(cipher)
    } catch (e: Exception) {
      invoke.reject(e.message ?: e.toString())
    }
  }

  @Command
  fun remove(invoke: Invoke) {
    val a = invoke.parseArgs(KeyArgs::class.java)
    prefs.edit().remove(prefKey(a.key, a.bio)).apply()
    if (a.bio) dropKey(true)
    invoke.resolve()
  }
}
