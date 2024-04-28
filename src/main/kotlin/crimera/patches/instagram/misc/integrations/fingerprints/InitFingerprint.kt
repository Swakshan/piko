package crimera.patches.instagram.misc.integrations.fingerprints

import app.revanced.patches.shared.misc.integrations.BaseIntegrationsPatch.IntegrationsFingerprint

internal object InitFingerprint : IntegrationsFingerprint(
    customFingerprint = { methodDef, _ ->
       methodDef.name == "onCreate" &&
        methodDef.definingClass == "Lcom/instagram/app/InstagramAppShell;"
    }
)