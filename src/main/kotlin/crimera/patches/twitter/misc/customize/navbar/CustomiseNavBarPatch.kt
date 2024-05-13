package crimera.patches.twitter.misc.customize.navbar

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.extensions.InstructionExtensions.addInstructions
import app.revanced.patcher.extensions.InstructionExtensions.addInstructionsWithLabels
import app.revanced.patcher.extensions.InstructionExtensions.getInstruction
import app.revanced.patcher.extensions.InstructionExtensions.getInstructions
import app.revanced.patcher.extensions.InstructionExtensions.removeInstruction
import app.revanced.patcher.fingerprint.MethodFingerprint
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.PatchException
import app.revanced.patcher.patch.annotation.CompatiblePackage
import app.revanced.patcher.patch.annotation.Patch
import app.revanced.patcher.util.smali.ExternalLabel
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import crimera.patches.twitter.misc.settings.SettingsPatch
import crimera.patches.twitter.misc.settings.fingerprints.SettingsStatusLoadFingerprint

object CustomiseNavBarFingerprint:MethodFingerprint(
    returnType = "V",
    strings = listOf(
        "tabCustomizationPreferences",
        "communitiesUtils",
        "exploreImmersiveFeatures",
        "subscriptionsFeatures",
    )
)

@Patch(
    name = "Customize Navigation Bar items",
    dependencies = [SettingsPatch::class],
    compatiblePackages = [CompatiblePackage("com.twitter.android")],
    use = false,
    requiresIntegrations = true
)
@Suppress("unused")
object CustomiseNavBarPatch:BytecodePatch(
    setOf(CustomiseNavBarFingerprint,SettingsStatusLoadFingerprint)
){
    override fun execute(context: BytecodeContext) {
        val results = CustomiseNavBarFingerprint.result
            ?:throw PatchException("CustomiseNavBarFingerprint not found")

        val method = results.mutableClass.methods.last { it.returnType == "Ljava/util/List;" }
        val instructions = method.getInstructions()

        val returnObj_loc = instructions.last { it.opcode == Opcode.RETURN_OBJECT }.location.index
        val r0 = method.getInstruction<OneRegisterInstruction>(returnObj_loc).registerA

        val METHOD = """
            invoke-static {v$r0}, ${SettingsPatch.CUSTOMISE_DESCRIPTOR}/NavBar;->navBar(Ljava/util/List;)Ljava/util/List;
            move-result-object v$r0
        """.trimIndent()

        method.addInstructions(returnObj_loc,METHOD)

        SettingsStatusLoadFingerprint.enableSettings("navBarCustomisation")
        //end
    }
}