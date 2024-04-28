package crimera.patches.instagram.ads

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.extensions.InstructionExtensions.addInstruction
import app.revanced.patcher.extensions.InstructionExtensions.addInstructions
import app.revanced.patcher.extensions.InstructionExtensions.getInstruction
import app.revanced.patcher.extensions.InstructionExtensions.getInstructions
import app.revanced.patcher.fingerprint.MethodFingerprint
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.PatchException
import com.android.tools.smali.dexlib2.Opcode
import app.revanced.patcher.patch.annotation.CompatiblePackage
import app.revanced.patcher.patch.annotation.Patch
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction


object TigonEnabledFlagFingerprint : MethodFingerprint(
    returnType = "Ljava/lang/Object;",
    strings = listOf(
        "liger_load_error",
        "power",
    ),
)

object HTTPStreamingFlagFingerprint : MethodFingerprint(
    returnType = "Z",
    strings = listOf(
        ",",
        "all",
    ),
    opcodes = listOf(
        Opcode.CONST_4,
        Opcode.SGET_OBJECT,
        Opcode.CONST_WIDE,
        Opcode.INVOKE_STATIC,
        Opcode.MOVE_RESULT_OBJECT,
    ),
)



@Patch(
    description = "sets required tigon related flags to default",
    compatiblePackages = [CompatiblePackage("com.instagram.android")],
    use = true,
    requiresIntegrations = true,
)
object DefaultTigonPatch:BytecodePatch(
    setOf(TigonEnabledFlagFingerprint,HTTPStreamingFlagFingerprint)
){
    override fun execute(context: BytecodeContext) {
        val result = TigonEnabledFlagFingerprint.result
            ?:throw PatchException("TigonEnabledFlagFingerprint not found")

        val method = result.mutableMethod
        val instructions = method.getInstructions()

        val movResLoc = instructions.filter { it.opcode == Opcode.MOVE_RESULT }[1].location.index
        val reg = method.getInstruction<OneRegisterInstruction>(movResLoc).registerA

        method.addInstruction(movResLoc+1,"""
            const v$reg, 0x0
        """.trimIndent())


        val result2 = HTTPStreamingFlagFingerprint.result
            ?:throw PatchException("HTTPStreamingFlagFingerprint not found")

        val method2 = result2.mutableMethod

        method2.addInstructions(0,"""
            const v0, 0x0
            return v0
        """.trimIndent())
    }
}