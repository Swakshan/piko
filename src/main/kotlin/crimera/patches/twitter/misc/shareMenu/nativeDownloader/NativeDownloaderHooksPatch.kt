package crimera.patches.twitter.misc.shareMenu.nativeDownloader

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.extensions.InstructionExtensions.getInstructions
import app.revanced.patcher.extensions.InstructionExtensions.replaceInstruction
import app.revanced.patcher.fingerprint.MethodFingerprint
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.PatchException
import app.revanced.patcher.patch.annotation.CompatiblePackage
import app.revanced.patcher.patch.annotation.Patch
import app.revanced.patcher.util.proxy.mutableTypes.MutableMethod
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c
import com.android.tools.smali.dexlib2.dexbacked.instruction.DexBackedInstruction35c
import com.android.tools.smali.dexlib2.iface.reference.Reference

internal abstract class NativeDownloaderMethodFingerprint(
    private val methodName: String,
) : MethodFingerprint(customFingerprint = { methodDef, classDef ->
    methodDef.name == methodName && classDef.toString() == "Lapp/revanced/integrations/twitter/patches/NativeDownloader;"
})

internal object TweetObjectFingerprint : MethodFingerprint(strings = listOf("https://x.com/%1\$s/status/%2\$d"))

internal object GetTweetClassFingerprint : NativeDownloaderMethodFingerprint("getTweetClass")

internal object GetTweetIdFingerprint : NativeDownloaderMethodFingerprint("getTweetId")

internal object GetTweetUsernameFingerprint : NativeDownloaderMethodFingerprint("getTweetUsername")

internal object GetTweetMediaFingerprint : NativeDownloaderMethodFingerprint("getTweetMedia")

internal object GetUserNameMethodCaller : MethodFingerprint(
    returnType = "Z", opcodes = listOf(
        Opcode.IGET_OBJECT,
        Opcode.IGET_OBJECT,
        Opcode.IGET_OBJECT,
        Opcode.IGET_OBJECT,
        Opcode.INVOKE_STATIC,
        Opcode.MOVE_RESULT,
        Opcode.RETURN
    )
)

@Patch(
    compatiblePackages = [CompatiblePackage("com.twitter.android")],
)
class NativeDownloaderHooksPatch : BytecodePatch(
    setOf(
        GetTweetClassFingerprint,
        GetTweetIdFingerprint,
        GetTweetUsernameFingerprint,
        GetTweetMediaFingerprint,
        GetUserNameMethodCaller,
        TweetObjectFingerprint,
    ),
) {
    private fun MutableMethod.changeFirstString(value: String) {
        this.getInstructions().firstOrNull { it.opcode == Opcode.CONST_STRING }?.let { instruction ->
            val register = (instruction as BuilderInstruction21c).registerA
            this.replaceInstruction(instruction.location.index, "const-string v$register, \"$value\"")
        } ?: throw PatchException("const-string not found for method: ${this.name}")
    }

    private fun Reference.getMethodFromReference(): Char {
        val ref = this.toString()
        val index = ref.indexOf("->")
        return ref[index + 2]
    }

    override fun execute(context: BytecodeContext) {
        val getTweetObjectFingerprint = TweetObjectFingerprint.result ?: throw PatchException("bruh")

        val tweetObjectClass = getTweetObjectFingerprint.classDef
        val tweetObjectClassName = tweetObjectClass.toString().removePrefix("L").removeSuffix(";")

        val getIdMethod = tweetObjectClass.methods.firstOrNull { mutableMethod ->
            mutableMethod.name == "getId"
        } ?: throw PatchException("getIdMethod not found")

        val getUserNameMethodCaller =
            GetUserNameMethodCaller.result ?: throw PatchException("Could not find UserNameMethodCaller fingerprint")
        val getUserNameMethodName = getUserNameMethodCaller.method.implementation?.instructions?.firstOrNull { t ->
            t.opcode == Opcode.INVOKE_STATIC
        }.let {
            (it as DexBackedInstruction35c).reference.getMethodFromReference()
        }

        val getUsernameMethod = tweetObjectClass.methods.firstOrNull { mutableMethod ->
            mutableMethod.name.contains(getUserNameMethodName) && mutableMethod.returnType == "Ljava/lang/String;"
        } ?: throw PatchException("getUsernameMethod not found")

        val getMediaObjectMethod = tweetObjectClass.methods.firstOrNull { methodDef ->
            methodDef.implementation?.instructions?.map { it.opcode }?.toList() == listOf(
                Opcode.IGET_OBJECT,
                Opcode.IGET_OBJECT,
                Opcode.IGET_OBJECT,
                Opcode.IGET_OBJECT,
                Opcode.RETURN_OBJECT,
            )
        } ?: throw PatchException("getMediaObject not found")

        GetTweetClassFingerprint.result?.mutableMethod?.changeFirstString(tweetObjectClassName)
            ?: throw GetTweetClassFingerprint.exception

        GetTweetIdFingerprint.result?.mutableMethod?.changeFirstString(getIdMethod.name)
            ?: throw GetTweetIdFingerprint.exception

        GetTweetUsernameFingerprint.result?.mutableMethod?.changeFirstString(getUsernameMethod.name)
            ?: throw GetTweetUsernameFingerprint.exception

        GetTweetMediaFingerprint.result?.mutableMethod?.changeFirstString(getMediaObjectMethod.name)
            ?: throw GetTweetMediaFingerprint.exception
    }
}
