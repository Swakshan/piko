package crimera.patches.instagram.ads

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.extensions.InstructionExtensions.addInstruction
import app.revanced.patcher.extensions.or
import app.revanced.patcher.fingerprint.MethodFingerprint
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.PatchException

import app.revanced.patcher.patch.annotation.CompatiblePackage
import app.revanced.patcher.patch.annotation.Patch
import app.revanced.patcher.util.proxy.mutableTypes.MutableField.Companion.toMutable
import app.revanced.patcher.util.proxy.mutableTypes.MutableMethod.Companion.toMutable
import app.revanced.patcher.util.smali.toInstructions
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.immutable.ImmutableField
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import crimera.patches.instagram.misc.integrations.IntegrationsPatch

object JniHandlerFingerprint : MethodFingerprint(
    customFingerprint = { methodDef, _ -> methodDef.definingClass == "Lcom/facebook/proxygen/JniHandler;" }
)

object NativeReadBufferFingerprint : MethodFingerprint(
    customFingerprint = { methodDef, _ -> methodDef.definingClass == "Lcom/facebook/proxygen/NativeReadBuffer;" }
)


@Patch(
    name = "Proxygen",
    description = "hook proxygen",
    compatiblePackages = [CompatiblePackage("com.instagram.android")],
    dependencies = [DefaultTigonPatch::class,IntegrationsPatch::class],
    requiresIntegrations = true,
    use = true
)
object ProxygenHook:BytecodePatch(
    setOf(JniHandlerFingerprint,NativeReadBufferFingerprint)
) {
    override fun execute(context: BytecodeContext) {
        val result = JniHandlerFingerprint.result
            ?: throw PatchException("JniHandlerFingerprint not found")

        val NETWORKHOOKCLS = "Lapp/revanced/integrations/instagram/NetworkHooks;"

        val methods = result.mutableClass.methods
        val headerMethod = methods.first { it.name == "sendHeaders" }
        val bodyMethod = methods.first { it.name =="sendRequestWithBodyAndEom" }

        headerMethod.addInstruction(0,"""
            invoke-static{p0,p1}, $NETWORKHOOKCLS->jniHandlerSendHeaders(Lcom/facebook/proxygen/JniHandler;Lorg/apache/http/client/methods/HttpUriRequest;)V
        """.trimIndent())

        bodyMethod.addInstruction(0,"""
            invoke-static {p0, p1, p2, p3, p4}, $NETWORKHOOKCLS->jniHandlerSendRequest(Lcom/facebook/proxygen/JniHandler;Lorg/apache/http/client/methods/HttpUriRequest;[BII)V
        """.trimIndent())



        val result2 = NativeReadBufferFingerprint.result
            ?: throw PatchException("NativeReadBufferFingerprint not found")

        val result2Cls = result2.mutableClass
        val methods2 = result2Cls.methods
        val fields2 = result2Cls.fields

        //Adds necessary additional fields
        val modifiedResponseField = ImmutableField(
            result2.classDef.type,
            "modifiedResponse",
            "[B",
            AccessFlags.PUBLIC or AccessFlags.PUBLIC,
            null,
            null,
            null
        ).toMutable()
        fields2.add(modifiedResponseField)

        val modifiedResponseOffsetField = ImmutableField(
            result2.classDef.type,
            "modifiedResponseOffset",
            "I",
            AccessFlags.PUBLIC or AccessFlags.PUBLIC,
            null,
            null,
            null
        ).toMutable()
        fields2.add(modifiedResponseOffsetField)

        val requestURIField = ImmutableField(
            result2.classDef.type,
            "requestURI",
            "Ljava/net/URI;",
            AccessFlags.PUBLIC or AccessFlags.PUBLIC,
            null,
            null,
            null
        ).toMutable()
        fields2.add(requestURIField)

        //modifies 'read' method
        val readMethod = methods2.first { it.name=="read" }
        readMethod.setName( "_read")
        val newReadMethod = ImmutableMethod(
            readMethod.definingClass,
            "read",
            readMethod.parameters,
            readMethod.returnType,
            readMethod.accessFlags,
            null,
            null,
            ImmutableMethodImplementation(
                5, """
                    invoke-static {p0, p1, p2, p3}, $NETWORKHOOKCLS->nativeReadBufferRead(Lcom/facebook/proxygen/NativeReadBuffer;[BII)I
                    move-result v0
                    return v0
                     """.toInstructions(), null, null
            )
        ).toMutable()
        methods2.add(newReadMethod)

        //modifies 'size' method
        val sizeMethod = methods2.first {it.name=="size" }
        sizeMethod.setName("_size")
        val newSizeMethod = ImmutableMethod(
            sizeMethod.definingClass,
            "size",
            sizeMethod.parameters,
            sizeMethod.returnType,
            sizeMethod.accessFlags,
            null,
            null,
            ImmutableMethodImplementation(
                1, """
                    invoke-static {v0}, $NETWORKHOOKCLS->nativeReadBufferSize(Lcom/facebook/proxygen/NativeReadBuffer;)I
                    move-result v0
                    return v0

                    """.toInstructions(), null, null
            )
        ).toMutable()
        methods2.add(newSizeMethod)

    //end func
    }
    //end class
}