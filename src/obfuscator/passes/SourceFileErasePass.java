package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

public class SourceFileErasePass implements ObfuscationPass {

    @Override
    public String name() { return "SourceFileErasePass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableSourceErase()) return;

        int erased = 0;

        for (ClassNode cn : classes) {
            boolean changed = false;

            cn.sourceFile = null;
            cn.sourceDebug = null;
            changed = true;

            for (MethodNode mn : cn.methods) {
                if (mn.localVariables != null) {
                    mn.localVariables.clear();
                }

                if (mn.visibleAnnotations != null) {
                    mn.visibleAnnotations.removeIf(a ->
                        a.desc.contains("DebugInfo") ||
                        a.desc.contains("LineNumber") ||
                        a.desc.contains("SourceFile")
                    );
                }

                if (mn.instructions != null) {
                    List<AbstractInsnNode> toRemove = new ArrayList<>();
                    for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                        if (insn instanceof LineNumberNode) {
                            toRemove.add(insn);
                        }
                    }
                    for (AbstractInsnNode insn : toRemove) {
                        LabelNode label = ((LineNumberNode) insn).start;
                        mn.instructions.remove(insn);
                    }
                }
            }

            if (cn.innerClasses != null) {
                Iterator<InnerClassNode> it = cn.innerClasses.iterator();
                while (it.hasNext()) {
                    InnerClassNode icn = it.next();
                    if (icn.outerName == null && icn.innerName == null) {
                        it.remove();
                    }
                }
            }

            cn.outerClass = null;
            cn.outerMethod = null;
            cn.outerMethodDesc = null;

            if (cn.attrs != null) {
                cn.attrs.clear();
            }

            if (changed) erased++;
        }

    }
}
