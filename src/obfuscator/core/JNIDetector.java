package obfuscator.core;

import obfuscator.config.ObfuscatorConfig;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

public class JNIDetector {

    private final Set<String> jniClasses = new HashSet<>();
    private final Set<String> jniMethods = new HashSet<>();
    private final Set<String> jniFields = new HashSet<>();
    private ObfuscatorConfig config;

    public void analyze(List<ClassNode> classes, ObfuscatorConfig config) {
        this.config = config;
        Set<String> knownClasses = new HashSet<>();
        for (ClassNode cn : classes) knownClasses.add(cn.name);

        for (ClassNode cn : classes) {
            boolean hasNative = false;
            boolean hasLoadLib = false;

            for (MethodNode mn : cn.methods) {
                if ((mn.access & Opcodes.ACC_NATIVE) != 0) {
                    hasNative = true;
                    jniMethods.add(cn.name + "." + mn.name + mn.desc);
                }

                if (mn.name.equals("JNI_OnLoad") || mn.name.equals("JNI_OnUnload")) {
                    hasNative = true;
                }

                if (mn.instructions == null) continue;
                AbstractInsnNode prev = null;
                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode) {
                        MethodInsnNode mi = (MethodInsnNode) insn;
                        if (mi.owner.equals("java/lang/System") && mi.name.equals("loadLibrary")) {
                            hasLoadLib = true;
                        }
                        if (mi.owner.equals("java/lang/System") && mi.name.equals("load")) {
                            hasLoadLib = true;
                        }
                        if (mi.owner.equals("java/lang/Runtime") && mi.name.equals("loadLibrary")) {
                            hasLoadLib = true;
                        }
                        if (mi.owner.equals("java/lang/Runtime") && mi.name.equals("load")) {
                            hasLoadLib = true;
                        }
                    }
                    if (insn instanceof LdcInsnNode) {
                        LdcInsnNode ldc = (LdcInsnNode) insn;
                        if (ldc.cst instanceof String) {
                            String s = (String) ldc.cst;
                            if (s.endsWith(".so") || s.contains("lib") && s.endsWith(".so")) {
                                hasLoadLib = true;
                            }
                        }
                    }
                    prev = insn;
                }
            }

            if (hasNative || hasLoadLib) {
                jniClasses.add(cn.name);
                for (MethodNode mn : cn.methods) {
                    if ((mn.access & Opcodes.ACC_NATIVE) != 0) {
                        jniMethods.add(cn.name + "." + mn.name + mn.desc);
                    }
                }
                if (config.isEnableJniFieldProtection()) {
                    for (FieldNode fn : cn.fields) {
                        jniFields.add(cn.name + "." + fn.name);
                    }
                } else {
                    for (FieldNode fn : cn.fields) {
                        if (config.isJniKeptField(fn.name, cn.name + "." + fn.name)) {
                            jniFields.add(cn.name + "." + fn.name);
                        }
                    }
                }
            }
        }

    }

    public boolean isJNIClass(String name) { return jniClasses.contains(name); }
    public boolean isMethodProtected(String owner, String name, String desc) {
        return jniMethods.contains(owner + "." + name + desc);
    }
    public boolean isFieldProtected(String owner, String name) {
        return jniFields.contains(owner + "." + name);
    }
}
