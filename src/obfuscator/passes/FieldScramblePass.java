package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

public class FieldScramblePass implements ObfuscationPass {

    @Override
    public String name() { return "FieldScramblePass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableFieldScramble()) return;

        Random rng = new Random(System.nanoTime() ^ 0xF1E1D5EEL);
        int scrambled = 0;

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;

            List<FieldNode> eligibleFields = new ArrayList<>();
            for (FieldNode fn : cn.fields) {
                if (!fn.desc.equals("I") && !fn.desc.equals("Z") && !fn.desc.equals("B") && !fn.desc.equals("S")) continue;
                if ((fn.access & Opcodes.ACC_FINAL) != 0) continue;
                if ((fn.access & Opcodes.ACC_VOLATILE) != 0) continue;
                if (detector.isFieldProtected(cn.name, fn.name)) continue;
                if ((fn.access & Opcodes.ACC_STATIC) == 0) continue;
                eligibleFields.add(fn);
            }

            if (eligibleFields.isEmpty()) continue;

            Set<String> usedNames = new HashSet<>();
            for (FieldNode fn : cn.fields) usedNames.add(fn.name);
            for (MethodNode mn : cn.methods) usedNames.add(mn.name);

            for (FieldNode fn : eligibleFields) {
                int xorKey = rng.nextInt(0x7FFF) + 1;
                int rot = rng.nextInt(15) + 1;

                String getterName = uniqueName(usedNames, "_g");
                String setterName = uniqueName(usedNames, "_s");

                addIntGetter(cn, getterName, fn.name, xorKey, rot);
                addIntSetter(cn, setterName, fn.name, xorKey, rot);

                replaceFieldAccesses(cn, fn, getterName, setterName);
                scrambled++;
            }
        }

    }

    private void addIntGetter(ClassNode cn, String name, String fieldName, int xorKey, int rot) {
        MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, name, "()I", null, null);
        InsnList ins = new InsnList();
        ins.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, fieldName, "I"));
        ins.add(new LdcInsnNode(xorKey));
        ins.add(new InsnNode(Opcodes.IXOR));
        ins.add(new LdcInsnNode(rot));
        ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "rotateRight", "(II)I", false));
        ins.add(new InsnNode(Opcodes.IRETURN));
        m.instructions = ins;
        m.maxStack = 3;
        m.maxLocals = 0;
        cn.methods.add(m);
    }

    private void addIntSetter(ClassNode cn, String name, String fieldName, int xorKey, int rot) {
        MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, name, "(I)V", null, null);
        InsnList ins = new InsnList();
        ins.add(new VarInsnNode(Opcodes.ILOAD, 0));
        ins.add(new LdcInsnNode(rot));
        ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "rotateLeft", "(II)I", false));
        ins.add(new LdcInsnNode(xorKey));
        ins.add(new InsnNode(Opcodes.IXOR));
        ins.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, fieldName, "I"));
        ins.add(new InsnNode(Opcodes.RETURN));
        m.instructions = ins;
        m.maxStack = 3;
        m.maxLocals = 1;
        cn.methods.add(m);
    }

    private void replaceFieldAccesses(ClassNode cn, FieldNode targetField, String getterName, String setterName) {
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            if (mn.name.equals(getterName) || mn.name.equals(setterName)) continue;

            List<AbstractInsnNode> toReplace = new ArrayList<>();
            for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof FieldInsnNode) {
                    FieldInsnNode fi = (FieldInsnNode) insn;
                    if (fi.owner.equals(cn.name)
                            && fi.name.equals(targetField.name)
                            && fi.desc.equals(targetField.desc)) {
                        toReplace.add(insn);
                    }
                }
            }

            for (AbstractInsnNode insn : toReplace) {
                FieldInsnNode fi = (FieldInsnNode) insn;
                if (fi.getOpcode() == Opcodes.GETSTATIC) {
                    MethodInsnNode call = new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, getterName, "()I", false);
                    mn.instructions.set(insn, call);
                } else if (fi.getOpcode() == Opcodes.PUTSTATIC) {
                    MethodInsnNode call = new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, setterName, "(I)V", false);
                    mn.instructions.set(insn, call);
                }
            }
        }
    }

    private String uniqueName(Set<String> used, String base) {
        String n = base;
        int suffix = 0;
        while (used.contains(n)) {
            n = base + suffix++;
        }
        used.add(n);
        return n;
    }
}
