package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

public class OpaquePredicatePass implements ObfuscationPass {

    private static final String[] FIELD_NAMES = {
        "byte", "case", "char", "else", "enum", "goto", "long", "null", "this", "void"
    };

    @Override
    public String name() { return "OpaquePredicatePass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableOpaquePredicates()) return;

        Random rng = new Random(System.nanoTime() ^ 0xBEEFCAFEL);
        int count = 0;
        int classIdx = 0;

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;
            List<InjectTarget> targets = new ArrayList<>();

            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() < 8) continue;
                if (mn.name.equals("<clinit>")) continue;
                if (isDecoderOrHelper(mn.name)) continue;
                if ((mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) continue;

                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn.getOpcode() == -1) continue;
                    boolean isStore = insn.getOpcode() >= Opcodes.ISTORE && insn.getOpcode() <= Opcodes.ASTORE;
                    boolean isReturn = insn.getOpcode() >= Opcodes.IRETURN && insn.getOpcode() <= Opcodes.RETURN;
                    boolean isPop = insn.getOpcode() == Opcodes.POP || insn.getOpcode() == Opcodes.POP2;

                    if (isStore && rng.nextInt(3) == 0) targets.add(new InjectTarget(mn, insn));
                    else if (isReturn && rng.nextInt(2) == 0) targets.add(new InjectTarget(mn, insn));
                    else if (isPop && rng.nextInt(2) == 0) targets.add(new InjectTarget(mn, insn));
                }
            }

            if (targets.isEmpty()) continue;

            Set<String> used = new HashSet<>();
            for (FieldNode fn : cn.fields) used.add(fn.name);
            for (MethodNode mn : cn.methods) used.add(mn.name);

            String stateFieldName = uniqueName(used, FIELD_NAMES[classIdx % FIELD_NAMES.length]);
            classIdx++;

            int stateValue = pickSafeState(rng);

            cn.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                stateFieldName, "I", null, null
            ));

            MethodNode clinit = findOrCreateClinit(cn);
            InsnList init = new InsnList();
            int mask = rng.nextInt(0xFFFF) + 1;
            int rot = rng.nextInt(15) + 1;
            init.add(new LdcInsnNode(Integer.rotateLeft(stateValue, rot) ^ mask));
            init.add(new LdcInsnNode(mask));
            init.add(new InsnNode(Opcodes.IXOR));
            init.add(new LdcInsnNode(rot));
            init.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "rotateRight", "(II)I", false));
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, stateFieldName, "I"));
            if (clinit.instructions.size() > 0) {
                clinit.instructions.insert(init);
            } else {
                clinit.instructions.add(init);
                clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            }

            for (InjectTarget target : targets) {
                int form = rng.nextInt(8);
                InsnList guard = buildPredicate(form, cn.name, stateFieldName, stateValue, rng);
                target.method.instructions.insertBefore(target.insn, guard);
                count++;
            }
        }
    }

    private int pickSafeState(Random rng) {
        for (int attempt = 0; attempt < 1000; attempt++) {
            int v = rng.nextInt(0x7FFF) + 0x100;
            if (v % 7 == 3) continue;
            int mixed = (v ^ (v >>> 16)) & 7;
            if (mixed == 3) continue;
            if ((v * v + v) % 2 != 0) continue;
            return v;
        }
        return 0x4D2;
    }

    private InsnList buildPredicate(int form, String className, String fieldName, int stateValue, Random rng) {
        InsnList guard = new InsnList();
        LabelNode skip = new LabelNode();

        switch (form) {
            case 0:
                guard.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                guard.add(intInsn(7));
                guard.add(new InsnNode(Opcodes.IREM));
                guard.add(intInsn(3));
                guard.add(new JumpInsnNode(Opcodes.IF_ICMPNE, skip));
                addExceptionThrow(guard, skip, rng);
                break;

            case 1:
                guard.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                guard.add(new InsnNode(Opcodes.DUP));
                guard.add(intInsn(16));
                guard.add(new InsnNode(Opcodes.IUSHR));
                guard.add(new InsnNode(Opcodes.IXOR));
                guard.add(intInsn(7));
                guard.add(new InsnNode(Opcodes.IAND));
                guard.add(intInsn(3));
                guard.add(new JumpInsnNode(Opcodes.IF_ICMPNE, skip));
                addExceptionThrow(guard, skip, rng);
                break;

            case 2:
                guard.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "abs", "(I)I", false));
                guard.add(new JumpInsnNode(Opcodes.IFGE, skip));
                addExceptionThrow(guard, skip, rng);
                break;

            case 3:
                guard.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                guard.add(intInsn(0));
                guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "max", "(II)I", false));
                guard.add(new JumpInsnNode(Opcodes.IFGE, skip));
                addExceptionThrow(guard, skip, rng);
                break;

            case 4:
                guard.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                guard.add(intInsn(4));
                guard.add(new InsnNode(Opcodes.IMUL));
                guard.add(intInsn(2));
                guard.add(new InsnNode(Opcodes.IADD));
                guard.add(intInsn(2));
                guard.add(new InsnNode(Opcodes.IREM));
                guard.add(new JumpInsnNode(Opcodes.IFEQ, skip));
                addExceptionThrow(guard, skip, rng);
                break;

            case 5:
                guard.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/String", "valueOf", "(I)Ljava/lang/String;", false));
                guard.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false));
                guard.add(new JumpInsnNode(Opcodes.IFNE, skip));
                addExceptionThrow(guard, skip, rng);
                break;

            case 6:
                guard.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                guard.add(intInsn(0));
                guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "compare", "(II)I", false));
                guard.add(new JumpInsnNode(Opcodes.IFGE, skip));
                addExceptionThrow(guard, skip, rng);
                break;

            case 7:
                guard.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                guard.add(intInsn(100000));
                guard.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "min", "(II)I", false));
                guard.add(intInsn(-10));
                guard.add(new JumpInsnNode(Opcodes.IF_ICMPGE, skip));
                addExceptionThrow(guard, skip, rng);
                break;
        }
        return guard;
    }

    private void addExceptionThrow(InsnList guard, LabelNode skip, Random rng) {
        guard.add(new InsnNode(Opcodes.ACONST_NULL));
        guard.add(new InsnNode(Opcodes.ATHROW));
        guard.add(skip);
    }

    private static AbstractInsnNode intInsn(int val) {
        if (val >= -1 && val <= 5) return new InsnNode(Opcodes.ICONST_0 + val);
        if (val >= Byte.MIN_VALUE && val <= Byte.MAX_VALUE) return new IntInsnNode(Opcodes.BIPUSH, val);
        if (val >= Short.MIN_VALUE && val <= Short.MAX_VALUE) return new IntInsnNode(Opcodes.SIPUSH, val);
        return new LdcInsnNode(val);
    }

    private String uniqueName(Set<String> used, String base) {
        String n = base;
        while (used.contains(n)) n = n + "_";
        used.add(n);
        return n;
    }

    private MethodNode findOrCreateClinit(ClassNode cn) {
        for (MethodNode mn : cn.methods) if (mn.name.equals("<clinit>")) return mn;
        MethodNode c = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        c.instructions = new InsnList(); c.maxStack = 4; c.maxLocals = 0;
        cn.methods.add(c);
        return c;
    }

    private boolean isDecoderOrHelper(String name) {
        if (name.startsWith("_numInit") || name.startsWith("_init") || name.startsWith("_s")) return true;
        String[] decNames = {"do","if","for","new","try","int","go","is","at","of"};
        for (String dec : decNames) {
            if (name.equals(dec) || name.startsWith(dec + "_")) return true;
        }
        return false;
    }

    private static class InjectTarget {
        MethodNode method;
        AbstractInsnNode insn;
        InjectTarget(MethodNode m, AbstractInsnNode i) { method = m; insn = i; }
    }
}
