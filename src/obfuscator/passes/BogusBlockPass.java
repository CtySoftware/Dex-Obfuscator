package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

public class BogusBlockPass implements ObfuscationPass {

    private static final String[] FIELD_NAMES = {
        "byte","case","char","else","enum","goto","long","null","this","void"
    };

    @Override
    public String name() { return "BogusBlockPass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableBogusBlocks()) return;

        Random rng = new Random(System.nanoTime() ^ 0xDEADF00DL);
        int injected = 0;
        int classIdx = 0;

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;

            List<InjectPoint> points = new ArrayList<>();
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() < 10) continue;
                if (mn.name.equals("<clinit>") || mn.name.equals("<init>")) continue;
                if (isDecoderOrHelper(mn.name)) continue;
                if ((mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) continue;
                if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) continue;

                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn.getOpcode() == -1) continue;
                    boolean isSafe = (insn.getOpcode() >= Opcodes.ISTORE && insn.getOpcode() <= Opcodes.ASTORE)
                        || insn.getOpcode() == Opcodes.POP
                        || insn.getOpcode() == Opcodes.POP2
                        || insn.getOpcode() == Opcodes.PUTSTATIC
                        || insn.getOpcode() == Opcodes.PUTFIELD;
                    if (isSafe && rng.nextInt(4) == 0) {
                        points.add(new InjectPoint(mn, insn));
                    }
                }
            }

            if (points.isEmpty()) continue;

            Set<String> used = new HashSet<>();
            for (FieldNode fn : cn.fields) used.add(fn.name);
            for (MethodNode mn : cn.methods) used.add(mn.name);

            String guardFieldName = uniqueName(used, FIELD_NAMES[classIdx % FIELD_NAMES.length]);
            classIdx++;

            int guardValue = pickGuardValue(rng);

            cn.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                guardFieldName, "I", null, null
            ));

            MethodNode clinit = findOrCreateClinit(cn);
            InsnList guardInit = buildGuardInit(cn.name, guardFieldName, guardValue, rng);
            if (clinit.instructions.size() > 0) {
                clinit.instructions.insert(guardInit);
            } else {
                clinit.instructions.add(guardInit);
                clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            }

            int limit = Math.min(points.size(), 8);
            Collections.shuffle(points, rng);
            for (int i = 0; i < limit; i++) {
                InjectPoint pt = points.get(i);
                int form = rng.nextInt(4);
                InsnList bogus = buildBogusBlock(form, cn.name, guardFieldName, guardValue, pt.method, rng);
                pt.method.instructions.insert(pt.insn, bogus);
                injected++;
            }
        }

    }

    private int pickGuardValue(Random rng) {
        int v;
        do {
            v = rng.nextInt(0x7FFF) + 0x100;
        } while (v % 7 == 3);
        return v;
    }

    private InsnList buildGuardInit(String className, String fieldName, int value, Random rng) {
        InsnList ins = new InsnList();
        int mask = rng.nextInt(0xFFFF) + 1;
        int rot = rng.nextInt(13) + 2;
        ins.add(new LdcInsnNode(Integer.rotateLeft(value, rot) ^ mask));
        ins.add(new LdcInsnNode(mask));
        ins.add(new InsnNode(Opcodes.IXOR));
        ins.add(new LdcInsnNode(rot));
        ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "rotateRight", "(II)I", false));
        ins.add(new FieldInsnNode(Opcodes.PUTSTATIC, className, fieldName, "I"));
        return ins;
    }

    private InsnList buildBogusBlock(int form, String className, String fieldName, int guardValue, MethodNode mn, Random rng) {
        InsnList ins = new InsnList();
        LabelNode skipBogus = new LabelNode();
        LabelNode bogusStart = new LabelNode();
        LabelNode bogusEnd = new LabelNode();

        switch (form) {
            case 0: {
                ins.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                ins.add(intInsn(7));
                ins.add(new InsnNode(Opcodes.IREM));
                ins.add(intInsn(3));
                ins.add(new JumpInsnNode(Opcodes.IF_ICMPNE, skipBogus));
                ins.add(bogusStart);
                emitFakeComputation(ins, mn, rng);
                ins.add(bogusEnd);
                ins.add(skipBogus);
                break;
            }
            case 1: {
                ins.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                ins.add(new InsnNode(Opcodes.DUP));
                ins.add(new InsnNode(Opcodes.IMUL));
                ins.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"));
                ins.add(new InsnNode(Opcodes.IADD));
                ins.add(intInsn(2));
                ins.add(new InsnNode(Opcodes.IREM));
                ins.add(intInsn(1));
                ins.add(new JumpInsnNode(Opcodes.IF_ICMPNE, skipBogus));
                ins.add(bogusStart);
                emitFakeComputation(ins, mn, rng);
                ins.add(bogusEnd);
                ins.add(skipBogus);
                break;
            }
            case 2: {
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "nanoTime", "()J", false));
                ins.add(new InsnNode(Opcodes.L2I));
                ins.add(new InsnNode(Opcodes.DUP));
                ins.add(new InsnNode(Opcodes.IMUL));
                ins.add(intInsn(2));
                ins.add(new InsnNode(Opcodes.IREM));
                ins.add(intInsn(1));
                ins.add(new JumpInsnNode(Opcodes.IF_ICMPNE, skipBogus));
                ins.add(bogusStart);
                emitFakeComputation(ins, mn, rng);
                ins.add(bogusEnd);
                ins.add(skipBogus);
                break;
            }
            case 3: {
                int c = rng.nextInt(1000) + 100;
                ins.add(intInsn(c));
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "bitCount", "(I)I", false));
                ins.add(intInsn(33));
                ins.add(new JumpInsnNode(Opcodes.IF_ICMPLT, skipBogus));
                ins.add(bogusStart);
                emitFakeComputation(ins, mn, rng);
                ins.add(bogusEnd);
                ins.add(skipBogus);
                break;
            }
        }

        return ins;
    }

    private void emitFakeComputation(InsnList ins, MethodNode mn, Random rng) {
        int form = rng.nextInt(2);
        int deadLocal = mn.maxLocals;
        mn.maxLocals = Math.max(mn.maxLocals, deadLocal + 1);

        switch (form) {
            case 0: {
                int a = rng.nextInt(10000) + 1;
                int b = rng.nextInt(10000) + 1;
                ins.add(intInsn(a));
                ins.add(intInsn(b));
                ins.add(new InsnNode(Opcodes.IMUL));
                ins.add(new InsnNode(Opcodes.ICONST_1));
                ins.add(new InsnNode(Opcodes.ISHR));
                ins.add(new VarInsnNode(Opcodes.ISTORE, deadLocal));
                break;
            }
            case 1: {
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "currentTimeMillis", "()J", false));
                ins.add(new InsnNode(Opcodes.L2I));
                ins.add(new VarInsnNode(Opcodes.ISTORE, deadLocal));
                ins.add(new VarInsnNode(Opcodes.ILOAD, deadLocal));
                ins.add(new IntInsnNode(Opcodes.SIPUSH, 0xFF));
                ins.add(new InsnNode(Opcodes.IAND));
                ins.add(new VarInsnNode(Opcodes.ISTORE, deadLocal));
                break;
            }
        }
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

    private static class InjectPoint {
        MethodNode method;
        AbstractInsnNode insn;
        InjectPoint(MethodNode m, AbstractInsnNode i) { method = m; insn = i; }
    }
}
