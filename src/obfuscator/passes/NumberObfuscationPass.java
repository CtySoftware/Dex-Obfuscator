package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

public class NumberObfuscationPass implements ObfuscationPass {

    private static final String[] FIELD_NAMES = {
        "do", "if", "for", "new", "try", "int", "go", "is", "at"
    };

    private final int round;
    private final int minAbs;

    public NumberObfuscationPass() { this(1, 2); }
    public NumberObfuscationPass(int round, int minAbs) {
        this.round = round;
        this.minAbs = minAbs;
    }

    @Override
    public String name() { return "NumberObfuscationPass[R" + round + "]"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableNumberObfuscation()) return;

        Random rng = new Random(0xDEAF ^ (round * 0xC0FFEEL));
        int totalCount = 0;
        int classIdx = 0;

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;
            List<IntTarget> allTargets = new ArrayList<>();

            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                if (isDecoderOrHelper(mn.name)) continue;
                if ((mn.access & Opcodes.ACC_NATIVE) != 0) continue;
                if ((mn.access & Opcodes.ACC_ABSTRACT) != 0) continue;

                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (isIntConstant(insn)) {
                        int val = getIntValue(insn);
                        if (Math.abs(val) < minAbs) continue;
                        if (val != 0 && val != 1 && val != -1) {
                            allTargets.add(new IntTarget(mn, insn, val));
                        }
                    }
                }
            }

            if (allTargets.isEmpty()) continue;

            int classKey = rng.nextInt(0x7FFF) + 0x100;

            List<Integer> uniqueVals = new ArrayList<>();
            Map<Integer, Integer> valToIndex = new HashMap<>();
            for (IntTarget t : allTargets) {
                if (!valToIndex.containsKey(t.value)) {
                    valToIndex.put(t.value, uniqueVals.size());
                    uniqueVals.add(t.value);
                }
            }

            Set<String> usedNames = new HashSet<>();
            for (FieldNode fn : cn.fields) usedNames.add(fn.name);
            for (MethodNode mn : cn.methods) usedNames.add(mn.name);

            String baseFieldName = FIELD_NAMES[classIdx % FIELD_NAMES.length];
            if (round > 1) baseFieldName = baseFieldName + "_r" + round;
            String fieldName = uniqueName(usedNames, baseFieldName);
            classIdx++;

            FieldNode arrayField = new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                fieldName,
                "[I",
                null,
                null
            );
            cn.fields.add(arrayField);

            MethodNode clinit = findOrCreateClinit(cn);
            InsnList init = buildArrayInit(cn.name, fieldName, uniqueVals, classKey, cn);
            if (clinit.instructions.size() > 0) {
                clinit.instructions.insert(init);
            } else {
                clinit.instructions.add(init);
                clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            }

            for (IntTarget t : allTargets) {
                int idx = valToIndex.get(t.value);
                InsnList replacement = new InsnList();
                replacement.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, fieldName, "[I"));
                replacement.add(loadInt(idx));
                replacement.add(new InsnNode(Opcodes.IALOAD));
                replacement.add(loadInt(classKey));
                replacement.add(new InsnNode(Opcodes.IXOR));

                t.method.instructions.insertBefore(t.insn, replacement);
                t.method.instructions.remove(t.insn);
                totalCount++;
            }
        }
    }

    private static final int MAX_PER_HELPER = 100;

    private InsnList buildArrayInit(String className, String fieldName, List<Integer> values, int key, ClassNode cn) {
        if (values.size() <= MAX_PER_HELPER) {
            return buildArrayInitDirect(className, fieldName, values, key);
        }
        return buildArrayInitSplit(className, fieldName, values, key, cn);
    }

    private InsnList buildArrayInitDirect(String className, String fieldName, List<Integer> values, int key) {
        InsnList insns = new InsnList();
        insns.add(loadInt(values.size()));
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        for (int i = 0; i < values.size(); i++) {
            int encrypted = values.get(i) ^ key;
            insns.add(new InsnNode(Opcodes.DUP));
            insns.add(loadInt(i));
            insns.add(loadInt(encrypted));
            insns.add(new InsnNode(Opcodes.IASTORE));
        }
        insns.add(new FieldInsnNode(Opcodes.PUTSTATIC, className, fieldName, "[I"));
        return insns;
    }

    private InsnList buildArrayInitSplit(String className, String fieldName, List<Integer> values, int key, ClassNode cn) {
        int numHelpers = (values.size() + MAX_PER_HELPER - 1) / MAX_PER_HELPER;

        for (int h = 0; h < numHelpers; h++) {
            int start = h * MAX_PER_HELPER;
            int end = Math.min(start + MAX_PER_HELPER, values.size());
            String helperName = "_numInit" + round + "_" + h;

            MethodNode helper = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, helperName, "([I)V", null, null);
            InsnList hIns = new InsnList();
            for (int i = start; i < end; i++) {
                int encrypted = values.get(i) ^ key;
                hIns.add(new VarInsnNode(Opcodes.ALOAD, 0)); 
                hIns.add(loadInt(i));
                hIns.add(loadInt(encrypted));
                hIns.add(new InsnNode(Opcodes.IASTORE));
            }
            hIns.add(new InsnNode(Opcodes.RETURN));
            helper.instructions = hIns;
            helper.maxStack = 4;
            helper.maxLocals = 1;
            cn.methods.add(helper);
        }

        InsnList insns = new InsnList();
        insns.add(loadInt(values.size()));
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        insns.add(new FieldInsnNode(Opcodes.PUTSTATIC, className, fieldName, "[I"));

        for (int h = 0; h < numHelpers; h++) {
            insns.add(new FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "[I"));
            insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, "_numInit" + round + "_" + h, "([I)V", false));
        }
        return insns;
    }

    private MethodNode findOrCreateClinit(ClassNode cn) {
        for (MethodNode mn : cn.methods) {
            if (mn.name.equals("<clinit>")) {
                return mn;
            }
        }
        MethodNode clinit = new MethodNode(
            Opcodes.ACC_STATIC,
            "<clinit>",
            "()V",
            null,
            null
        );
        clinit.instructions = new InsnList();
        clinit.maxStack = 4;
        clinit.maxLocals = 0;
        cn.methods.add(clinit);
        return clinit;
    }

    private boolean isIntConstant(AbstractInsnNode insn) {
        int op = insn.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) return true;
        if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) return true;
        if (insn instanceof LdcInsnNode) {
            return ((LdcInsnNode) insn).cst instanceof Integer;
        }
        return false;
    }

    private int getIntValue(AbstractInsnNode insn) {
        int op = insn.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) {
            return op - Opcodes.ICONST_0;
        }
        if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) {
            return ((IntInsnNode) insn).operand;
        }
        if (insn instanceof LdcInsnNode) {
            return (Integer) ((LdcInsnNode) insn).cst;
        }
        return 0;
    }

    private static AbstractInsnNode loadInt(int val) {
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

    private boolean isDecoderOrHelper(String name) {
        if (name.startsWith("_numInit") || name.startsWith("_init") || name.startsWith("_s")) return true;
        String[] decNames = {"do","if","for","new","try","int","go","is","at","of"};
        for (String dec : decNames) {
            if (name.equals(dec) || name.startsWith(dec + "_")) return true;
        }
        return false;
    }

    private static class IntTarget {
        MethodNode method;
        AbstractInsnNode insn;
        int value;
        IntTarget(MethodNode m, AbstractInsnNode i, int v) { method = m; insn = i; value = v; }
    }
}

