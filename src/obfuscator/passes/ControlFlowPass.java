package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

public class ControlFlowPass implements ObfuscationPass {

    @Override
    public String name() { return "ControlFlowPass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableControlFlowFlattening()) return;

        Random rng = new Random(0xF1A7);
        int count = 0;

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() < 15) continue;
                if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
                if (isDecoderOrHelper(mn.name)) continue;
                if ((mn.access & Opcodes.ACC_NATIVE) != 0) continue;
                if ((mn.access & Opcodes.ACC_ABSTRACT) != 0) continue;
                if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) continue;

                if (flattenMethod(mn, rng)) count++;
            }
        }
    }

    private boolean flattenMethod(MethodNode mn, Random rng) {
        List<InsnList> blocks = splitBasicBlocks(mn);
        if (blocks.size() < 3) return false; 

        int stateVar = mn.maxLocals;
        mn.maxLocals++;

        List<Integer> stateValues = new ArrayList<>();
        Set<Integer> usedValues = new HashSet<>();
        for (int i = 0; i < blocks.size(); i++) {
            int val;
            do { val = rng.nextInt(9000) + 1000; } while (usedValues.contains(val));
            usedValues.add(val);
            stateValues.add(val);
        }

        InsnList newInsns = new InsnList();

        LabelNode loopStart = new LabelNode();
        LabelNode loopEnd = new LabelNode();
        LabelNode defaultLabel = new LabelNode();

        newInsns.add(intInsn(stateValues.get(0)));
        newInsns.add(new VarInsnNode(Opcodes.ISTORE, stateVar));

        newInsns.add(loopStart);
        newInsns.add(new VarInsnNode(Opcodes.ILOAD, stateVar));

        List<Integer> order = new ArrayList<>();
        for (int i = 0; i < blocks.size(); i++) order.add(i);

        LabelNode[] caseLabels = new LabelNode[blocks.size()];
        for (int i = 0; i < blocks.size(); i++) {
            caseLabels[i] = new LabelNode();
        }
        int[] sortedKeys = new int[blocks.size()];
        LabelNode[] sortedLabels = new LabelNode[blocks.size()];
        Integer[] indices = new Integer[blocks.size()];
        for (int i = 0; i < blocks.size(); i++) indices[i] = i;
        Arrays.sort(indices, (a, b) -> Integer.compare(stateValues.get(a), stateValues.get(b)));
        for (int i = 0; i < blocks.size(); i++) {
            sortedKeys[i] = stateValues.get(indices[i]);
            sortedLabels[i] = caseLabels[indices[i]];
        }

        newInsns.add(new LookupSwitchInsnNode(defaultLabel, sortedKeys, sortedLabels));

        for (int i = 0; i < blocks.size(); i++) {
            newInsns.add(caseLabels[i]);

            InsnList block = blocks.get(i);

            AbstractInsnNode lastInsn = getLastReal(block);
            boolean endsWithReturn = lastInsn != null && 
                lastInsn.getOpcode() >= Opcodes.IRETURN && lastInsn.getOpcode() <= Opcodes.RETURN;
            newInsns.add(block);

            if (!endsWithReturn && i < blocks.size() - 1) {
                newInsns.add(intInsn(stateValues.get(i + 1)));
                newInsns.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
                newInsns.add(new JumpInsnNode(Opcodes.GOTO, loopStart));
            } else if (!endsWithReturn) {
                newInsns.add(new JumpInsnNode(Opcodes.GOTO, loopEnd));
            }
        }
        newInsns.add(defaultLabel);
        newInsns.add(new JumpInsnNode(Opcodes.GOTO, loopEnd));
        newInsns.add(loopEnd);

        mn.instructions = newInsns;
        return true;
    }

    private List<InsnList> splitBasicBlocks(MethodNode mn) {
        Set<AbstractInsnNode> leaders = new LinkedHashSet<>();
        leaders.add(mn.instructions.getFirst());

        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode) {
                AbstractInsnNode next = insn.getNext();
                if (next != null) leaders.add(next);
            }
        }
        List<InsnList> blocks = new ArrayList<>();
        InsnList current = new InsnList();
        int count = 0;
        int blockSize = 6;

        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();

            mn.instructions.remove(insn);
            current.add(insn);
            count++;

            boolean isReturn = insn.getOpcode() >= Opcodes.IRETURN && insn.getOpcode() <= Opcodes.RETURN;
            boolean isThrow = insn.getOpcode() == Opcodes.ATHROW;
            boolean isJump = insn instanceof JumpInsnNode;

            if (count >= blockSize || isReturn || isThrow || isJump) {
                if (current.size() > 0) {
                    blocks.add(current);
                    current = new InsnList();
                    count = 0;
                }
            }

            insn = next;
        }

        if (current.size() > 0) {
            blocks.add(current);
        }

        return blocks;
    }

    private AbstractInsnNode getLastReal(InsnList insns) {
        AbstractInsnNode last = insns.getLast();
        while (last != null && last.getOpcode() == -1) {
            last = last.getPrevious();
        }
        return last;
    }

    private boolean isDecoderOrHelper(String name) {
        if (name.startsWith("_numInit") || name.startsWith("_init") || name.startsWith("_s")) return true;
        String[] decNames = {"do","if","for","new","try","int","go","is","at","of"};
        for (String dec : decNames) {
            if (name.equals(dec) || name.startsWith(dec + "_")) return true;
        }
        return false;
    }

    private static AbstractInsnNode intInsn(int val) {
        if (val >= -1 && val <= 5) return new InsnNode(Opcodes.ICONST_0 + val);
        if (val >= Byte.MIN_VALUE && val <= Byte.MAX_VALUE) return new IntInsnNode(Opcodes.BIPUSH, val);
        if (val >= Short.MIN_VALUE && val <= Short.MAX_VALUE) return new IntInsnNode(Opcodes.SIPUSH, val);
        return new LdcInsnNode(val);
    }
}
