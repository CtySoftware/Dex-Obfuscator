package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

public class GotoObfuscationPass implements ObfuscationPass {

    @Override
    public String name() { return "GotoObfuscationPass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableGotoObfuscation()) return;

        Random rng = new Random(System.nanoTime() ^ 0xB33FL);
        int fakeJumps = 0;

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() < 12) continue;
                if (mn.name.equals("<clinit>") || mn.name.equals("<init>")) continue;
                if (isDecoderOrHelper(mn.name)) continue;
                if ((mn.access & Opcodes.ACC_NATIVE) != 0) continue;
                if ((mn.access & Opcodes.ACC_ABSTRACT) != 0) continue;
                if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) continue;

                List<AbstractInsnNode> safePoints = new ArrayList<>();
                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (isSafeInsertionPoint(insn)) {
                        safePoints.add(insn);
                    }
                }

                if (safePoints.size() < 4) continue;

                int insertCount = Math.max(2, safePoints.size() / 2);
                Collections.shuffle(safePoints, rng);

                for (int i = 0; i < insertCount && i < safePoints.size(); i++) {
                    AbstractInsnNode insertAfter = safePoints.get(i);

                    AbstractInsnNode skipTarget = insertAfter.getNext();
                    int skip = rng.nextInt(4) + 2;
                    for (int s = 0; s < skip && skipTarget != null; s++) {
                        skipTarget = skipTarget.getNext();
                    }
                    if (skipTarget == null) continue;

                    LabelNode jumpTarget = new LabelNode();
                    mn.instructions.insertBefore(skipTarget, jumpTarget);

                    int technique = rng.nextInt(5);
                    InsnList fakeJump = new InsnList();

                    switch (technique) {
                        case 0: {
                            int a = rng.nextInt(100) + 50;
                            int b = a + rng.nextInt(50) + 1;
                            fakeJump.add(intInsn(a));
                            fakeJump.add(intInsn(b));
                            fakeJump.add(new JumpInsnNode(Opcodes.IF_ICMPGT, jumpTarget));
                            break;
                        }
                        case 1: {
                            int x = rng.nextInt(1000);
                            int y = x + rng.nextInt(500) + 1;
                            fakeJump.add(intInsn(x));
                            fakeJump.add(intInsn(y));
                            fakeJump.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, jumpTarget));
                            break;
                        }
                        case 2: {
                            int x = rng.nextInt(1000) + 1;
                            fakeJump.add(intInsn(x));
                            fakeJump.add(new JumpInsnNode(Opcodes.IFLT, jumpTarget));
                            break;
                        }
                        case 3: {
                            int c = rng.nextInt(500) + 100;
                            fakeJump.add(intInsn(c));
                            fakeJump.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "bitCount", "(I)I", false));
                            fakeJump.add(intInsn(33));
                            fakeJump.add(new JumpInsnNode(Opcodes.IF_ICMPGE, jumpTarget));
                            break;
                        }
                        case 4: {
                            int p = rng.nextInt(1000) + 10;
                            fakeJump.add(intInsn(p));
                            fakeJump.add(new InsnNode(Opcodes.DUP));
                            fakeJump.add(new InsnNode(Opcodes.IMUL));
                            fakeJump.add(intInsn(p));
                            fakeJump.add(new InsnNode(Opcodes.IADD));
                            fakeJump.add(intInsn(2));
                            fakeJump.add(new InsnNode(Opcodes.IREM));
                            fakeJump.add(intInsn(1));
                            fakeJump.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, jumpTarget));
                            break;
                        }
                    }

                    mn.instructions.insert(insertAfter, fakeJump);
                    fakeJumps++;
                }
            }
        }
    }

    private boolean isSafeInsertionPoint(AbstractInsnNode insn) {
        int op = insn.getOpcode();
        if (op == -1) return false;
        if (op >= Opcodes.ISTORE && op <= Opcodes.ASTORE) return true;
        if (op == Opcodes.POP || op == Opcodes.POP2) return true;

        if (insn instanceof MethodInsnNode) {
            MethodInsnNode min = (MethodInsnNode) insn;
            if (min.desc.endsWith(")V")) return true;
        }
        if (op == Opcodes.PUTFIELD || op == Opcodes.PUTSTATIC) return true;
        if (op == Opcodes.MONITORENTER || op == Opcodes.MONITOREXIT) return true;

        return false;
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
