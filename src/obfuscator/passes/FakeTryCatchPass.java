package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

public class FakeTryCatchPass implements ObfuscationPass {

    @Override
    public String name() { return "FakeTryCatchPass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableFakeTryCatch()) return;

        Random rng = new Random(0xCAFE);
        int count = 0;

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() < 8) continue;
                if (mn.name.equals("<clinit>") || mn.name.equals("<init>")) continue;
                if (isDecoderOrHelper(mn.name)) continue;
                if ((mn.access & Opcodes.ACC_NATIVE) != 0) continue;
                if ((mn.access & Opcodes.ACC_ABSTRACT) != 0) continue;

                if (wrapMethodInFakeTryCatch(mn, rng)) count++;
            }
        }
    }

    private boolean wrapMethodInFakeTryCatch(MethodNode mn, Random rng) {
        AbstractInsnNode firstReal = mn.instructions.getFirst();
        while (firstReal != null && firstReal.getOpcode() == -1) {
            firstReal = firstReal.getNext();
        }
        if (firstReal == null) return false;

        AbstractInsnNode lastReal = mn.instructions.getLast();
        while (lastReal != null && lastReal.getOpcode() == -1) {
            lastReal = lastReal.getPrevious();
        }
        if (lastReal == null || lastReal == firstReal) return false;

        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode handler1 = new LabelNode();
        LabelNode handler2 = new LabelNode();
        LabelNode afterHandlers = new LabelNode();

        mn.instructions.insertBefore(firstReal, tryStart);
        mn.instructions.insert(lastReal, tryEnd);

        int deadLocal = mn.maxLocals;

        InsnList tail = new InsnList();

        tail.add(handler1);
        tail.add(new VarInsnNode(Opcodes.ASTORE, deadLocal));
        tail.add(new VarInsnNode(Opcodes.ALOAD, deadLocal));
        tail.add(new InsnNode(Opcodes.ATHROW));

        tail.add(handler2);
        tail.add(new VarInsnNode(Opcodes.ASTORE, deadLocal));
        int a = rng.nextInt(100) + 50;
        int b = a + rng.nextInt(50) + 1;
        tail.add(intInsn(a));
        tail.add(intInsn(b));
        tail.add(new JumpInsnNode(Opcodes.IF_ICMPLT, afterHandlers));
        tail.add(new VarInsnNode(Opcodes.ALOAD, deadLocal));
        tail.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Throwable", "getMessage", "()Ljava/lang/String;", false));
        tail.add(new InsnNode(Opcodes.POP));
        tail.add(new VarInsnNode(Opcodes.ALOAD, deadLocal));
        tail.add(new InsnNode(Opcodes.ATHROW));

        tail.add(afterHandlers);
        tail.add(new VarInsnNode(Opcodes.ALOAD, deadLocal));
        tail.add(new InsnNode(Opcodes.ATHROW));

        mn.instructions.insert(tryEnd, tail);

        if (mn.tryCatchBlocks == null) mn.tryCatchBlocks = new ArrayList<>();
        mn.tryCatchBlocks.add(new TryCatchBlockNode(tryStart, tryEnd, handler1, "java/lang/RuntimeException"));
        mn.tryCatchBlocks.add(new TryCatchBlockNode(tryStart, tryEnd, handler2, "java/lang/Exception"));

        mn.maxLocals = Math.max(mn.maxLocals, deadLocal + 1);
        return true;
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
