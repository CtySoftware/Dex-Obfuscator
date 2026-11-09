package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import java.util.*;

public class IrreducibleFlowPass implements ObfuscationPass {

    private static final String[] FIELD_NAMES = {
        "byte", "case", "char", "else", "enum", "goto", "long", "null", "this", "void"
    };

    @Override
    public String name() { return "IrreducibleFlowPass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableIrreducibleFlow()) return;

        Random rng = new Random(System.nanoTime() ^ 0x1BADB002C0FFEEL);
        int classIdx = 0;

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;

            Map<MethodNode, List<AbstractInsnNode>> plan = new LinkedHashMap<>();
            for (MethodNode mn : cn.methods) {
                if (!eligible(mn)) continue;
                List<AbstractInsnNode> pts = collectSafePoints(mn);
                Collections.shuffle(pts, rng);
                int cap = Math.min(pts.size(), 30);
                plan.put(mn, new ArrayList<>(pts.subList(0, cap)));
            }

            if (plan.isEmpty()) continue;

            Set<String> used = new HashSet<>();
            for (FieldNode fn : cn.fields) used.add(fn.name);
            for (MethodNode mn : cn.methods) used.add(mn.name);

            String guardField = uniqueName(used, FIELD_NAMES[classIdx % FIELD_NAMES.length]);
            classIdx++;

            int guardValue = pickGuardValue(rng);
            cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, guardField, "I", null, null));

            MethodNode clinit = findOrCreateClinit(cn);
            InsnList init = buildGuardInit(cn.name, guardField, guardValue, rng);
            if (clinit.instructions.size() > 0) {
                clinit.instructions.insert(init);
            } else {
                clinit.instructions.add(init);
                clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            }

            for (Map.Entry<MethodNode, List<AbstractInsnNode>> e : plan.entrySet()) {
                MethodNode mn = e.getKey();
                AbstractInsnNode first = mn.instructions.getFirst();
                InsnList head = buildTangle(cn.name, guardField, rng);
                if (first != null) mn.instructions.insertBefore(first, head);
                else mn.instructions.add(head);
                for (AbstractInsnNode point : e.getValue()) {
                    mn.instructions.insert(point, buildGadget(cn.name, guardField, rng));
                }
                mn.maxStack = Math.max(mn.maxStack, 4);
            }
        }
    }

    private boolean eligible(MethodNode mn) {
        if (mn.instructions == null) return false;
        int size = mn.instructions.size();
        if (size < 6 || size > 8000) return false;
        if (mn.name.equals("<init>")) return false;
        if ((mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) return false;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int op = insn.getOpcode();
            if (op == Opcodes.JSR || op == Opcodes.RET) return false;
        }
        return true;
    }

    private List<AbstractInsnNode> collectSafePoints(MethodNode mn) {
        List<AbstractInsnNode> result = new ArrayList<>();
        AbstractInsnNode[] arr = mn.instructions.toArray();
        int n = arr.length;
        if (n < 3) return result;

        Map<AbstractInsnNode, Integer> idx = new HashMap<>();
        for (int i = 0; i < n; i++) idx.put(arr[i], i);

        int[] depth = new int[n];
        Arrays.fill(depth, -1);
        Deque<Integer> work = new ArrayDeque<>();

        depth[0] = 0;
        work.add(0);
        if (mn.tryCatchBlocks != null) {
            for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                Integer h = idx.get(tcb.handler);
                if (h != null && depth[h] == -1) {
                    depth[h] = 1;
                    work.add(h);
                }
            }
        }

        while (!work.isEmpty()) {
            int i = work.poll();
            AbstractInsnNode insn = arr[i];
            int after = depth[i] + stackEffect(insn);
            if (after < 0) after = 0;

            for (int s : successors(insn, i, idx)) {
                if (s < 0 || s >= n) continue;
                if (depth[s] == -1) {
                    depth[s] = after;
                    work.add(s);
                }
            }
        }

        for (int i = 0; i < n; i++) {
            AbstractInsnNode cur = arr[i];
            if (depth[i] < 0) continue;
            if (!isStatementBoundary(cur)) continue;
            AbstractInsnNode next = cur.getNext();
            if (next == null) continue;
            Integer ni = idx.get(next);
            if (ni == null) continue;
            if (depth[ni] != 0) continue;
            result.add(cur);
        }
        return result;
    }

    private List<Integer> successors(AbstractInsnNode insn, int i, Map<AbstractInsnNode, Integer> idx) {
        List<Integer> out = new ArrayList<>();
        int op = insn.getOpcode();

        if (insn instanceof JumpInsnNode) {
            Integer t = idx.get(((JumpInsnNode) insn).label);
            if (t != null) out.add(t);
            if (op != Opcodes.GOTO) out.add(i + 1);
            return out;
        }
        if (insn instanceof TableSwitchInsnNode) {
            TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
            Integer d = idx.get(ts.dflt);
            if (d != null) out.add(d);
            for (LabelNode l : ts.labels) {
                Integer t = idx.get(l);
                if (t != null) out.add(t);
            }
            return out;
        }
        if (insn instanceof LookupSwitchInsnNode) {
            LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
            Integer d = idx.get(ls.dflt);
            if (d != null) out.add(d);
            for (LabelNode l : ls.labels) {
                Integer t = idx.get(l);
                if (t != null) out.add(t);
            }
            return out;
        }
        if (op == Opcodes.IRETURN || op == Opcodes.LRETURN || op == Opcodes.FRETURN
            || op == Opcodes.DRETURN || op == Opcodes.ARETURN || op == Opcodes.RETURN
            || op == Opcodes.ATHROW) {
            return out;
        }
        out.add(i + 1);
        return out;
    }

    private boolean isStatementBoundary(AbstractInsnNode insn) {
        int op = insn.getOpcode();
        if (op >= Opcodes.ISTORE && op <= Opcodes.ASTORE) return true;
        if (op == Opcodes.PUTSTATIC || op == Opcodes.PUTFIELD) return true;
        if (op == Opcodes.POP || op == Opcodes.POP2) return true;
        if (op == Opcodes.MONITORENTER || op == Opcodes.MONITOREXIT) return true;
        if (insn instanceof MethodInsnNode) {
            return (Type.getReturnType(((MethodInsnNode) insn).desc) == Type.VOID_TYPE);
        }
        return false;
    }

    private int stackEffect(AbstractInsnNode insn) {
        int op = insn.getOpcode();
        if (op < 0) return 0;

        if (insn instanceof FieldInsnNode) {
            int sz = Type.getType(((FieldInsnNode) insn).desc).getSize();
            switch (op) {
                case Opcodes.GETSTATIC: return sz;
                case Opcodes.PUTSTATIC: return -sz;
                case Opcodes.GETFIELD: return sz - 1;
                case Opcodes.PUTFIELD: return -sz - 1;
            }
        }
        if (insn instanceof MethodInsnNode) {
            String desc = ((MethodInsnNode) insn).desc;
            int sizes = Type.getArgumentsAndReturnSizes(desc);
            int argSize = sizes >> 2;
            int retSize = sizes & 0x03;
            boolean stat = op == Opcodes.INVOKESTATIC;
            int popped = stat ? argSize - 1 : argSize;
            return retSize - popped;
        }
        if (insn instanceof InvokeDynamicInsnNode) {
            String desc = ((InvokeDynamicInsnNode) insn).desc;
            int sizes = Type.getArgumentsAndReturnSizes(desc);
            int argSize = sizes >> 2;
            int retSize = sizes & 0x03;
            return retSize - (argSize - 1);
        }
        if (insn instanceof LdcInsnNode) {
            Object c = ((LdcInsnNode) insn).cst;
            return (c instanceof Long || c instanceof Double) ? 2 : 1;
        }
        if (insn instanceof MultiANewArrayInsnNode) {
            return 1 - ((MultiANewArrayInsnNode) insn).dims;
        }

        switch (op) {
            case Opcodes.NOP:
            case Opcodes.INEG: case Opcodes.LNEG: case Opcodes.FNEG: case Opcodes.DNEG:
            case Opcodes.I2B: case Opcodes.I2C: case Opcodes.I2S:
            case Opcodes.I2F: case Opcodes.L2D: case Opcodes.F2I: case Opcodes.D2L:
            case Opcodes.SWAP: case Opcodes.IINC:
            case Opcodes.GOTO: case Opcodes.RET: case Opcodes.RETURN:
            case Opcodes.NEWARRAY: case Opcodes.ANEWARRAY: case Opcodes.ARRAYLENGTH:
            case Opcodes.CHECKCAST: case Opcodes.INSTANCEOF:
            case Opcodes.LALOAD: case Opcodes.DALOAD:
                return 0;

            case Opcodes.ACONST_NULL:
            case Opcodes.ICONST_M1: case Opcodes.ICONST_0: case Opcodes.ICONST_1:
            case Opcodes.ICONST_2: case Opcodes.ICONST_3: case Opcodes.ICONST_4: case Opcodes.ICONST_5:
            case Opcodes.FCONST_0: case Opcodes.FCONST_1: case Opcodes.FCONST_2:
            case Opcodes.BIPUSH: case Opcodes.SIPUSH:
            case Opcodes.ILOAD: case Opcodes.FLOAD: case Opcodes.ALOAD:
            case Opcodes.DUP: case Opcodes.DUP_X1: case Opcodes.DUP_X2:
            case Opcodes.I2L: case Opcodes.I2D: case Opcodes.F2L: case Opcodes.F2D:
            case Opcodes.JSR: case Opcodes.NEW:
                return 1;

            case Opcodes.LCONST_0: case Opcodes.LCONST_1:
            case Opcodes.DCONST_0: case Opcodes.DCONST_1:
            case Opcodes.LLOAD: case Opcodes.DLOAD:
            case Opcodes.DUP2: case Opcodes.DUP2_X1: case Opcodes.DUP2_X2:
                return 2;

            case Opcodes.ISTORE: case Opcodes.FSTORE: case Opcodes.ASTORE:
            case Opcodes.POP:
            case Opcodes.IADD: case Opcodes.FADD: case Opcodes.ISUB: case Opcodes.FSUB:
            case Opcodes.IMUL: case Opcodes.FMUL: case Opcodes.IDIV: case Opcodes.FDIV:
            case Opcodes.IREM: case Opcodes.FREM:
            case Opcodes.ISHL: case Opcodes.ISHR: case Opcodes.IUSHR:
            case Opcodes.LSHL: case Opcodes.LSHR: case Opcodes.LUSHR:
            case Opcodes.IAND: case Opcodes.IOR: case Opcodes.IXOR:
            case Opcodes.L2I: case Opcodes.L2F: case Opcodes.D2I: case Opcodes.D2F:
            case Opcodes.FCMPL: case Opcodes.FCMPG:
            case Opcodes.IALOAD: case Opcodes.FALOAD: case Opcodes.AALOAD:
            case Opcodes.BALOAD: case Opcodes.CALOAD: case Opcodes.SALOAD:
            case Opcodes.IFEQ: case Opcodes.IFNE: case Opcodes.IFLT: case Opcodes.IFGE:
            case Opcodes.IFGT: case Opcodes.IFLE: case Opcodes.IFNULL: case Opcodes.IFNONNULL:
            case Opcodes.IRETURN: case Opcodes.FRETURN: case Opcodes.ARETURN:
            case Opcodes.TABLESWITCH: case Opcodes.LOOKUPSWITCH:
            case Opcodes.ATHROW: case Opcodes.MONITORENTER: case Opcodes.MONITOREXIT:
                return -1;

            case Opcodes.LSTORE: case Opcodes.DSTORE:
            case Opcodes.POP2:
            case Opcodes.LADD: case Opcodes.DADD: case Opcodes.LSUB: case Opcodes.DSUB:
            case Opcodes.LMUL: case Opcodes.DMUL: case Opcodes.LDIV: case Opcodes.DDIV:
            case Opcodes.LREM: case Opcodes.DREM:
            case Opcodes.LAND: case Opcodes.LOR: case Opcodes.LXOR:
            case Opcodes.IF_ICMPEQ: case Opcodes.IF_ICMPNE: case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE: case Opcodes.IF_ICMPGT: case Opcodes.IF_ICMPLE:
            case Opcodes.IF_ACMPEQ: case Opcodes.IF_ACMPNE:
            case Opcodes.LRETURN: case Opcodes.DRETURN:
                return -2;

            case Opcodes.IASTORE: case Opcodes.FASTORE: case Opcodes.AASTORE:
            case Opcodes.BASTORE: case Opcodes.CASTORE: case Opcodes.SASTORE:
            case Opcodes.LCMP: case Opcodes.DCMPL: case Opcodes.DCMPG:
                return -3;

            case Opcodes.LASTORE: case Opcodes.DASTORE:
                return -4;
        }
        return 0;
    }

    private InsnList buildTangle(String owner, String field, Random rng) {
        int k = 4 + rng.nextInt(3);
        LabelNode[] b = new LabelNode[k];
        for (int i = 0; i < k; i++) b[i] = new LabelNode();
        LabelNode exit = new LabelNode();

        InsnList g = new InsnList();
        for (int i = 0; i < k; i++) {
            g.add(b[i]);
            LabelNode next = (i + 1 < k) ? b[i + 1] : exit;
            emitOpaqueTrue(g, owner, field, next, rng);
            int dead = 2 + rng.nextInt(2);
            for (int d = 0; d < dead; d++) {
                emitOpaqueFalse(g, owner, field, b[rng.nextInt(k)], rng);
            }
            g.add(new JumpInsnNode(Opcodes.GOTO, b[rng.nextInt(k)]));
        }
        g.add(exit);
        return g;
    }

    private InsnList buildGadget(String owner, String field, Random rng) {
        InsnList g = new InsnList();
        LabelNode a = new LabelNode();
        LabelNode b = new LabelNode();
        LabelNode exit = new LabelNode();

        emitOpaqueFalse(g, owner, field, b, rng);
        g.add(a);
        emitOpaqueFalse(g, owner, field, exit, rng);
        g.add(new JumpInsnNode(Opcodes.GOTO, b));
        g.add(b);
        emitOpaqueTrue(g, owner, field, exit, rng);
        g.add(new JumpInsnNode(Opcodes.GOTO, a));
        g.add(exit);
        return g;
    }

    private void emitOpaqueFalse(InsnList g, String owner, String field, LabelNode target, Random rng) {
        if (rng.nextBoolean()) {
            g.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, field, "I"));
            g.add(intInsn(7));
            g.add(new InsnNode(Opcodes.IREM));
            g.add(intInsn(3));
            g.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, target));
        } else {
            g.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, field, "I"));
            g.add(new InsnNode(Opcodes.ICONST_1));
            g.add(new InsnNode(Opcodes.IOR));
            g.add(new InsnNode(Opcodes.ICONST_1));
            g.add(new InsnNode(Opcodes.IAND));
            g.add(new JumpInsnNode(Opcodes.IFEQ, target));
        }
    }

    private void emitOpaqueTrue(InsnList g, String owner, String field, LabelNode target, Random rng) {
        if (rng.nextBoolean()) {
            g.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, field, "I"));
            g.add(intInsn(7));
            g.add(new InsnNode(Opcodes.IREM));
            g.add(intInsn(3));
            g.add(new JumpInsnNode(Opcodes.IF_ICMPNE, target));
        } else {
            g.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, field, "I"));
            g.add(new InsnNode(Opcodes.ICONST_1));
            g.add(new InsnNode(Opcodes.IOR));
            g.add(new InsnNode(Opcodes.ICONST_1));
            g.add(new InsnNode(Opcodes.IAND));
            g.add(new JumpInsnNode(Opcodes.IFNE, target));
        }
    }

    private int pickGuardValue(Random rng) {
        int v;
        do {
            v = rng.nextInt(0x7FFF) + 0x100;
        } while (v % 7 == 3);
        return v;
    }

    private InsnList buildGuardInit(String owner, String field, int value, Random rng) {
        InsnList ins = new InsnList();
        int mask = rng.nextInt(0xFFFF) + 1;
        int rot = rng.nextInt(13) + 2;
        ins.add(new LdcInsnNode(Integer.rotateLeft(value, rot) ^ mask));
        ins.add(new LdcInsnNode(mask));
        ins.add(new InsnNode(Opcodes.IXOR));
        ins.add(new LdcInsnNode(rot));
        ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "rotateRight", "(II)I", false));
        ins.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner, field, "I"));
        return ins;
    }

    private MethodNode findOrCreateClinit(ClassNode cn) {
        for (MethodNode mn : cn.methods) if (mn.name.equals("<clinit>")) return mn;
        MethodNode c = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        c.instructions = new InsnList();
        c.maxStack = 4;
        c.maxLocals = 0;
        cn.methods.add(c);
        return c;
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
}
