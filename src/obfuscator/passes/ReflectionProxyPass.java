package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import java.util.*;

public class ReflectionProxyPass implements ObfuscationPass {

    private static final String[] NAMES = {"do","if","for","new","try","int","go","is","at","of"};

    @Override public String name() { return "ReflectionProxyPass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableReflectionProxy()) return;
        Random rng = new Random(0xCAFE);
        Set<String> userClasses = new HashSet<>();
        for (ClassNode cn : classes) userClasses.add(cn.name);

        int totalDispatched = 0, totalCtors = 0, totalInline = 0;
        int ci = 0;

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;
            List<CallTarget> methodTargets = new ArrayList<>();
            List<CallTarget> inlineTargets = new ArrayList<>();
            List<CtorTarget> ctorTargets = new ArrayList<>();

            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                if ((mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) continue;

                Map<String, Deque<AbstractInsnNode[]>> newStack = new HashMap<>();

                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn.getOpcode() == Opcodes.NEW && insn instanceof TypeInsnNode) {
                        TypeInsnNode t = (TypeInsnNode) insn;
                        AbstractInsnNode next = t.getNext();
                        if (next != null && next.getOpcode() == Opcodes.DUP) {
                            newStack.computeIfAbsent(t.desc, k -> new ArrayDeque<>())
                                .push(new AbstractInsnNode[]{t, next});
                        }
                    } else if (insn instanceof MethodInsnNode) {
                        MethodInsnNode min = (MethodInsnNode) insn;
                        if (min.name.equals("<init>") && min.getOpcode() == Opcodes.INVOKESPECIAL) {
                            Deque<AbstractInsnNode[]> stk = newStack.get(min.owner);
                            if (stk != null && !stk.isEmpty()) {
                                AbstractInsnNode[] pair = stk.pop();
                                if (!userClasses.contains(min.owner) && getCtorType(min.desc) != null) {
                                    ctorTargets.add(new CtorTarget(mn, min, (TypeInsnNode) pair[0], pair[1]));
                                }
                            }
                        } else if (isQualifyingMethod(min, userClasses)) {
                            methodTargets.add(new CallTarget(mn, min));
                        } else if (isNonVoidQualifyingMethod(min, userClasses)) {
                            inlineTargets.add(new CallTarget(mn, min));
                        }
                    }
                }
            }

            if (methodTargets.isEmpty() && inlineTargets.isEmpty() && ctorTargets.isEmpty()) continue;

            Set<String> used = new HashSet<>();
            for (FieldNode fn : cn.fields) used.add(fn.name);
            for (MethodNode mn : cn.methods) used.add(mn.name);

            Crypto sharedCrypto = null;
            if ((!methodTargets.isEmpty() || !inlineTargets.isEmpty()) && config.isEnableReflectiveDispatch()) {
                sharedCrypto = setupCrypto(cn, rng, ci, used);
            }

            if (!methodTargets.isEmpty()) {
                totalDispatched += buildMethodDispatch(cn, methodTargets, rng, ci, used, sharedCrypto);
            }

            if (!inlineTargets.isEmpty() && sharedCrypto != null) {
                for (CallTarget t : inlineTargets) {
                    if (emitInlineReflective(t.method, t.call, cn.name, sharedCrypto)) totalInline++;
                }
            }

            if (!ctorTargets.isEmpty()) {
                totalCtors += buildCtorProxy(cn, ctorTargets, rng, ci, used);
            }
            ci++;
        }
    }

    private boolean isQualifyingMethod(MethodInsnNode min, Set<String> userClasses) {
        if (min.getOpcode() != Opcodes.INVOKEVIRTUAL && min.getOpcode() != Opcodes.INVOKEINTERFACE) return false;
        if (min.name.equals("<init>") || min.name.equals("<clinit>")) return false;
        if (userClasses.contains(min.owner)) return false;
        return getMethodType(min.desc) != null;
    }

    private boolean isNonVoidQualifyingMethod(MethodInsnNode min, Set<String> userClasses) {
        int op = min.getOpcode();
        if (op != Opcodes.INVOKEVIRTUAL && op != Opcodes.INVOKEINTERFACE && op != Opcodes.INVOKESTATIC) return false;
        if (min.name.equals("<init>") || min.name.equals("<clinit>")) return false;
        if (userClasses.contains(min.owner)) return false;
        Type ret = Type.getReturnType(min.desc);
        if (ret.getSort() == Type.VOID) return false;
        if (!isInlineType(ret)) return false;
        for (Type arg : Type.getArgumentTypes(min.desc)) {
            if (!isInlineType(arg)) return false;
        }
        return true;
    }

    private boolean isInlineType(Type t) {
        int s = t.getSort();
        return s == Type.INT || s == Type.BOOLEAN || s == Type.FLOAT
            || s == Type.LONG || s == Type.DOUBLE
            || s == Type.BYTE || s == Type.CHAR || s == Type.SHORT
            || s == Type.OBJECT || s == Type.ARRAY;
    }

    private String getMethodType(String desc) {
        switch (desc) {
            case "(I)V": return "VI";
            case "(F)V": return "VF";
            case "()V": return "V0";
            case "(Z)V": return "VZ";
            case "(IIII)V": return "V4I";
            default:
                if (desc.startsWith("(L") && desc.endsWith(";)V") && desc.indexOf(';') == desc.length() - 3)
                    return "VO";
                return null;
        }
    }

    private String getCtorType(String desc) {
        switch (desc) {
            case "()V": return "C0";
            case "(II)V": return "C2I";
            case "(IIF)V": return "C3IF";
            default:
                if (desc.startsWith("(L") && desc.endsWith(";)V") && desc.indexOf(';') == desc.length() - 3)
                    return "C1";
                return null;
        }
    }

    private String toDispatchType(String methodType) {
        switch (methodType) {
            case "V0": return "D_VOID";
            case "VI": case "VZ": return "D_INT";
            case "VF": return "D_FLOAT";
            case "VO": return "D_OBJ";
            case "V4I": return "D_4INT";
            default: return null;
        }
    }

    private String getDispatchDesc(String dType) {
        switch (dType) {
            case "D_VOID": return "(Ljava/lang/Object;I)V";
            case "D_INT":  return "(Ljava/lang/Object;II)V";
            case "D_FLOAT": return "(Ljava/lang/Object;IF)V";
            case "D_OBJ":  return "(Ljava/lang/Object;ILjava/lang/Object;)V";
            case "D_4INT": return "(Ljava/lang/Object;IIIII)V";
            default: return null;
        }
    }

    private int getDispatchMaxLocals(String dType) {
        switch (dType) {
            case "D_VOID": return 3;
            case "D_INT":  return 4;
            case "D_FLOAT": return 4;
            case "D_OBJ":  return 4;
            case "D_4INT": return 7;
            default: return 8;
        }
    }

    private int buildMethodDispatch(ClassNode cn, List<CallTarget> targets, Random rng, int ci, Set<String> used, Crypto crypto) {
        Map<String, DispatchEntry> uniqueEntries = new LinkedHashMap<>();
        for (CallTarget t : targets) {
            String key = t.call.owner + "." + t.call.name + t.call.desc + "#" + t.call.getOpcode();
            if (!uniqueEntries.containsKey(key)) {
                uniqueEntries.put(key, new DispatchEntry(t.call.owner, t.call.name, t.call.desc, t.call.getOpcode()));
            }
        }

        Map<String, Integer> keyToOpcode = new HashMap<>();
        Set<Integer> usedOpcodes = new HashSet<>();
        for (String key : uniqueEntries.keySet()) {
            int op;
            do { op = rng.nextInt(9000) + 1000; } while (usedOpcodes.contains(op));
            usedOpcodes.add(op);
            keyToOpcode.put(key, op);
        }

        Map<String, Map<Integer, DispatchEntry>> dispatchGroups = new LinkedHashMap<>();
        for (Map.Entry<String, DispatchEntry> e : uniqueEntries.entrySet()) {
            String mType = getMethodType(e.getValue().desc);
            String dType = toDispatchType(mType);
            if (dType == null) continue;
            int opcode = keyToOpcode.get(e.getKey());
            dispatchGroups.computeIfAbsent(dType, k -> new LinkedHashMap<>()).put(opcode, e.getValue());
        }

        Map<String, String> dispatchNames = new HashMap<>();
        int ni = 0;
        for (String dType : dispatchGroups.keySet()) {
            String dName = uniqueName(used, NAMES[(ci * 3 + ni) % NAMES.length]);
            dispatchNames.put(dType, dName);
            addDispatchMethod(cn, dName, dType, dispatchGroups.get(dType), crypto);
            ni++;
        }

        int count = 0;
        for (CallTarget t : targets) {
            String mType = getMethodType(t.call.desc);
            String dType = toDispatchType(mType);
            if (dType == null) continue;
            String dName = dispatchNames.get(dType);
            if (dName == null) continue;
            String key = t.call.owner + "." + t.call.name + t.call.desc + "#" + t.call.getOpcode();
            Integer opcode = keyToOpcode.get(key);
            if (opcode == null) continue;
            if (replaceWithDispatch(t.method, t.call, cn.name, dName, dType, opcode))
                count++;
        }
        return count;
    }

    private void addDispatchMethod(ClassNode cn, String name, String dType, Map<Integer, DispatchEntry> cases, Crypto crypto) {
        String desc = getDispatchDesc(dType);
        MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, name, desc, null, null);
        InsnList ins = new InsnList();

        LabelNode ts = new LabelNode(), te = new LabelNode(), tc = new LabelNode();
        ins.add(ts);

        ins.add(new VarInsnNode(Opcodes.ILOAD, 1));

        List<Map.Entry<Integer, DispatchEntry>> sorted = new ArrayList<>(cases.entrySet());
        sorted.sort(Comparator.comparingInt(Map.Entry::getKey));

        LabelNode defaultLabel = new LabelNode();
        int[] keys = new int[sorted.size()];
        LabelNode[] labels = new LabelNode[sorted.size()];
        for (int i = 0; i < sorted.size(); i++) {
            keys[i] = sorted.get(i).getKey();
            labels[i] = new LabelNode();
        }

        ins.add(new LookupSwitchInsnNode(defaultLabel, keys, labels));

        for (int i = 0; i < sorted.size(); i++) {
            ins.add(labels[i]);
            DispatchEntry entry = sorted.get(i).getValue();

            if (crypto != null) {
                emitReflectiveCall(ins, entry, cn.name, crypto);
            } else {
                ins.add(new VarInsnNode(Opcodes.ALOAD, 0));
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, entry.owner));
                emitArgLoads(ins, dType, entry);
                boolean isItf = entry.invokeKind == Opcodes.INVOKEINTERFACE;
                ins.add(new MethodInsnNode(entry.invokeKind, entry.owner, entry.name, entry.desc, isItf));
            }

            ins.add(new InsnNode(Opcodes.RETURN));
        }

        ins.add(defaultLabel);
        ins.add(te);
        ins.add(new InsnNode(Opcodes.RETURN));
        ins.add(tc);
        ins.add(new InsnNode(Opcodes.POP));
        ins.add(new InsnNode(Opcodes.RETURN));

        m.instructions = ins;
        m.tryCatchBlocks = new ArrayList<>();
        m.tryCatchBlocks.add(new TryCatchBlockNode(ts, te, tc, "java/lang/Exception"));
        m.maxStack = 16;
        m.maxLocals = getDispatchMaxLocals(dType);
        cn.methods.add(m);
    }

    private boolean emitInlineReflective(MethodNode mn, MethodInsnNode call, String className, Crypto crypto) {
        Type[] args = Type.getArgumentTypes(call.desc);
        Type ret = Type.getReturnType(call.desc);
        boolean isStatic = call.getOpcode() == Opcodes.INVOKESTATIC;

        int base = mn.maxLocals;
        int[] argLocals = new int[args.length];
        int cursor = base;
        for (int i = 0; i < args.length; i++) {
            argLocals[i] = cursor;
            cursor += args[i].getSize();
        }
        int objLocal = isStatic ? -1 : cursor++;
        mn.maxLocals = cursor;

        InsnList out = new InsnList();

        for (int i = args.length - 1; i >= 0; i--) {
            out.add(new VarInsnNode(storeOp(args[i]), argLocals[i]));
        }
        if (!isStatic) {
            out.add(new VarInsnNode(Opcodes.ASTORE, objLocal));
        }

        if (isStatic) {
            emitClassOf(out, Type.getObjectType(call.owner), className, crypto);
        } else {
            out.add(new VarInsnNode(Opcodes.ALOAD, objLocal));
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false));
        }

        out.add(new LdcInsnNode(encrypt(call.name, crypto.key, crypto.shift)));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, crypto.decrypt, "(Ljava/lang/String;)Ljava/lang/String;", false));

        out.add(intInsn(args.length));
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Class"));
        for (int i = 0; i < args.length; i++) {
            out.add(new InsnNode(Opcodes.DUP));
            out.add(intInsn(i));
            emitClassOf(out, args[i], className, crypto);
            out.add(new InsnNode(Opcodes.AASTORE));
        }

        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
            "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));

        if (isStatic) {
            out.add(new InsnNode(Opcodes.ACONST_NULL));
        } else {
            out.add(new VarInsnNode(Opcodes.ALOAD, objLocal));
        }

        out.add(intInsn(args.length));
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        for (int i = 0; i < args.length; i++) {
            out.add(new InsnNode(Opcodes.DUP));
            out.add(intInsn(i));
            out.add(new VarInsnNode(loadOp(args[i]), argLocals[i]));
            emitBox(out, args[i]);
            out.add(new InsnNode(Opcodes.AASTORE));
        }

        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
            "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));

        emitCastOrUnbox(out, ret);

        mn.instructions.insertBefore(call, out);
        mn.instructions.remove(call);
        mn.maxStack = Math.max(mn.maxStack, 8);
        return true;
    }

    private int storeOp(Type t) {
        switch (t.getSort()) {
            case Type.INT: case Type.BOOLEAN: case Type.BYTE: case Type.CHAR: case Type.SHORT: return Opcodes.ISTORE;
            case Type.FLOAT: return Opcodes.FSTORE;
            case Type.LONG: return Opcodes.LSTORE;
            case Type.DOUBLE: return Opcodes.DSTORE;
            default: return Opcodes.ASTORE;
        }
    }

    private int loadOp(Type t) {
        switch (t.getSort()) {
            case Type.INT: case Type.BOOLEAN: case Type.BYTE: case Type.CHAR: case Type.SHORT: return Opcodes.ILOAD;
            case Type.FLOAT: return Opcodes.FLOAD;
            case Type.LONG: return Opcodes.LLOAD;
            case Type.DOUBLE: return Opcodes.DLOAD;
            default: return Opcodes.ALOAD;
        }
    }

    private void emitBox(InsnList ins, Type t) {
        switch (t.getSort()) {
            case Type.INT:
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false)); break;
            case Type.BOOLEAN:
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false)); break;
            case Type.FLOAT:
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false)); break;
            case Type.LONG:
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false)); break;
            case Type.DOUBLE:
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false)); break;
            case Type.BYTE:
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false)); break;
            case Type.CHAR:
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false)); break;
            case Type.SHORT:
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false)); break;
            default: break;
        }
    }

    private void emitCastOrUnbox(InsnList ins, Type ret) {
        switch (ret.getSort()) {
            case Type.INT:
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Integer"));
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false)); break;
            case Type.BOOLEAN:
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Boolean"));
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Boolean", "booleanValue", "()Z", false)); break;
            case Type.FLOAT:
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Float"));
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Float", "floatValue", "()F", false)); break;
            case Type.LONG:
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Long"));
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false)); break;
            case Type.DOUBLE:
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Double"));
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Double", "doubleValue", "()D", false)); break;
            case Type.BYTE:
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Byte"));
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Byte", "byteValue", "()B", false)); break;
            case Type.CHAR:
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Character"));
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Character", "charValue", "()C", false)); break;
            case Type.SHORT:
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Short"));
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Short", "shortValue", "()S", false)); break;
            case Type.ARRAY:
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, ret.getDescriptor())); break;
            case Type.OBJECT:
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, ret.getInternalName())); break;
            default: break;
        }
    }

    private void emitReflectiveCall(InsnList ins, DispatchEntry entry, String className, Crypto crypto) {
        ins.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false));
        ins.add(new LdcInsnNode(encrypt(entry.name, crypto.key, crypto.shift)));
        ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, crypto.decrypt, "(Ljava/lang/String;)Ljava/lang/String;", false));
        emitParamTypes(ins, entry, className, crypto);
        ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
            "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));
        ins.add(new VarInsnNode(Opcodes.ALOAD, 0));
        emitArgsObjectArray(ins, entry);
        ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
            "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        ins.add(new InsnNode(Opcodes.POP));
    }

    private void emitParamTypes(InsnList ins, DispatchEntry entry, String className, Crypto crypto) {
        Type[] args = Type.getArgumentTypes(entry.desc);
        ins.add(intInsn(args.length));
        ins.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Class"));
        for (int j = 0; j < args.length; j++) {
            ins.add(new InsnNode(Opcodes.DUP));
            ins.add(intInsn(j));
            emitClassOf(ins, args[j], className, crypto);
            ins.add(new InsnNode(Opcodes.AASTORE));
        }
    }

    private void emitClassOf(InsnList ins, Type t, String className, Crypto crypto) {
        switch (t.getSort()) {
            case Type.INT: ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE", "Ljava/lang/Class;")); break;
            case Type.BOOLEAN: ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Boolean", "TYPE", "Ljava/lang/Class;")); break;
            case Type.FLOAT: ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Float", "TYPE", "Ljava/lang/Class;")); break;
            case Type.LONG: ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Long", "TYPE", "Ljava/lang/Class;")); break;
            case Type.DOUBLE: ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Double", "TYPE", "Ljava/lang/Class;")); break;
            case Type.SHORT: ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Short", "TYPE", "Ljava/lang/Class;")); break;
            case Type.BYTE: ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Byte", "TYPE", "Ljava/lang/Class;")); break;
            case Type.CHAR: ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Character", "TYPE", "Ljava/lang/Class;")); break;
            default: {
                String cn = t.getInternalName().replace('/', '.');
                ins.add(new LdcInsnNode(encrypt(cn, crypto.key, crypto.shift)));
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, crypto.decrypt, "(Ljava/lang/String;)Ljava/lang/String;", false));
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false));
            }
        }
    }

    private void emitArgsObjectArray(InsnList ins, DispatchEntry entry) {
        Type[] args = Type.getArgumentTypes(entry.desc);
        ins.add(intInsn(args.length));
        ins.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        int local = 2;
        for (int j = 0; j < args.length; j++) {
            ins.add(new InsnNode(Opcodes.DUP));
            ins.add(intInsn(j));
            Type t = args[j];
            switch (t.getSort()) {
                case Type.INT: case Type.SHORT: case Type.BYTE: case Type.CHAR:
                    ins.add(new VarInsnNode(Opcodes.ILOAD, local));
                    ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
                    break;
                case Type.BOOLEAN:
                    ins.add(new VarInsnNode(Opcodes.ILOAD, local));
                    ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false));
                    break;
                case Type.FLOAT:
                    ins.add(new VarInsnNode(Opcodes.FLOAD, local));
                    ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false));
                    break;
                default:
                    ins.add(new VarInsnNode(Opcodes.ALOAD, local));
            }
            ins.add(new InsnNode(Opcodes.AASTORE));
            local += t.getSize();
        }
    }

    private Crypto setupCrypto(ClassNode cn, Random rng, int ci, Set<String> used) {
        int key = rng.nextInt(200) + 50;
        int shift = rng.nextInt(5) + 1;
        String keyField = uniqueName(used, NAMES[(ci * 2 + 4) % NAMES.length]);
        String shiftField = uniqueName(used, NAMES[(ci * 2 + 5) % NAMES.length]);
        cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, keyField, "I", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, shiftField, "I", null, null));

        MethodNode clinit = findOrCreateClinit(cn);
        InsnList ki = new InsnList();
        ki.add(new LdcInsnNode(key ^ 0x3D2A));
        ki.add(new LdcInsnNode(0x3D2A));
        ki.add(new InsnNode(Opcodes.IXOR));
        ki.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, keyField, "I"));
        ki.add(new LdcInsnNode(shift + 0x4B1C));
        ki.add(new LdcInsnNode(0x4B1C));
        ki.add(new InsnNode(Opcodes.ISUB));
        ki.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, shiftField, "I"));
        if (clinit.instructions.size() > 0) clinit.instructions.insert(ki);
        else { clinit.instructions.add(ki); clinit.instructions.add(new InsnNode(Opcodes.RETURN)); }

        String decryptName = uniqueName(used, NAMES[(ci + 8) % NAMES.length]);
        addDecryptMethod(cn, decryptName, keyField, shiftField);
        return new Crypto(decryptName, key, shift);
    }

    private void emitArgLoads(InsnList ins, String dType, DispatchEntry entry) {
        switch (dType) {
            case "D_VOID":
                break;
            case "D_INT":
                ins.add(new VarInsnNode(Opcodes.ILOAD, 2));
                break;
            case "D_FLOAT":
                ins.add(new VarInsnNode(Opcodes.FLOAD, 2));
                break;
            case "D_OBJ": {
                String paramType = entry.desc.substring(2, entry.desc.indexOf(';'));
                ins.add(new VarInsnNode(Opcodes.ALOAD, 2));
                ins.add(new TypeInsnNode(Opcodes.CHECKCAST, paramType));
                break;
            }
            case "D_4INT":
                for (int j = 0; j < 4; j++)
                    ins.add(new VarInsnNode(Opcodes.ILOAD, 2 + j));
                break;
        }
    }

    private boolean replaceWithDispatch(MethodNode mn, MethodInsnNode call,
                                         String className, String dispatchName,
                                         String dType, int opcode) {
        InsnList patch = new InsnList();
        int tb = mn.maxLocals;
        String dispatchDesc = getDispatchDesc(dType);

        switch (dType) {
            case "D_VOID":
                patch.add(intInsn(opcode));
                break;
            case "D_INT":
                patch.add(new VarInsnNode(Opcodes.ISTORE, tb));
                patch.add(intInsn(opcode));
                patch.add(new VarInsnNode(Opcodes.ILOAD, tb));
                mn.maxLocals = Math.max(mn.maxLocals, tb + 1);
                break;
            case "D_FLOAT":
                patch.add(new VarInsnNode(Opcodes.FSTORE, tb));
                patch.add(intInsn(opcode));
                patch.add(new VarInsnNode(Opcodes.FLOAD, tb));
                mn.maxLocals = Math.max(mn.maxLocals, tb + 2);
                break;
            case "D_OBJ":
                patch.add(new VarInsnNode(Opcodes.ASTORE, tb));
                patch.add(intInsn(opcode));
                patch.add(new VarInsnNode(Opcodes.ALOAD, tb));
                mn.maxLocals = Math.max(mn.maxLocals, tb + 1);
                break;
            case "D_4INT":
                patch.add(new VarInsnNode(Opcodes.ISTORE, tb + 3));
                patch.add(new VarInsnNode(Opcodes.ISTORE, tb + 2));
                patch.add(new VarInsnNode(Opcodes.ISTORE, tb + 1));
                patch.add(new VarInsnNode(Opcodes.ISTORE, tb));
                patch.add(intInsn(opcode));
                patch.add(new VarInsnNode(Opcodes.ILOAD, tb));
                patch.add(new VarInsnNode(Opcodes.ILOAD, tb + 1));
                patch.add(new VarInsnNode(Opcodes.ILOAD, tb + 2));
                patch.add(new VarInsnNode(Opcodes.ILOAD, tb + 3));
                mn.maxLocals = Math.max(mn.maxLocals, tb + 4);
                break;
            default: return false;
        }
        mn.instructions.insertBefore(call, patch);
        mn.instructions.set(call, new MethodInsnNode(Opcodes.INVOKESTATIC, className, dispatchName, dispatchDesc, false));
        return true;
    }

    private int buildCtorProxy(ClassNode cn, List<CtorTarget> targets, Random rng, int ci, Set<String> used) {
        int classKey = rng.nextInt(200) + 50;
        int classShift = rng.nextInt(5) + 1;

        String keyField = uniqueName(used, NAMES[(ci * 2) % NAMES.length]);
        String shiftField = uniqueName(used, NAMES[(ci * 2 + 1) % NAMES.length]);

        cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, keyField, "I", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, shiftField, "I", null, null));

        MethodNode clinit = findOrCreateClinit(cn);
        InsnList ki = new InsnList();
        ki.add(new LdcInsnNode(classKey ^ 0x3D2A));
        ki.add(new LdcInsnNode(0x3D2A));
        ki.add(new InsnNode(Opcodes.IXOR));
        ki.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, keyField, "I"));
        ki.add(new LdcInsnNode(classShift + 0x4B1C));
        ki.add(new LdcInsnNode(0x4B1C));
        ki.add(new InsnNode(Opcodes.ISUB));
        ki.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, shiftField, "I"));
        if (clinit.instructions.size() > 0) clinit.instructions.insert(ki);
        else { clinit.instructions.add(ki); clinit.instructions.add(new InsnNode(Opcodes.RETURN)); }

        String decryptName = uniqueName(used, NAMES[(ci + 5) % NAMES.length]);
        addDecryptMethod(cn, decryptName, keyField, shiftField);

        Set<String> neededCtorHelpers = new HashSet<>();
        for (CtorTarget t : targets) {
            String h = getCtorType(t.init.desc);
            if (h != null) neededCtorHelpers.add(h);
        }

        Map<String, String> ctorHelperNames = new HashMap<>();
        int hi = 0;
        for (String hType : neededCtorHelpers) {
            String hName = uniqueName(used, NAMES[(ci + 7 + hi) % NAMES.length]);
            ctorHelperNames.put(hType, hName);
            addCtorHelper(cn, hName, hType, decryptName);
            hi++;
        }

        int count = 0;
        for (CtorTarget t : targets) {
            String hType = getCtorType(t.init.desc);
            if (hType == null) continue;
            String hName = ctorHelperNames.get(hType);
            if (hName == null) continue;
            if (replaceCtorCall(t, cn.name, hName, hType, classKey, classShift))
                count++;
        }
        return count;
    }

    private boolean replaceCtorCall(CtorTarget t, String className, String helperName,
                                     String hType, int key, int shift) {
        MethodNode mn = t.method;
        MethodInsnNode init = t.init;
        String encClass = encrypt(init.owner.replace('/', '.'), key, shift);

        mn.instructions.remove(t.newInsn);
        mn.instructions.remove(t.dupInsn);

        InsnList patch = new InsnList();
        String helperDesc;

        switch (hType) {
            case "C0":
                patch.add(new LdcInsnNode(encClass));
                helperDesc = "(Ljava/lang/String;)Ljava/lang/Object;";
                break;
            case "C1": {
                int tb = mn.maxLocals;
                String paramType = init.desc.substring(2, init.desc.indexOf(';')).replace('/', '.');
                patch.add(new VarInsnNode(Opcodes.ASTORE, tb));
                patch.add(new LdcInsnNode(encClass));
                patch.add(new VarInsnNode(Opcodes.ALOAD, tb));
                patch.add(new LdcInsnNode(encrypt(paramType, key, shift)));
                mn.maxLocals = Math.max(mn.maxLocals, tb + 1);
                helperDesc = "(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;";
                break;
            }
            case "C2I": {
                int tb = mn.maxLocals;
                patch.add(new VarInsnNode(Opcodes.ISTORE, tb + 1));
                patch.add(new VarInsnNode(Opcodes.ISTORE, tb));
                patch.add(new LdcInsnNode(encClass));
                patch.add(new VarInsnNode(Opcodes.ILOAD, tb));
                patch.add(new VarInsnNode(Opcodes.ILOAD, tb + 1));
                mn.maxLocals = Math.max(mn.maxLocals, tb + 2);
                helperDesc = "(Ljava/lang/String;II)Ljava/lang/Object;";
                break;
            }
            case "C3IF": {
                int tb = mn.maxLocals;
                patch.add(new VarInsnNode(Opcodes.FSTORE, tb + 2));
                patch.add(new VarInsnNode(Opcodes.ISTORE, tb + 1));
                patch.add(new VarInsnNode(Opcodes.ISTORE, tb));
                patch.add(new LdcInsnNode(encClass));
                patch.add(new VarInsnNode(Opcodes.ILOAD, tb));
                patch.add(new VarInsnNode(Opcodes.ILOAD, tb + 1));
                patch.add(new VarInsnNode(Opcodes.FLOAD, tb + 2));
                mn.maxLocals = Math.max(mn.maxLocals, tb + 3);
                helperDesc = "(Ljava/lang/String;IIF)Ljava/lang/Object;";
                break;
            }
            default: return false;
        }

        mn.instructions.insertBefore(init, patch);

        MethodInsnNode proxyCall = new MethodInsnNode(Opcodes.INVOKESTATIC, className, helperName, helperDesc, false);
        mn.instructions.set(init, proxyCall);
        mn.instructions.insert(proxyCall, new TypeInsnNode(Opcodes.CHECKCAST, t.newInsn.desc));
        return true;
    }

    private void addCtorHelper(ClassNode cn, String name, String type, String decryptName) {
        String desc;
        switch (type) {
            case "C0": desc = "(Ljava/lang/String;)Ljava/lang/Object;"; break;
            case "C1": desc = "(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;"; break;
            case "C2I": desc = "(Ljava/lang/String;II)Ljava/lang/Object;"; break;
            case "C3IF": desc = "(Ljava/lang/String;IIF)Ljava/lang/Object;"; break;
            default: return;
        }
        MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, name, desc, null, null);
        InsnList ins = new InsnList();
        LabelNode ts = new LabelNode(), te = new LabelNode(), tc = new LabelNode();
        ins.add(ts);
        ins.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, decryptName, "(Ljava/lang/String;)Ljava/lang/String;", false));
        ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false));

        switch (type) {
            case "C0":
                buildEmptyParamTypes(ins);
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getConstructor",
                    "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", false));
                buildEmptyArgs(ins);
                break;
            case "C1":
                ins.add(new InsnNode(Opcodes.ICONST_1));
                ins.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Class"));
                ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_0));
                ins.add(new VarInsnNode(Opcodes.ALOAD, 2));
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, decryptName, "(Ljava/lang/String;)Ljava/lang/String;", false));
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false));
                ins.add(new InsnNode(Opcodes.AASTORE));
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getConstructor",
                    "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", false));
                ins.add(new InsnNode(Opcodes.ICONST_1));
                ins.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
                ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_0));
                ins.add(new VarInsnNode(Opcodes.ALOAD, 1));
                ins.add(new InsnNode(Opcodes.AASTORE));
                break;
            case "C2I":
                buildParamTypesNInt(ins, 2);
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getConstructor",
                    "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", false));
                ins.add(new InsnNode(Opcodes.ICONST_2));
                ins.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
                ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_0));
                ins.add(new VarInsnNode(Opcodes.ILOAD, 1));
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
                ins.add(new InsnNode(Opcodes.AASTORE));
                ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_1));
                ins.add(new VarInsnNode(Opcodes.ILOAD, 2));
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
                ins.add(new InsnNode(Opcodes.AASTORE));
                break;
            case "C3IF":
                ins.add(new InsnNode(Opcodes.ICONST_3));
                ins.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Class"));
                ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_0));
                ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE", "Ljava/lang/Class;"));
                ins.add(new InsnNode(Opcodes.AASTORE));
                ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_1));
                ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE", "Ljava/lang/Class;"));
                ins.add(new InsnNode(Opcodes.AASTORE));
                ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_2));
                ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Float", "TYPE", "Ljava/lang/Class;"));
                ins.add(new InsnNode(Opcodes.AASTORE));
                ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getConstructor",
                    "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", false));
                ins.add(new InsnNode(Opcodes.ICONST_3));
                ins.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
                ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_0));
                ins.add(new VarInsnNode(Opcodes.ILOAD, 1));
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
                ins.add(new InsnNode(Opcodes.AASTORE));
                ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_1));
                ins.add(new VarInsnNode(Opcodes.ILOAD, 2));
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
                ins.add(new InsnNode(Opcodes.AASTORE));
                ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_2));
                ins.add(new VarInsnNode(Opcodes.FLOAD, 3));
                ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false));
                ins.add(new InsnNode(Opcodes.AASTORE));
                break;
        }
        ins.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Constructor", "newInstance",
            "([Ljava/lang/Object;)Ljava/lang/Object;", false));
        ins.add(te);
        ins.add(new InsnNode(Opcodes.ARETURN));
        ins.add(tc);
        ins.add(new InsnNode(Opcodes.POP));
        ins.add(new InsnNode(Opcodes.ACONST_NULL));
        ins.add(new InsnNode(Opcodes.ARETURN));
        m.instructions = ins;
        m.tryCatchBlocks = new ArrayList<>();
        m.tryCatchBlocks.add(new TryCatchBlockNode(ts, te, tc, "java/lang/Exception"));
        m.maxStack = 12; m.maxLocals = 6;
        cn.methods.add(m);
    }

    private void addDecryptMethod(ClassNode cn, String name, String keyField, String shiftField) {
        MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, name,
            "(Ljava/lang/String;)Ljava/lang/String;", null, null);
        InsnList i = new InsnList();
        i.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, keyField, "I"));
        i.add(new VarInsnNode(Opcodes.ISTORE, 4));
        i.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, shiftField, "I"));
        i.add(new VarInsnNode(Opcodes.ISTORE, 5));
        i.add(new VarInsnNode(Opcodes.ALOAD, 0));
        i.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false));
        i.add(new VarInsnNode(Opcodes.ASTORE, 1));
        i.add(new VarInsnNode(Opcodes.ALOAD, 1));
        i.add(new InsnNode(Opcodes.ARRAYLENGTH));
        i.add(new VarInsnNode(Opcodes.ISTORE, 3));
        i.add(new InsnNode(Opcodes.ICONST_0));
        i.add(new VarInsnNode(Opcodes.ISTORE, 2));
        LabelNode ls = new LabelNode(), le = new LabelNode();
        i.add(ls);
        i.add(new VarInsnNode(Opcodes.ILOAD, 2));
        i.add(new VarInsnNode(Opcodes.ILOAD, 3));
        i.add(new JumpInsnNode(Opcodes.IF_ICMPGE, le));
        i.add(new VarInsnNode(Opcodes.ALOAD, 1));
        i.add(new VarInsnNode(Opcodes.ILOAD, 2));
        i.add(new VarInsnNode(Opcodes.ALOAD, 1));
        i.add(new VarInsnNode(Opcodes.ILOAD, 2));
        i.add(new InsnNode(Opcodes.CALOAD));
        i.add(new VarInsnNode(Opcodes.ILOAD, 4));
        i.add(new VarInsnNode(Opcodes.ILOAD, 2));
        i.add(new VarInsnNode(Opcodes.ILOAD, 5));
        i.add(new InsnNode(Opcodes.IMUL));
        i.add(new InsnNode(Opcodes.IADD));
        i.add(new InsnNode(Opcodes.IXOR));
        i.add(new InsnNode(Opcodes.I2C));
        i.add(new InsnNode(Opcodes.CASTORE));
        i.add(new IincInsnNode(2, 1));
        i.add(new JumpInsnNode(Opcodes.GOTO, ls));
        i.add(le);
        i.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        i.add(new InsnNode(Opcodes.DUP));
        i.add(new VarInsnNode(Opcodes.ALOAD, 1));
        i.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false));
        i.add(new InsnNode(Opcodes.ARETURN));
        m.instructions = i;
        m.maxStack = 8; m.maxLocals = 6;
        cn.methods.add(m);
    }

    private void buildParamTypesNInt(InsnList ins, int n) {
        ins.add(new InsnNode(Opcodes.ICONST_0 + n));
        ins.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Class"));
        for (int j = 0; j < n; j++) {
            ins.add(new InsnNode(Opcodes.DUP)); ins.add(new InsnNode(Opcodes.ICONST_0 + j));
            ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE", "Ljava/lang/Class;"));
            ins.add(new InsnNode(Opcodes.AASTORE));
        }
    }
    private void buildEmptyParamTypes(InsnList ins) {
        ins.add(new InsnNode(Opcodes.ICONST_0));
        ins.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Class"));
    }
    private void buildEmptyArgs(InsnList ins) {
        ins.add(new InsnNode(Opcodes.ICONST_0));
        ins.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
    }

    private static AbstractInsnNode intInsn(int val) {
        if (val >= -1 && val <= 5) return new InsnNode(Opcodes.ICONST_0 + val);
        if (val >= Byte.MIN_VALUE && val <= Byte.MAX_VALUE) return new IntInsnNode(Opcodes.BIPUSH, val);
        if (val >= Short.MIN_VALUE && val <= Short.MAX_VALUE) return new IntInsnNode(Opcodes.SIPUSH, val);
        return new LdcInsnNode(val);
    }

    private String encrypt(String s, int key, int shift) {
        char[] c = s.toCharArray();
        for (int i = 0; i < c.length; i++) c[i] = (char)(c[i] ^ (key + i * shift));
        return new String(c);
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

    private static class CallTarget {
        MethodNode method; MethodInsnNode call;
        CallTarget(MethodNode m, MethodInsnNode c) { method = m; call = c; }
    }

    private static class CtorTarget {
        MethodNode method; MethodInsnNode init;
        TypeInsnNode newInsn; AbstractInsnNode dupInsn;
        CtorTarget(MethodNode m, MethodInsnNode i, TypeInsnNode n, AbstractInsnNode d) {
            method = m; init = i; newInsn = n; dupInsn = d;
        }
    }

    private static class DispatchEntry {
        String owner;
        String name;
        String desc;
        int invokeKind;
        DispatchEntry(String owner, String name, String desc, int invokeKind) {
            this.owner = owner; this.name = name; this.desc = desc; this.invokeKind = invokeKind;
        }
    }

    private static class Crypto {
        final String decrypt;
        final int key;
        final int shift;
        Crypto(String decrypt, int key, int shift) { this.decrypt = decrypt; this.key = key; this.shift = shift; }
    }
}
