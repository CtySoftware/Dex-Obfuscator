package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class StringEncryptPass implements ObfuscationPass {

    private static final String[] DEC_NAMES = {"do","if","for","new","try","int","go","is","at","of"};
    private static final String[] FIELD_NAMES = {"byte","case","char","else","enum","goto","long","null","this","void"};
    private static final int MAX_INTS_PER_METHOD = 30;

    @Override public String name() { return "StringEncryptPass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableStringEncryption()) return;
        Random rng = new Random(0xDEADCAFEL ^ System.currentTimeMillis());
        int count = 0, classIdx = 0;
        List<ClassNode> poolsToInject = new ArrayList<>();

        for (ClassNode cn : classes) {
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) {
                continue;
            }

            List<StringTarget> targets = new ArrayList<>();
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                if (isDecoderOrHelper(mn.name)) continue;
                int ordinal = 0;
                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode) {
                        LdcInsnNode ldc = (LdcInsnNode) insn;
                        if (ldc.cst instanceof String && !((String)ldc.cst).isEmpty()) {
                            String s = (String) ldc.cst;
                            int callsiteId = murmur3Mix(
                                cn.name.hashCode(),
                                (mn.name + mn.desc).hashCode(),
                                ordinal
                            );
                            List<String> chunks = null;
                            if (isCriticalString(s) && s.length() >= 6) {
                                chunks = new ArrayList<>();
                                int chunkLen = Math.max(2, s.length() / 3);
                                for (int i = 0; i < s.length(); i += chunkLen) {
                                    chunks.add(s.substring(i, Math.min(i + chunkLen, s.length())));
                                }
                            }
                            targets.add(new StringTarget(mn, ldc, callsiteId, ordinal, chunks));
                            ordinal++;
                        }
                    }
                }
            }
            if (targets.isEmpty()) continue;

            Set<String> used = new HashSet<>();
            for (FieldNode fn : cn.fields) used.add(fn.name);
            for (MethodNode mn : cn.methods) used.add(mn.name);

            Random classRng = new Random(rng.nextLong());
            int classKey = classRng.nextInt(0x7FFFFFFF) + 1;
            int xorSeed = classRng.nextInt(0x7FFFFFFF) + 1;
            int rotAmount = classRng.nextInt(6) + 1;
            boolean rotateLeft = classRng.nextBoolean();
            boolean reverseBytes = classRng.nextBoolean();
            int lenXor = classRng.nextInt(0xFF) + 1;
            int offsetMask = classRng.nextInt(0xFFFF) + 1;

            int paddingStart = classRng.nextInt(17) + 8;
            int bytesOffset = classRng.nextInt(2) + 1;
            boolean highOffset = classRng.nextBoolean();
            int offsetForm = classRng.nextInt(3);
            int keyForm = classRng.nextInt(3);

            List<int[]> allCipherData = new ArrayList<>();
            int offset = 0;

            Map<StringTarget, Integer> singleOffsets = new HashMap<>();
            Map<StringTarget, List<Integer>> chunkOffsetsMap = new HashMap<>();
            Map<StringTarget, List<Integer>> chunkCallsitesMap = new HashMap<>();

            for (StringTarget t : targets) {
                if (t.chunks == null) {
                    byte[] plainBytes = ((String)t.ldc.cst).getBytes(StandardCharsets.UTF_8);
                    int len = plainBytes.length;

                    byte[] cipherBytes = new byte[len];
                    for (int i = 0; i < len; i++) {
                        int b = plainBytes[i] & 0xFF;
                        int key = 0;
                        if (keyForm == 0) {
                            key = (xorSeed ^ i) * 0x9E3779B9 + classKey + t.callsiteId;
                        } else if (keyForm == 1) {
                            key = (xorSeed + i) * 0x7F4A7C15 ^ classKey ^ t.callsiteId;
                        } else if (keyForm == 2) {
                            key = (xorSeed ^ ~i) * 0x517CC1B7 - classKey + t.callsiteId;
                        }
                        b ^= (key & 0xFF);
                        if (rotateLeft) {
                            b = ((b << rotAmount) | (b >>> (8 - rotAmount))) & 0xFF;
                        } else {
                            b = ((b >>> rotAmount) | (b << (8 - rotAmount))) & 0xFF;
                        }
                        cipherBytes[i] = (byte) b;
                    }
                    if (reverseBytes) {
                        for (int i = 0; i < len / 2; i++) {
                            byte temp = cipherBytes[i];
                            cipherBytes[i] = cipherBytes[len - 1 - i];
                            cipherBytes[len - 1 - i] = temp;
                        }
                    }

                    int[] cipherInts = buildCipherInts(cipherBytes, len, lenXor, t.callsiteId, bytesOffset, classRng);
                    allCipherData.add(cipherInts);
                    singleOffsets.put(t, offset + paddingStart);
                    offset += cipherInts.length;
                } else {
                    List<Integer> chunkOffsets = new ArrayList<>();
                    List<Integer> chunkCallsites = new ArrayList<>();
                    int ord = 0;
                    for (String chunk : t.chunks) {
                        int chunkCallsiteId = murmur3Mix(t.callsiteId, ord, 0x1337C0DE);
                        chunkCallsites.add(chunkCallsiteId);

                        byte[] plainBytes = chunk.getBytes(StandardCharsets.UTF_8);
                        int len = plainBytes.length;

                        byte[] cipherBytes = new byte[len];
                        for (int i = 0; i < len; i++) {
                            int b = plainBytes[i] & 0xFF;
                            int key = 0;
                            if (keyForm == 0) {
                                key = (xorSeed ^ i) * 0x9E3779B9 + classKey + chunkCallsiteId;
                            } else if (keyForm == 1) {
                                key = (xorSeed + i) * 0x7F4A7C15 ^ classKey ^ chunkCallsiteId;
                            } else if (keyForm == 2) {
                                key = (xorSeed ^ ~i) * 0x517CC1B7 - classKey + chunkCallsiteId;
                            }
                            b ^= (key & 0xFF);
                            if (rotateLeft) {
                                b = ((b << rotAmount) | (b >>> (8 - rotAmount))) & 0xFF;
                            } else {
                                b = ((b >>> rotAmount) | (b << (8 - rotAmount))) & 0xFF;
                            }
                            cipherBytes[i] = (byte) b;
                        }
                        if (reverseBytes) {
                            for (int i = 0; i < len / 2; i++) {
                                byte temp = cipherBytes[i];
                                cipherBytes[i] = cipherBytes[len - 1 - i];
                                cipherBytes[len - 1 - i] = temp;
                            }
                        }

                        int[] cipherInts = buildCipherInts(cipherBytes, len, lenXor, chunkCallsiteId, bytesOffset, classRng);
                        allCipherData.add(cipherInts);
                        chunkOffsets.add(offset + paddingStart);
                        offset += cipherInts.length;
                        ord++;
                    }
                    chunkOffsetsMap.put(t, chunkOffsets);
                    chunkCallsitesMap.put(t, chunkCallsites);
                }
            }

            String poolClassName = cn.name + "_Pool";
            ClassNode poolCn = new ClassNode();
            poolCn.version = cn.version;
            poolCn.access = Opcodes.ACC_SUPER;
            poolCn.name = poolClassName;
            poolCn.superName = "java/lang/Object";
            poolCn.fields = new ArrayList<>();
            poolCn.methods = new ArrayList<>();

            MethodNode init = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
            init.instructions = new InsnList();
            init.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            init.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
            init.instructions.add(new InsnNode(Opcodes.RETURN));
            init.maxStack = 1;
            init.maxLocals = 1;
            poolCn.methods.add(init);

            String decName = uniqueName(used, DEC_NAMES[classIdx % DEC_NAMES.length]);
            String dataFieldName = uniqueName(used, FIELD_NAMES[(classIdx + 3) % FIELD_NAMES.length]);

            poolCn.fields.add(new FieldNode(Opcodes.ACC_STATIC, dataFieldName, "[I", null, null));

            String initPoolMethodName = uniqueName(used, "_init_pool");

            int totalPoolSize = Math.max(64 + classRng.nextInt(32), offset + paddingStart);
            int[] allInts = new int[totalPoolSize];
            for (int i = 0; i < totalPoolSize; i++) {
                allInts[i] = classRng.nextInt();
            }

            int pos = paddingStart;
            for (int[] chunk : allCipherData) {
                for (int val : chunk) {
                    allInts[pos++] = val;
                }
            }

            addPoolInitializer(poolCn, poolClassName, initPoolMethodName, dataFieldName, allInts, used, classRng);
            addDecoder(cn, decName, poolClassName, dataFieldName, initPoolMethodName, xorSeed, classKey, lenXor, offsetMask, rotateLeft, rotAmount, reverseBytes, bytesOffset, highOffset, offsetForm, keyForm);

            poolsToInject.add(poolCn);

            for (StringTarget t : targets) {
                InsnList patch = new InsnList();
                if (t.chunks == null) {
                    int off = singleOffsets.get(t);
                    int encodedOffset = 0;
                    if (offsetForm == 0) {
                        encodedOffset = (off + t.callsiteId) ^ offsetMask;
                    } else if (offsetForm == 1) {
                        encodedOffset = (off - t.callsiteId) ^ offsetMask;
                    } else if (offsetForm == 2) {
                        encodedOffset = off ^ offsetMask ^ t.callsiteId;
                    }

                    long packed = 0;
                    if (highOffset) {
                        packed = ((long) encodedOffset << 32) | (t.callsiteId & 0xFFFFFFFFL);
                    } else {
                        packed = ((long) t.callsiteId << 32) | (encodedOffset & 0xFFFFFFFFL);
                    }
                    long mask = classRng.nextLong();
                    patch.add(new LdcInsnNode(packed ^ mask));
                    patch.add(new LdcInsnNode(mask));
                    patch.add(new InsnNode(Opcodes.LXOR));

                    patch.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, decName,
                        "(J)Ljava/lang/String;", false));
                } else {
                    List<Integer> chunkOffs = chunkOffsetsMap.get(t);
                    List<Integer> chunkCallsites = chunkCallsitesMap.get(t);

                    patch.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
                    patch.add(new InsnNode(Opcodes.DUP));
                    patch.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));

                    for (int c = 0; c < t.chunks.size(); c++) {
                        int chunkOff = chunkOffs.get(c);
                        int chunkCallsite = chunkCallsites.get(c);
                        int encodedOffset = 0;
                        if (offsetForm == 0) {
                            encodedOffset = (chunkOff + chunkCallsite) ^ offsetMask;
                        } else if (offsetForm == 1) {
                            encodedOffset = (chunkOff - chunkCallsite) ^ offsetMask;
                        } else if (offsetForm == 2) {
                            encodedOffset = chunkOff ^ offsetMask ^ chunkCallsite;
                        }

                        long packed = 0;
                        if (highOffset) {
                            packed = ((long) encodedOffset << 32) | (chunkCallsite & 0xFFFFFFFFL);
                        } else {
                            packed = ((long) chunkCallsite << 32) | (encodedOffset & 0xFFFFFFFFL);
                        }
                        long mask = classRng.nextLong();
                        patch.add(new LdcInsnNode(packed ^ mask));
                        patch.add(new LdcInsnNode(mask));
                        patch.add(new InsnNode(Opcodes.LXOR));

                        patch.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, decName,
                            "(J)Ljava/lang/String;", false));
                        patch.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                            "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                    }
                    patch.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                        "()Ljava/lang/String;", false));
                }

                registry.addStringMapping(cn.name, t.method.name, (String) t.ldc.cst);
                t.method.instructions.insertBefore(t.ldc, patch);
                t.method.instructions.remove(t.ldc);
                count++;
            }
            classIdx++;
        }

        classes.addAll(poolsToInject);
    }

    private int[] buildCipherInts(byte[] cipherBytes, int len, int lenXor, int callsiteId, int bytesOffset, Random classRng) {
        int numInts = (len + 3) / 4;
        int[] cipherInts = new int[bytesOffset + numInts];
        cipherInts[0] = len ^ lenXor ^ callsiteId;
        if (bytesOffset == 2) {
            cipherInts[1] = classRng.nextInt();
        }
        for (int i = 0; i < len; i++) {
            int b = cipherBytes[i] & 0xFF;
            int idx = bytesOffset + (i / 4);
            cipherInts[idx] |= (b << ((i % 4) * 8));
        }
        return cipherInts;
    }

    private void addPoolInitializer(ClassNode poolCn, String poolClassName, String initPoolMethodName, String dataFieldName, int[] allInts, Set<String> used, Random classRng) {
        int totalSize = allInts.length;
        int numMethods = (totalSize + MAX_INTS_PER_METHOD - 1) / MAX_INTS_PER_METHOD;

        List<String> helperNames = new ArrayList<>();
        for (int m = 0; m < numMethods; m++) {
            String helperName = uniqueName(used, DEC_NAMES[classRng.nextInt(DEC_NAMES.length)] + "_" + DEC_NAMES[classRng.nextInt(DEC_NAMES.length)]);
            helperNames.add(helperName);

            int start = m * MAX_INTS_PER_METHOD;
            int end = Math.min(start + MAX_INTS_PER_METHOD, totalSize);

            MethodNode helper = new MethodNode(Opcodes.ACC_STATIC, helperName, "([I)V", null, null);
            InsnList hIns = new InsnList();
            for (int i = start; i < end; i++) {
                hIns.add(new VarInsnNode(Opcodes.ALOAD, 0));
                hIns.add(loadInt(i));
                hIns.add(loadInt(allInts[i]));
                hIns.add(new InsnNode(Opcodes.IASTORE));
            }
            hIns.add(new InsnNode(Opcodes.RETURN));
            helper.instructions = hIns;
            helper.maxStack = 4;
            helper.maxLocals = 1;
            poolCn.methods.add(helper);
        }

        MethodNode initPool = new MethodNode(Opcodes.ACC_STATIC, initPoolMethodName, "()V", null, null);
        InsnList ins = new InsnList();
        ins.add(loadInt(totalSize));
        ins.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        ins.add(new FieldInsnNode(Opcodes.PUTSTATIC, poolClassName, dataFieldName, "[I"));

        for (int m = 0; m < numMethods; m++) {
            ins.add(new FieldInsnNode(Opcodes.GETSTATIC, poolClassName, dataFieldName, "[I"));
            ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, poolClassName, helperNames.get(m), "([I)V", false));
        }
        ins.add(new InsnNode(Opcodes.RETURN));
        initPool.instructions = ins;
        initPool.maxStack = 4;
        initPool.maxLocals = 0;
        poolCn.methods.add(initPool);
    }

    private void addDecoder(ClassNode cn, String name, String poolClassName, String dataFieldName, String initPoolMethodName,
                            int xorSeed, int classKey, int lenXor, int offsetMask, boolean rotateLeft, int rotAmount, boolean reverseBytes,
                            int bytesOffset, boolean highOffset, int offsetForm, int keyForm) {
        MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, name,
            "(J)Ljava/lang/String;", null, null);
        InsnList ins = new InsnList();

        LabelNode initialized = new LabelNode();
        ins.add(new FieldInsnNode(Opcodes.GETSTATIC, poolClassName, dataFieldName, "[I"));
        ins.add(new JumpInsnNode(Opcodes.IFNONNULL, initialized));
        ins.add(new MethodInsnNode(Opcodes.INVOKESTATIC, poolClassName, initPoolMethodName, "()V", false));
        ins.add(initialized);

        if (highOffset) {
            ins.add(new VarInsnNode(Opcodes.LLOAD, 0));
            ins.add(loadInt(32));
            ins.add(new InsnNode(Opcodes.LUSHR));
            ins.add(new InsnNode(Opcodes.L2I));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 2));

            ins.add(new VarInsnNode(Opcodes.LLOAD, 0));
            ins.add(new InsnNode(Opcodes.L2I));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 3));
        } else {
            ins.add(new VarInsnNode(Opcodes.LLOAD, 0));
            ins.add(loadInt(32));
            ins.add(new InsnNode(Opcodes.LUSHR));
            ins.add(new InsnNode(Opcodes.L2I));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 3));

            ins.add(new VarInsnNode(Opcodes.LLOAD, 0));
            ins.add(new InsnNode(Opcodes.L2I));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 2));
        }

        if (offsetForm == 0) {
            ins.add(new VarInsnNode(Opcodes.ILOAD, 2));
            ins.add(loadInt(offsetMask));
            ins.add(new InsnNode(Opcodes.IXOR));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 3));
            ins.add(new InsnNode(Opcodes.ISUB));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 4));
        } else if (offsetForm == 1) {
            ins.add(new VarInsnNode(Opcodes.ILOAD, 2));
            ins.add(loadInt(offsetMask));
            ins.add(new InsnNode(Opcodes.IXOR));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 3));
            ins.add(new InsnNode(Opcodes.IADD));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 4));
        } else if (offsetForm == 2) {
            ins.add(new VarInsnNode(Opcodes.ILOAD, 2));
            ins.add(loadInt(offsetMask));
            ins.add(new InsnNode(Opcodes.IXOR));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 3));
            ins.add(new InsnNode(Opcodes.IXOR));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 4));
        }

        ins.add(new FieldInsnNode(Opcodes.GETSTATIC, poolClassName, dataFieldName, "[I"));
        ins.add(new VarInsnNode(Opcodes.ILOAD, 4));
        ins.add(new InsnNode(Opcodes.IALOAD));
        ins.add(loadInt(lenXor));
        ins.add(new InsnNode(Opcodes.IXOR));
        ins.add(new VarInsnNode(Opcodes.ILOAD, 3));
        ins.add(new InsnNode(Opcodes.IXOR));
        ins.add(new VarInsnNode(Opcodes.ISTORE, 5));

        ins.add(new VarInsnNode(Opcodes.ILOAD, 5));
        ins.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        ins.add(new VarInsnNode(Opcodes.ASTORE, 6));

        ins.add(new InsnNode(Opcodes.ICONST_0));
        ins.add(new VarInsnNode(Opcodes.ISTORE, 7));

        LabelNode loopStart = new LabelNode();
        LabelNode loopEnd = new LabelNode();
        ins.add(loopStart);

        ins.add(new VarInsnNode(Opcodes.ILOAD, 7));
        ins.add(new VarInsnNode(Opcodes.ILOAD, 5));
        ins.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        if (reverseBytes) {
            ins.add(new VarInsnNode(Opcodes.ILOAD, 4));
            ins.add(loadInt(bytesOffset));
            ins.add(new InsnNode(Opcodes.IADD));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 5));
            ins.add(new InsnNode(Opcodes.ICONST_1));
            ins.add(new InsnNode(Opcodes.ISUB));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 7));
            ins.add(new InsnNode(Opcodes.ISUB));
            ins.add(new InsnNode(Opcodes.ICONST_4));
            ins.add(new InsnNode(Opcodes.IDIV));
            ins.add(new InsnNode(Opcodes.IADD));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 8));
        } else {
            ins.add(new VarInsnNode(Opcodes.ILOAD, 4));
            ins.add(loadInt(bytesOffset));
            ins.add(new InsnNode(Opcodes.IADD));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 7));
            ins.add(new InsnNode(Opcodes.ICONST_4));
            ins.add(new InsnNode(Opcodes.IDIV));
            ins.add(new InsnNode(Opcodes.IADD));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 8));
        }

        ins.add(new FieldInsnNode(Opcodes.GETSTATIC, poolClassName, dataFieldName, "[I"));
        ins.add(new VarInsnNode(Opcodes.ILOAD, 8));
        ins.add(new InsnNode(Opcodes.IALOAD));

        if (reverseBytes) {
            ins.add(new VarInsnNode(Opcodes.ILOAD, 5));
            ins.add(new InsnNode(Opcodes.ICONST_1));
            ins.add(new InsnNode(Opcodes.ISUB));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 7));
            ins.add(new InsnNode(Opcodes.ISUB));
            ins.add(new InsnNode(Opcodes.ICONST_4));
            ins.add(new InsnNode(Opcodes.IREM));
        } else {
            ins.add(new VarInsnNode(Opcodes.ILOAD, 7));
            ins.add(new InsnNode(Opcodes.ICONST_4));
            ins.add(new InsnNode(Opcodes.IREM));
        }
        ins.add(new IntInsnNode(Opcodes.BIPUSH, 8));
        ins.add(new InsnNode(Opcodes.IMUL));

        ins.add(new InsnNode(Opcodes.IUSHR));
        ins.add(loadInt(0xFF));
        ins.add(new InsnNode(Opcodes.IAND));
        ins.add(new VarInsnNode(Opcodes.ISTORE, 9));

        if (rotateLeft) {
            ins.add(new VarInsnNode(Opcodes.ILOAD, 9));
            ins.add(loadInt(rotAmount));
            ins.add(new InsnNode(Opcodes.IUSHR));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 9));
            ins.add(loadInt(8 - rotAmount));
            ins.add(new InsnNode(Opcodes.ISHL));
        } else {
            ins.add(new VarInsnNode(Opcodes.ILOAD, 9));
            ins.add(loadInt(rotAmount));
            ins.add(new InsnNode(Opcodes.ISHL));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 9));
            ins.add(loadInt(8 - rotAmount));
            ins.add(new InsnNode(Opcodes.IUSHR));
        }
        ins.add(new InsnNode(Opcodes.IOR));
        ins.add(loadInt(0xFF));
        ins.add(new InsnNode(Opcodes.IAND));
        ins.add(new VarInsnNode(Opcodes.ISTORE, 9));

        if (keyForm == 0) {
            ins.add(loadInt(xorSeed));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 7));
            ins.add(new InsnNode(Opcodes.IXOR));
            ins.add(loadInt(0x9E3779B9));
            ins.add(new InsnNode(Opcodes.IMUL));
            ins.add(loadInt(classKey));
            ins.add(new InsnNode(Opcodes.IADD));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 3));
            ins.add(new InsnNode(Opcodes.IADD));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 10));
        } else if (keyForm == 1) {
            ins.add(loadInt(xorSeed));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 7));
            ins.add(new InsnNode(Opcodes.IADD));
            ins.add(loadInt(0x7F4A7C15));
            ins.add(new InsnNode(Opcodes.IMUL));
            ins.add(loadInt(classKey));
            ins.add(new InsnNode(Opcodes.IXOR));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 3));
            ins.add(new InsnNode(Opcodes.IXOR));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 10));
        } else if (keyForm == 2) {
            ins.add(loadInt(xorSeed));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 7));
            ins.add(new InsnNode(Opcodes.ICONST_M1));
            ins.add(new InsnNode(Opcodes.IXOR));
            ins.add(new InsnNode(Opcodes.IXOR));
            ins.add(loadInt(0x517CC1B7));
            ins.add(new InsnNode(Opcodes.IMUL));
            ins.add(loadInt(classKey));
            ins.add(new InsnNode(Opcodes.ISUB));
            ins.add(new VarInsnNode(Opcodes.ILOAD, 3));
            ins.add(new InsnNode(Opcodes.IADD));
            ins.add(new VarInsnNode(Opcodes.ISTORE, 10));
        }

        ins.add(new VarInsnNode(Opcodes.ILOAD, 9));
        ins.add(new VarInsnNode(Opcodes.ILOAD, 10));
        ins.add(loadInt(0xFF));
        ins.add(new InsnNode(Opcodes.IAND));
        ins.add(new InsnNode(Opcodes.IXOR));
        ins.add(new VarInsnNode(Opcodes.ISTORE, 9));

        ins.add(new VarInsnNode(Opcodes.ALOAD, 6));
        ins.add(new VarInsnNode(Opcodes.ILOAD, 7));
        ins.add(new VarInsnNode(Opcodes.ILOAD, 9));
        ins.add(new InsnNode(Opcodes.I2B));
        ins.add(new InsnNode(Opcodes.BASTORE));

        ins.add(new IincInsnNode(7, 1));
        ins.add(new JumpInsnNode(Opcodes.GOTO, loopStart));

        ins.add(loopEnd);

        ins.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        ins.add(new InsnNode(Opcodes.DUP));
        ins.add(new VarInsnNode(Opcodes.ALOAD, 6));
        ins.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;"));
        ins.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([BLjava/nio/charset/Charset;)V", false));
        ins.add(new InsnNode(Opcodes.ARETURN));

        m.instructions = ins;
        m.maxStack = 10;
        m.maxLocals = 12;
        cn.methods.add(m);
    }

    private static int murmur3Mix(int h1, int h2, int h3) {
        int h = h1 ^ h2 ^ h3;
        h ^= h >>> 16;
        h *= 0x85EBCA6B;
        h ^= h >>> 13;
        h *= 0xC2B2AE35;
        h ^= h >>> 16;
        return h;
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

    private boolean isCriticalString(String s) {
        if (s.length() < 3) return false;
        if (s.startsWith("android.") || s.startsWith("java.") || s.startsWith("com.google.") || s.startsWith("com.ano.")) {
            return true;
        }
        String[] criticalWords = {
            "Launcher", "Button", "Dialog", "LinearLayout", "StringBuilder", "TextView", "EditText",
            "SharedPreferences", "Context", "Intent", "Activity", "Application", "View", "ViewGroup"
        };
        for (String word : criticalWords) {
            if (s.contains(word)) return true;
        }
        return false;
    }

    private static class StringTarget {
        MethodNode method;
        LdcInsnNode ldc;
        int callsiteId;
        int ordinal;
        List<String> chunks;
        StringTarget(MethodNode m, LdcInsnNode l, int cid, int ord, List<String> ch) {
            method = m; ldc = l; callsiteId = cid; ordinal = ord; chunks = ch;
        }
    }
}
