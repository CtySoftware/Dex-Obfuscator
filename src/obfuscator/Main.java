package obfuscator;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.*;
import obfuscator.passes.*;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodTooLargeException;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class Main {

    private static final int INSN_THRESHOLD = 2000;
    private static final int CHUNK_SIZE = 600;
    private static int splitCounter = 0;

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Usage: java -jar obfuscator.jar <input> <output> <config>");
            System.exit(1);
        }

        Path inputDir = Paths.get(args[0]);
        Path outputDir = Paths.get(args[1]);
        Path configPath = Paths.get(args[2]);

        long start = System.currentTimeMillis();

        ObfuscatorConfig config = ObfuscatorConfig.load(configPath);
        List<ClassNode> classes = ClassScanner.scan(inputDir);

        JNIDetector detector = new JNIDetector();
        detector.analyze(classes, config);

        MappingRegistry registry = new MappingRegistry();

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) {
                registry.addExcludedClass(cn.name);
            }
        }

        List<ObfuscationPass> passes = new ArrayList<>();
        passes.add(new SourceFileErasePass());
        passes.add(new RenamePass());
        passes.add(new StringEncryptPass());
        passes.add(new ReflectionProxyPass());
        passes.add(new NumberObfuscationPass());
        passes.add(new OpaquePredicatePass());
        passes.add(new BogusBlockPass());
        passes.add(new FieldScramblePass());
        passes.add(new NumberObfuscationPass(2, 100));
        passes.add(new IrreducibleFlowPass());
        passes.add(new FakeTryCatchPass());
        passes.add(new GotoObfuscationPass());
        passes.add(new ControlFlowPass());
        passes.add(new IllegalIdentifierPass());

        for (ObfuscationPass pass : passes) {
            pass.execute(classes, detector, registry, config);
        }

        if (!Files.exists(outputDir)) Files.createDirectories(outputDir);

        for (ClassNode cn : classes) {
            splitAllLargeMethods(cn);

            byte[] data = writeClass(cn);
            if (data == null) {
                splitAllLargeMethods(cn);
                data = writeClass(cn);
            }
            if (data == null) {
                System.err.println("Skipping class that could not be written: " + cn.name);
                continue;
            }
            Path outPath = outputDir.resolve(cn.name + ".class");
            Files.createDirectories(outPath.getParent());
            Files.write(outPath, data);
        }

        Path mappingPath = outputDir.getParent().resolve("mapping.txt");
        Path headerPath = outputDir.getParent().resolve("obf_jni_map.h");
        Path smaliRefPath = outputDir.getParent().resolve("smali_references.txt");
        registry.writeMapping(mappingPath);
        registry.writeJniHeader(headerPath);
        registry.writeSmaliReferences(smaliRefPath);

        long elapsed = System.currentTimeMillis() - start;
        System.out.println("Obfuscated " + classes.size() + " classes in " + elapsed + "ms");
        System.out.println("Mapping written to " + mappingPath);
    }

    private static byte[] writeClass(ClassNode cn) {
        try {
            ClassWriter cw = new SafeClassWriter(ClassWriter.COMPUTE_FRAMES);
            cn.accept(cw);
            return cw.toByteArray();
        } catch (Exception e1) {
            stripFrameNodes(cn);
            try {
                ClassWriter cw2 = new SafeClassWriter(ClassWriter.COMPUTE_FRAMES);
                cn.accept(cw2);
                return cw2.toByteArray();
            } catch (Exception e2) {
                int savedVersion = cn.version;
                cn.version = Opcodes.V1_6;
                try {
                    ClassWriter cw3 = new ClassWriter(ClassWriter.COMPUTE_MAXS);
                    cn.accept(cw3);
                    return cw3.toByteArray();
                } catch (Exception e3) {
                    cn.version = savedVersion;
                    System.err.println("Failed to write class: " + cn.name);
                    return null;
                }
            }
        }
    }


    private static void stripFrameNodes(ClassNode cn) {
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            List<AbstractInsnNode> toRemove = new ArrayList<>();
            for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof FrameNode) toRemove.add(insn);
            }
            for (AbstractInsnNode insn : toRemove) mn.instructions.remove(insn);
        }
    }


    private static class SafeClassWriter extends ClassWriter {
        SafeClassWriter(int flags) { super(flags); }
        @Override
        protected String getCommonSuperClass(String type1, String type2) {
            return "java/lang/Object";
        }
    }

    private static void splitAllLargeMethods(ClassNode cn) {
        for (int pass = 0; pass < 30; pass++) {
            boolean changed = false;
            List<MethodNode> newMethods = new ArrayList<>();

            for (MethodNode mn : new ArrayList<>(cn.methods)) {
                if (mn.instructions == null) continue;
                if (mn.instructions.size() < INSN_THRESHOLD) continue;
                if ((mn.access & Opcodes.ACC_STATIC) == 0) continue;

                List<MethodNode> helpers = splitMethod(cn.name, mn);
                if (helpers != null && !helpers.isEmpty()) {
                    newMethods.addAll(helpers);
                    changed = true;
                }
            }

            if (!changed) break;
            cn.methods.addAll(newMethods);
        }
    }

    private static List<MethodNode> splitMethod(String className, MethodNode method) {
        List<AbstractInsnNode> allInsns = new ArrayList<>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            allInsns.add(insn);
        }

        while (!allInsns.isEmpty() && allInsns.get(allInsns.size() - 1).getOpcode() == Opcodes.RETURN) {
            allInsns.remove(allInsns.size() - 1);
        }
        if (allInsns.size() < INSN_THRESHOLD) return null;

        Set<Integer> safePoints = new HashSet<>();
        for (int i = 0; i < allInsns.size(); i++) {
            int op = allInsns.get(i).getOpcode();
            if (op == Opcodes.PUTSTATIC || op == Opcodes.ASTORE || 
                op == Opcodes.ISTORE || op == Opcodes.LSTORE ||
                op == Opcodes.FSTORE || op == Opcodes.DSTORE) {
                safePoints.add(i);
            }
            if (op == Opcodes.INVOKESTATIC && allInsns.get(i) instanceof MethodInsnNode) {
                if (((MethodInsnNode) allInsns.get(i)).desc.endsWith(")V")) {
                    safePoints.add(i);
                }
            }
        }

        if (safePoints.isEmpty()) return null;

        List<List<AbstractInsnNode>> chunks = new ArrayList<>();
        List<AbstractInsnNode> current = new ArrayList<>();

        for (int i = 0; i < allInsns.size(); i++) {
            current.add(allInsns.get(i));
            if (current.size() >= CHUNK_SIZE && safePoints.contains(i)) {
                chunks.add(current);
                current = new ArrayList<>();
            }
        }
        if (!current.isEmpty()) chunks.add(current);

        if (chunks.size() <= 1) return null;

        for (List<AbstractInsnNode> chunk : chunks) {
            Set<LabelNode> defined = new HashSet<>();
            Set<Integer> writtenLocals = new HashSet<>();
            for (AbstractInsnNode insn : chunk) {
                if (insn instanceof LabelNode) defined.add((LabelNode) insn);
                if (insn instanceof VarInsnNode) {
                    int op = insn.getOpcode();
                    if (op >= Opcodes.ISTORE && op <= Opcodes.ASTORE) writtenLocals.add(((VarInsnNode) insn).var);
                }
            }
            for (AbstractInsnNode insn : chunk) {
                if (insn instanceof JumpInsnNode) {
                    if (!defined.contains(((JumpInsnNode) insn).label)) return null;
                } else if (insn instanceof TableSwitchInsnNode) {
                    TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
                    if (!defined.contains(ts.dflt)) return null;
                    for (LabelNode l : ts.labels) if (!defined.contains(l)) return null;
                } else if (insn instanceof LookupSwitchInsnNode) {
                    LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
                    if (!defined.contains(ls.dflt)) return null;
                    for (LabelNode l : ls.labels) if (!defined.contains(l)) return null;
                } else if (insn instanceof VarInsnNode) {
                    int op = insn.getOpcode();
                    if (op >= Opcodes.ILOAD && op <= Opcodes.ALOAD && !writtenLocals.contains(((VarInsnNode) insn).var)) return null;
                } else if (insn instanceof IincInsnNode) {
                    if (!writtenLocals.contains(((IincInsnNode) insn).var)) return null;
                }
            }
        }

        Map<LabelNode, LabelNode> labelMap = new HashMap<>();
        for (AbstractInsnNode insn : allInsns) {
            if (insn instanceof LabelNode) labelMap.put((LabelNode) insn, new LabelNode());
            if (insn instanceof JumpInsnNode) {
                LabelNode t = ((JumpInsnNode) insn).label;
                if (!labelMap.containsKey(t)) labelMap.put(t, new LabelNode());
            }
            if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
                if (!labelMap.containsKey(ts.dflt)) labelMap.put(ts.dflt, new LabelNode());
                for (LabelNode l : ts.labels) if (!labelMap.containsKey(l)) labelMap.put(l, new LabelNode());
            }
            if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
                if (!labelMap.containsKey(ls.dflt)) labelMap.put(ls.dflt, new LabelNode());
                for (LabelNode l : ls.labels) if (!labelMap.containsKey(l)) labelMap.put(l, new LabelNode());
            }
        }

        List<MethodNode> helpers = new ArrayList<>();
        List<String> helperNames = new ArrayList<>();

        for (int c = 0; c < chunks.size(); c++) {
            String name = "_s" + (splitCounter++);
            helperNames.add(name);

            MethodNode helper = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, name, "()V", null, null);
            InsnList hInsns = new InsnList();
            for (AbstractInsnNode insn : chunks.get(c)) {
                AbstractInsnNode cloned = insn.clone(labelMap);
                if (cloned != null) hInsns.add(cloned);
            }
            hInsns.add(new InsnNode(Opcodes.RETURN));
            helper.instructions = hInsns;
            helper.maxStack = Math.max(method.maxStack, 8);
            helper.maxLocals = Math.max(method.maxLocals, 1);
            helper.tryCatchBlocks = new ArrayList<>();
            helpers.add(helper);
        }

        method.instructions.clear();
        if (method.tryCatchBlocks != null) method.tryCatchBlocks.clear();
        InsnList calls = new InsnList();
        for (String name : helperNames) {
            calls.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, name, "()V", false));
        }
        calls.add(new InsnNode(Opcodes.RETURN));
        method.instructions.add(calls);
        method.maxStack = 1;
        method.maxLocals = 0;

        return helpers;
    }
}
