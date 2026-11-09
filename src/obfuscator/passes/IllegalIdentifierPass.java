package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.Opcodes;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

public class IllegalIdentifierPass implements ObfuscationPass {
    private static final String[] KEYWORDS = {
        "do", "if", "for", "int", "new", "try", "byte", "case", "char",
        "else", "goto", "long", "this", "void", "enum", "null", "true",
        "false", "break", "catch", "class", "final", "float", "short",
        "super", "throw", "while", "const", "native", "return", "static",
        "switch", "throws", "import", "public", "double", "assert",
        "default", "extends", "finally", "package", "private", "abstract",
        "continue", "volatile", "transient", "implements", "instanceof",
        "synchronized"
    };

    @Override
    public String name() { return "IllegalIdentifierPass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableIllegalIdentifiers()) return;

        List<String> namePool = new ArrayList<>();
        for (String kw : KEYWORDS) namePool.add(kw);
        for (int i = 0; i < 20; i++) {
            for (String kw : KEYWORDS) {
                namePool.add(kw + "_" + i);
            }
        }

        Set<String> knownClasses = new HashSet<>();
        Map<String, ClassNode> classNodeMap = new HashMap<>();
        for (ClassNode cn : classes) {
            knownClasses.add(cn.name);
            classNodeMap.put(cn.name, cn);
        }
        Set<String> classesWithFrameworkAncestor = new HashSet<>();
        for (ClassNode cn : classes) {
            if (hasFrameworkAncestor(cn, knownClasses, classNodeMap, new HashSet<>())) {
                classesWithFrameworkAncestor.add(cn.name);
            }
        }
        Set<String> sdkSigs = loadSdkMethodSigs(config.getAndroidJarPath());
        Set<String> frameworkOverrides = new HashSet<>();
        for (ClassNode cn : classes) {
            if (classesWithFrameworkAncestor.contains(cn.name)) {
                for (MethodNode mn : cn.methods) {
                    if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
                    if ((mn.access & Opcodes.ACC_STATIC) != 0) continue;
                    String sig = mn.name + mn.desc;
                    if (sdkSigs.isEmpty() || sdkSigs.contains(sig)) {
                        frameworkOverrides.add(sig);
                    }
                }
            }
        }

        int nameIdx = 0;

        Map<String, String> methodRenames = new LinkedHashMap<>();
        Map<String, String> fieldRenames = new LinkedHashMap<>();

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;
            Set<String> usedMethodNames = new HashSet<>();
            Set<String> usedFieldNames = new HashSet<>();

            for (MethodNode mn : cn.methods) {
                if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
                if (isDecoderOrHelper(mn.name)) continue;
                if ((mn.access & Opcodes.ACC_NATIVE) != 0) continue;
                if (frameworkOverrides.contains(mn.name + mn.desc)) continue;
                if (mn.name.length() <= 3 && !isJavaKeyword(mn.name)) {
                    String key = cn.name + "." + mn.name + mn.desc;
                    if (!methodRenames.containsKey(key)) {
                        String newName = namePool.get(nameIdx % namePool.size());
                        while (usedMethodNames.contains(newName)) {
                            nameIdx++;
                            newName = namePool.get(nameIdx % namePool.size());
                        }
                        usedMethodNames.add(newName);
                        methodRenames.put(key, newName);
                        nameIdx++;
                    }
                }
            }

            for (FieldNode fn : cn.fields) {
                if (fn.name.length() <= 3 && !isJavaKeyword(fn.name)) {
                    String key = cn.name + "." + fn.name;
                    if (!fieldRenames.containsKey(key)) {
                        String newName = namePool.get(nameIdx % namePool.size());
                        while (usedFieldNames.contains(newName)) {
                            nameIdx++;
                            newName = namePool.get(nameIdx % namePool.size());
                        }
                        usedFieldNames.add(newName);
                        fieldRenames.put(key, newName);
                        nameIdx++;
                    }
                }
            }
        }

        Map<String, String> regMethodMap = registry.getMethodMap();
        Map<String, String> methodAmendments = new HashMap<>();
        for (Map.Entry<String, String> mre : regMethodMap.entrySet()) {
            String originalKey = mre.getKey();
            String renamedName = mre.getValue();
            int dot = originalKey.indexOf('.');
            int paren = originalKey.indexOf('(');
            if (dot < 0 || paren < 0) continue;
            String originalOwner = originalKey.substring(0, dot);
            String desc = originalKey.substring(paren);
            String obfOwner = registry.getClassMap().getOrDefault(originalOwner, originalOwner);
            String ilKey = obfOwner + "." + renamedName + desc;
            if (methodRenames.containsKey(ilKey)) {
                methodAmendments.put(originalKey, methodRenames.get(ilKey));
            }
        }
        regMethodMap.putAll(methodAmendments);

        Map<String, String> regFieldMap = registry.getFieldMap();
        Map<String, String> fieldAmendments = new HashMap<>();
        for (Map.Entry<String, String> fre : regFieldMap.entrySet()) {
            String originalKey = fre.getKey();
            String renamedName = fre.getValue();
            int dot = originalKey.indexOf('.');
            if (dot < 0) continue;
            String originalOwner = originalKey.substring(0, dot);
            String obfOwner = registry.getClassMap().getOrDefault(originalOwner, originalOwner);
            String ilKey = obfOwner + "." + renamedName;
            if (fieldRenames.containsKey(ilKey)) {
                fieldAmendments.put(originalKey, fieldRenames.get(ilKey));
            }
        }
        regFieldMap.putAll(fieldAmendments);

        Remapper remapper = new Remapper() {
            @Override
            public String mapMethodName(String owner, String name, String descriptor) {
                String key = owner + "." + name + descriptor;
                return methodRenames.getOrDefault(key, name);
            }

            @Override
            public String mapFieldName(String owner, String name, String descriptor) {
                String key = owner + "." + name;
                return fieldRenames.getOrDefault(key, name);
            }
        };

        List<ClassNode> remapped = new ArrayList<>();
        for (ClassNode cn : classes) {
            ClassNode newCn = new ClassNode();
            ClassRemapper cr = new ClassRemapper(newCn, remapper);
            cn.accept(cr);
            remapped.add(newCn);
        }

        classes.clear();
        classes.addAll(remapped);
    }

    private Set<String> loadSdkMethodSigs(String androidJarPath) {
        Set<String> sigs = new HashSet<>();
        if (androidJarPath == null || androidJarPath.isEmpty()) return sigs;
        Path p = Paths.get(androidJarPath);
        if (!Files.exists(p)) return sigs;
        try (ZipFile zf = new ZipFile(p.toFile())) {
            Enumeration<? extends ZipEntry> e = zf.entries();
            while (e.hasMoreElements()) {
                ZipEntry ze = e.nextElement();
                if (!ze.getName().endsWith(".class")) continue;
                try (InputStream is = zf.getInputStream(ze)) {
                    new ClassReader(is).accept(new ClassVisitor(Opcodes.ASM9) {
                        @Override
                        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
                            if ((access & Opcodes.ACC_STATIC) == 0
                                && !name.equals("<init>") && !name.equals("<clinit>")) {
                                sigs.add(name + desc);
                            }
                            return null;
                        }
                    }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                }
            }
        } catch (IOException ex) {
            return new HashSet<>();
        }
        return sigs;
    }

    private boolean isJavaKeyword(String name) {
        for (String kw : KEYWORDS) {
            if (kw.equals(name)) return true;
        }
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

    private boolean hasFrameworkAncestor(ClassNode cn, Set<String> knownClasses, Map<String, ClassNode> classNodeMap, Set<String> visited) {
        if (visited.contains(cn.name)) return false;
        visited.add(cn.name);
        if (cn.superName != null && !cn.superName.equals("java/lang/Object")) {
            if (!knownClasses.contains(cn.superName)) return true;
            ClassNode superNode = classNodeMap.get(cn.superName);
            if (superNode != null && hasFrameworkAncestor(superNode, knownClasses, classNodeMap, visited)) return true;
        }
        if (cn.interfaces != null) {
            for (String iface : cn.interfaces) {
                if (!knownClasses.contains(iface)) return true;
                ClassNode ifaceNode = classNodeMap.get(iface);
                if (ifaceNode != null && hasFrameworkAncestor(ifaceNode, knownClasses, classNodeMap, visited)) return true;
            }
        }
        return false;
    }
}
