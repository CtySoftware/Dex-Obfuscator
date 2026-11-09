package obfuscator.passes;

import obfuscator.config.ObfuscatorConfig;
import obfuscator.core.JNIDetector;
import obfuscator.core.MappingRegistry;
import obfuscator.core.ObfuscationPass;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

public class RenamePass implements ObfuscationPass {

    @Override
    public String name() { return "RenamePass"; }

    @Override
    public void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config) {
        if (!config.isEnableRename()) return;

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

        Set<String> sdkMethodSigs = loadSdkMethodSigs(config.getAndroidJarPath());
        Set<String> frameworkOverrides = new HashSet<>();
        for (ClassNode cn : classes) {
            if (classesWithFrameworkAncestor.contains(cn.name)) {
                for (MethodNode mn : cn.methods) {
                    if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
                    if ((mn.access & Opcodes.ACC_STATIC) != 0) continue;
                    String sig = mn.name + mn.desc;
                    if (sdkMethodSigs.isEmpty() || sdkMethodSigs.contains(sig)) {
                        frameworkOverrides.add(sig);
                    }
                }
            }
        }

        Map<String, String> classMap = new HashMap<>();
        Map<String, String> methodMap = new HashMap<>();
        Map<String, String> fieldMap = new HashMap<>();

        for (ClassNode cn : classes) {
            if (config.isExcluded(cn.name)) continue;

            String newName = registry.getNewClassName(cn.name);
            classMap.put(cn.name, newName);

            for (MethodNode mn : cn.methods) {
                if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
                if (detector.isMethodProtected(cn.name, mn.name, mn.desc)) continue;
                if ((mn.access & Opcodes.ACC_NATIVE) != 0) continue;
                if (frameworkOverrides.contains(mn.name + mn.desc)) continue;
                String key = cn.name + "." + mn.name + mn.desc;
                if (!methodMap.containsKey(key)) {
                    methodMap.put(key, registry.getNewMethodName(cn.name, mn.name, mn.desc));
                }
            }

            for (FieldNode fn : cn.fields) {
                if (detector.isFieldProtected(cn.name, fn.name)) continue;
                String key = cn.name + "." + fn.name;
                if (!fieldMap.containsKey(key)) {
                    fieldMap.put(key, registry.getNewFieldName(cn.name, fn.name));
                }
            }
        }

        Remapper remapper = new Remapper() {
            @Override public String map(String internalName) {
                return classMap.getOrDefault(internalName, internalName);
            }
            @Override public String mapMethodName(String owner, String name, String descriptor) {
                String key = owner + "." + name + descriptor;
                return methodMap.getOrDefault(key, name);
            }
            @Override public String mapFieldName(String owner, String name, String descriptor) {
                String key = owner + "." + name;
                return fieldMap.getOrDefault(key, name);
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
        if (androidJarPath == null || androidJarPath.isEmpty()) {
            System.err.println("androidJarPath not set, protecting all instance methods of framework subclasses");
            return sigs;
        }
        Path p = Paths.get(androidJarPath);
        if (!Files.exists(p)) {
            System.err.println("androidJarPath not found: " + androidJarPath);
            return sigs;
        }
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
            System.err.println("Failed to read androidJar: " + ex.getMessage());
            return new HashSet<>();
        }
        return sigs;
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
