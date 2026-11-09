package obfuscator.core;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class MappingRegistry {

    private final Map<String, String> classMap = new LinkedHashMap<>();
    private final Map<String, String> methodMap = new LinkedHashMap<>();
    private final Map<String, String> fieldMap = new LinkedHashMap<>();
    private final Map<String, List<String>> stringMap = new LinkedHashMap<>();
    private final Set<String> excludedClasses = new LinkedHashSet<>();

    private int classCounter = 0;
    private int methodCounter = 0;
    private int fieldCounter = 0;

    private static final char[] HOMOGLYPH_POOL = { 'I', 'l', 'O' };



    private String toName(int index) {
        StringBuilder sb = new StringBuilder();
        int val = index;
        int pool = HOMOGLYPH_POOL.length;
        do {
            sb.append(HOMOGLYPH_POOL[val % pool]);
            val /= pool;
        } while (val > 0);
        if (isJavakeyword(sb.toString())) {
            sb.append(HOMOGLYPH_POOL[(index + 1) % pool]);
        }
        return sb.toString();
    }

    private boolean isJavakeyword(String s) {
        String stripped = s.replaceAll("[\u200B\u200C\u200D\u2060\uFEFF\u00AD]", "");
        switch (stripped) {
            case "do": case "if": case "for": case "int": case "new":
            case "try": case "void": case "null": case "true": case "false":
            case "this": case "else": case "goto": case "long": case "byte":
            case "char": case "case": case "enum": case "class": case "final":
            case "float": case "short": case "super": case "throw": case "while":
            case "const": case "break": case "catch": case "return": case "static":
            case "switch": case "throws": case "import": case "public": case "double":
            case "assert": case "native": case "default": case "extends": case "finally":
            case "package": case "private": case "abstract": case "continue":
            case "volatile": case "transient": case "implements": case "instanceof":
            case "synchronized": return true;
            default: return false;
        }
    }

    public String getNewClassName(String original) {
        String pkg = "";
        int slash = original.lastIndexOf('/');
        if (slash >= 0) pkg = original.substring(0, slash + 1);
        String newName = pkg + toName(classCounter++);
        classMap.put(original, newName);
        return newName;
    }

    public String getNewMethodName(String owner, String name, String desc) {
        String key = owner + "." + name + desc;
        String newName = toName(methodCounter++);
        methodMap.put(key, newName);
        return newName;
    }

    public String getNewFieldName(String owner, String name) {
        String key = owner + "." + name;
        String newName = toName(fieldCounter++);
        fieldMap.put(key, newName);
        return newName;
    }

    public void addStringMapping(String className, String methodName, String original) {
        String key = className + "." + methodName;
        stringMap.computeIfAbsent(key, k -> new ArrayList<>()).add(original);
    }

    public void addExcludedClass(String internalName) {
        excludedClasses.add(internalName);
    }

    public void writeMapping(Path mappingPath) throws IOException {
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(mappingPath))) {
            pw.println("=== CLASS MAPPINGS ===");
            for (Map.Entry<String, String> e : classMap.entrySet()) {
                pw.println(e.getKey() + " -> " + escapeUnicode(e.getValue()));
            }
            pw.println();
            pw.println("=== METHOD MAPPINGS ===");
            for (Map.Entry<String, String> e : methodMap.entrySet()) {
                pw.println(escapeUnicode(e.getKey()) + " -> " + escapeUnicode(e.getValue()));
            }
            pw.println();
            pw.println("=== FIELD MAPPINGS ===");
            for (Map.Entry<String, String> e : fieldMap.entrySet()) {
                pw.println(escapeUnicode(e.getKey()) + " -> " + escapeUnicode(e.getValue()));
            }
            pw.println();
            pw.println("=== STRING MAPPINGS ===");
            for (Map.Entry<String, List<String>> e : stringMap.entrySet()) {
                pw.println(e.getKey() + ":");
                for (String s : e.getValue()) {
                    pw.println("  \"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"");
                }
            }
        }
    }

    private static String escapeUnicode(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c > 127 || c < 32) {
                sb.append(String.format("\\u%04X", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public void writeJniHeader(Path headerPath) throws IOException {
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(headerPath))) {
            pw.println("#ifndef OBF_JNI_MAP_H");
            pw.println("#define OBF_JNI_MAP_H");
            pw.println();

            pw.println("// ====== Class Mappings ======");
            for (Map.Entry<String, String> e : classMap.entrySet()) {
                String original = e.getKey();
                String obfuscated = e.getValue();
                String simpleName = original;
                int lastSlash = original.lastIndexOf('/');
                if (lastSlash >= 0) simpleName = original.substring(lastSlash + 1);
                simpleName = simpleName.replaceAll("[^a-zA-Z0-9_]", "_");
                pw.println("#define OBF_CLASS_" + simpleName + " \"" + obfuscated + "\"");
            }
            pw.println();

            pw.println("// ====== Method Mappings ======");
            for (Map.Entry<String, String> e : methodMap.entrySet()) {
                String key = e.getKey();
                String obfName = e.getValue();
                int dot = key.indexOf('.');
                int paren = key.indexOf('(');
                if (dot < 0 || paren < 0) continue;
                String ownerClass = key.substring(0, dot);
                String methodName = key.substring(dot + 1, paren);
                String simpleOwner = ownerClass;
                int ls = ownerClass.lastIndexOf('/');
                if (ls >= 0) simpleOwner = ownerClass.substring(ls + 1);
                simpleOwner = simpleOwner.replaceAll("[^a-zA-Z0-9_]", "_");
                methodName = methodName.replaceAll("[^a-zA-Z0-9_]", "_");
                pw.println("#define OBF_METHOD_" + simpleOwner + "_" + methodName + " \"" + obfName + "\"");
            }
            pw.println();

            pw.println("// ====== Field Mappings ======");
            for (Map.Entry<String, String> e : fieldMap.entrySet()) {
                String key = e.getKey();
                String obfName = e.getValue();
                int dot = key.indexOf('.');
                if (dot < 0) continue;
                String ownerClass = key.substring(0, dot);
                String fieldName = key.substring(dot + 1);
                String simpleOwner = ownerClass;
                int ls = ownerClass.lastIndexOf('/');
                if (ls >= 0) simpleOwner = ownerClass.substring(ls + 1);
                simpleOwner = simpleOwner.replaceAll("[^a-zA-Z0-9_]", "_");
                fieldName = fieldName.replaceAll("[^a-zA-Z0-9_]", "_");
                pw.println("#define OBF_FIELD_" + simpleOwner + "_" + fieldName + " \"" + obfName + "\"");
            }
            pw.println();

            if (!excludedClasses.isEmpty()) {
                pw.println("// ====== Excluded Classes ======");
                for (String exc : excludedClasses) {
                    String simpleName = exc;
                    int ls2 = exc.lastIndexOf('/');
                    if (ls2 >= 0) simpleName = exc.substring(ls2 + 1);
                    simpleName = simpleName.replaceAll("[^a-zA-Z0-9_]", "_");
                    pw.println("#define OBF_CLASS_" + simpleName + " \"" + exc + "\"");
                }
                pw.println();
            }

            pw.println("#endif");
        }
    }

    public Map<String, String> getClassMap() { return classMap; }
    public Map<String, String> getMethodMap() { return methodMap; }
    public Map<String, String> getFieldMap() { return fieldMap; }

    public void writeSmaliReferences(Path refPath) throws IOException {
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(refPath))) {
            pw.println("================================================================");
            pw.println("  OBFUSCATION REFERENCE GUIDE");
            pw.println("  Use this file to update AndroidManifest.xml and external DEX");
            pw.println("================================================================");
            pw.println();

            pw.println("==== MANIFEST REPLACEMENTS ====");
            pw.println("Replace android:name values in AndroidManifest.xml:");
            pw.println();
            for (Map.Entry<String, String> e : classMap.entrySet()) {
                String original = e.getKey();
                String obfuscated = e.getValue();
                if (original.contains("$")) continue;
                String origDot = original.replace('/', '.');
                String obfDot = obfuscated.replace('/', '.');
                pw.println(origDot + "  -->  " + obfDot);
            }
            pw.println();

            pw.println("==== SMALI CLASS REPLACEMENTS ====");
            for (Map.Entry<String, String> e : classMap.entrySet()) {
                String original = e.getKey();
                String obfuscated = e.getValue();
                if (original.contains("$")) continue;
                pw.println("L" + original + ";  -->  L" + obfuscated + ";");
            }
            pw.println();

            pw.println("==== SMALI METHOD REPLACEMENTS ====");
            for (Map.Entry<String, String> e : methodMap.entrySet()) {
                String key = e.getKey();
                String obfName = e.getValue();
                int dot = key.indexOf('.');
                int paren = key.indexOf('(');
                if (dot < 0 || paren < 0) continue;
                String owner = key.substring(0, dot);
                String methodName = key.substring(dot + 1, paren);
                String desc = key.substring(paren);
                String obfOwner = classMap.getOrDefault(owner, owner);
                pw.println("L" + owner + ";->" + methodName + desc
                    + "  -->  L" + obfOwner + ";->" + obfName + desc);
            }
            pw.println();

            pw.println("==== SMALI FIELD REPLACEMENTS ====");
            for (Map.Entry<String, String> e : fieldMap.entrySet()) {
                String key = e.getKey();
                String obfName = e.getValue();
                int dot = key.indexOf('.');
                if (dot < 0) continue;
                String owner = key.substring(0, dot);
                String fieldName = key.substring(dot + 1);
                String obfOwner = classMap.getOrDefault(owner, owner);
                pw.println(owner + "." + fieldName + "  -->  " + obfOwner + "." + obfName);
            }
        }
    }
}
