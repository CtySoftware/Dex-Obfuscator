package obfuscator.config;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class ObfuscatorConfig {

    private final Set<String> excludeClasses = new HashSet<>();
    private final Set<String> jniKeepFields = new HashSet<>();
    private boolean enableJniFieldProtection = true;
    private boolean enableRename = true;
    private boolean enableStringEncryption = true;
    private boolean enableOpaquePredicates = true;
    private boolean enableControlFlow = true;
    private boolean enableIllegalIdentifiers = true;
    private boolean enableFakeTryCatch = true;
    private boolean enableControlFlowFlattening = false;
    private boolean enableNumberObfuscation = true;
    private boolean enableGotoObfuscation = true;
    private boolean enableReflectionProxy = true;
    private boolean enableSourceErase = true;
    private boolean enableBogusBlocks = true;
    private boolean enableFieldScramble = true;
    private boolean enableIrreducibleFlow = true;
    private boolean enableReflectiveDispatch = true;
    private String androidJarPath = "";

    public static ObfuscatorConfig load(Path path) throws IOException {
        ObfuscatorConfig cfg = new ObfuscatorConfig();
        String json = new String(Files.readAllBytes(path));
        json = json.replaceAll("/\\*.*?\\*/", "").replaceAll("//.*", "");

        for (String val : extractArray(json, "excludeClasses")) {
            cfg.excludeClasses.add(val.replace('.', '/'));
        }
        for (String val : extractArray(json, "jniKeepFields")) {
            cfg.jniKeepFields.add(val);
        }
        cfg.enableJniFieldProtection = extractBool(json, "enableJniFieldProtection", true);
        cfg.enableRename = extractBool(json, "enableRename", true);
        cfg.enableStringEncryption = extractBool(json, "enableStringEncryption", true);
        cfg.enableOpaquePredicates = extractBool(json, "enableOpaquePredicates", true);
        cfg.enableControlFlow = extractBool(json, "enableControlFlow", true);
        cfg.enableIllegalIdentifiers = extractBool(json, "enableIllegalIdentifiers", true);
        cfg.enableFakeTryCatch = extractBool(json, "enableFakeTryCatch", true);
        cfg.enableControlFlowFlattening = extractBool(json, "enableControlFlowFlattening", false);
        cfg.enableNumberObfuscation = extractBool(json, "enableNumberObfuscation", true);
        cfg.enableGotoObfuscation = extractBool(json, "enableGotoObfuscation", true);
        cfg.enableReflectionProxy = extractBool(json, "enableReflectionProxy", true);
        cfg.enableSourceErase = extractBool(json, "enableSourceErase", true);
        cfg.enableBogusBlocks = extractBool(json, "enableBogusBlocks", true);
        cfg.enableFieldScramble = extractBool(json, "enableFieldScramble", true);
        cfg.enableIrreducibleFlow = extractBool(json, "enableIrreducibleFlow", true);
        cfg.enableReflectiveDispatch = extractBool(json, "enableReflectiveDispatch", true);
        cfg.androidJarPath = extractString(json, "androidJarPath", "");
        return cfg;
    }

    private static List<String> extractArray(String json, String key) {
        List<String> result = new ArrayList<>();
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) return result;
        int start = json.indexOf('[', idx);
        int end = json.indexOf(']', start);
        if (start < 0 || end < 0) return result;
        String arr = json.substring(start + 1, end);
        for (String s : arr.split(",")) {
            s = s.trim().replace("\"", "");
            if (!s.isEmpty()) result.add(s);
        }
        return result;
    }

    private static String extractString(String json, String key, String def) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) return def;
        int colon = json.indexOf(':', idx);
        if (colon < 0) return def;
        int q1 = json.indexOf('"', colon);
        if (q1 < 0) return def;
        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) return def;
        return json.substring(q1 + 1, q2);
    }

    private static boolean extractBool(String json, String key, boolean def) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) return def;
        int colon = json.indexOf(':', idx);
        if (colon < 0) return def;
        String rest = json.substring(colon + 1, Math.min(colon + 20, json.length())).trim();
        if (rest.startsWith("true")) return true;
        if (rest.startsWith("false")) return false;
        return def;
    }

    public boolean isEnableJniFieldProtection() { return enableJniFieldProtection; }
    public boolean isJniKeptField(String simpleName, String qualifiedName) {
        return jniKeepFields.contains(simpleName) || jniKeepFields.contains(qualifiedName);
    }

    public boolean isExcluded(String internalName) {
        if (excludeClasses.contains(internalName)) return true;
        for (String ex : excludeClasses) {
            if (internalName.startsWith(ex + "$")) return true;
        }
        return false;
    }

    public boolean isEnableRename() { return enableRename; }
    public boolean isEnableStringEncryption() { return enableStringEncryption; }
    public boolean isEnableOpaquePredicates() { return enableOpaquePredicates; }
    public boolean isEnableControlFlow() { return enableControlFlow; }
    public boolean isEnableIllegalIdentifiers() { return enableIllegalIdentifiers; }
    public boolean isEnableFakeTryCatch() { return enableFakeTryCatch; }
    public boolean isEnableControlFlowFlattening() { return enableControlFlowFlattening; }
    public boolean isEnableNumberObfuscation() { return enableNumberObfuscation; }
    public boolean isEnableGotoObfuscation() { return enableGotoObfuscation; }
    public boolean isEnableReflectionProxy() { return enableReflectionProxy; }
    public boolean isEnableSourceErase() { return enableSourceErase; }
    public boolean isEnableBogusBlocks() { return enableBogusBlocks; }
    public boolean isEnableFieldScramble() { return enableFieldScramble; }
    public boolean isEnableIrreducibleFlow() { return enableIrreducibleFlow; }
    public boolean isEnableReflectiveDispatch() { return enableReflectiveDispatch; }
    public String getAndroidJarPath() { return androidJarPath; }
}
