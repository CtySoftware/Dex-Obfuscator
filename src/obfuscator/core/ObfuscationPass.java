package obfuscator.core;

import obfuscator.config.ObfuscatorConfig;
import org.objectweb.asm.tree.ClassNode;
import java.util.List;

public interface ObfuscationPass {
    String name();
    void execute(List<ClassNode> classes, JNIDetector detector, MappingRegistry registry, ObfuscatorConfig config);
}
