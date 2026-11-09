package obfuscator.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class ClassScanner {

    public static List<ClassNode> scan(Path inputDir) throws IOException {
        List<ClassNode> classes = new ArrayList<>();
        Files.walk(inputDir)
            .filter(p -> p.toString().endsWith(".class"))
            .forEach(p -> {
                try {
                    byte[] data = Files.readAllBytes(p);
                    ClassReader cr = new ClassReader(data);
                    ClassNode cn = new ClassNode();
                    cr.accept(cn, ClassReader.SKIP_FRAMES);
                    classes.add(cn);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        return classes;
    }
}
