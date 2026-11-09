# Dex Obfuscator

A bytecode-level obfuscator for Android `.class` files, built on top of [ASM](https://asm.ow2.io/). It operates directly on compiled Java bytecode before dexing, applying a configurable pipeline of obfuscation passes.

## Features

- **Identifier renaming** — classes, methods and fields renamed to short, obfuscated identifiers
- **String encryption** — string constants split into pools and decrypted at runtime via per-class decoders
- **Control flow obfuscation** — opaque predicates, bogus blocks, goto-based flattening, irreducible control flow
- **Number obfuscation** — integer constants rewritten as arithmetic expressions
- **Reflection proxying** — selected calls rewritten to go through reflection
- **Fake exception handlers** — unreachable try/catch blocks injected to confuse decompilers
- **Illegal identifiers** — names that are invalid Java but valid in the class file format, breaking naive decompilers
- **Field scrambling**
- **JNI-aware** — detects native methods and can exclude or protect fields referenced from native code
- **Large method splitting** — automatically splits methods that exceed the JVM bytecode size limit after obfuscation

## Requirements

- JDK 8 or newer (JDK 22 used for development)
- No external build tool required — a Windows batch script drives compilation

## Build

```bash
build_obfuscator.bat
```

This compiles the sources under `src/`, merges them with the ASM jars in `libs/`, and produces a runnable fat jar: `android-obfuscator.jar`.

## Usage

```bash
java -jar android-obfuscator.jar <input-classes-dir> <output-classes-dir> <config.json>
```

- `input-classes-dir` — directory tree of compiled `.class` files to obfuscate
- `output-classes-dir` — where obfuscated `.class` files are written
- `config.json` — pass configuration (see [`obfuscator-config.example.json`](obfuscator-config.example.json))

After a run, the tool also writes next to the output directory:

- `mapping.txt` — original → obfuscated name mapping for classes, methods and fields
- `obf_jni_map.h` — header mapping for native code that references obfuscated symbols
- `smali_references.txt` — reference list for patching smali/manifest resources

## Configuration

Copy `obfuscator-config.example.json` to `obfuscator-config.json` and adjust:

| Key | Description |
|---|---|
| `excludeClasses` | Classes (and their inner classes) to leave untouched |
| `enableJniFieldProtection` / `jniKeepFields` | Keep specific fields intact for native (JNI) access |
| `enableRename` | Rename classes, methods and fields |
| `enableStringEncryption` | Encrypt string constants |
| `enableOpaquePredicates` | Insert opaque predicates into control flow |
| `enableControlFlow` | General control-flow obfuscation |
| `enableIllegalIdentifiers` | Use decompiler-breaking identifiers |
| `enableFakeTryCatch` | Insert unreachable exception handlers |
| `enableControlFlowFlattening` | Flatten control flow into a dispatcher |
| `enableNumberObfuscation` | Rewrite numeric constants as expressions |
| `enableGotoObfuscation` | Rewrite control flow using goto chains |
| `enableReflectionProxy` | Route calls through reflection |
| `enableSourceErase` | Strip `SourceFile` attributes |
| `enableBogusBlocks` | Insert dead/junk code blocks |
| `enableFieldScramble` | Scramble field declaration order |
| `enableIrreducibleFlow` | Introduce irreducible control-flow graphs |
| `enableReflectiveDispatch` | Dispatch selected calls reflectively |
| `androidJarPath` | Path to the Android SDK's `android.jar` for the target API level |

## Project layout

```
src/obfuscator/
  Main.java                 entry point, pass pipeline, class writing, method splitting
  config/ObfuscatorConfig.java
  core/
    ClassScanner.java       loads .class files into ASM ClassNodes
    JNIDetector.java        detects native method usage
    MappingRegistry.java    records and exports the rename mapping
    ObfuscationPass.java    pass interface
  passes/
    RenamePass.java
    StringEncryptPass.java
    ReflectionProxyPass.java
    NumberObfuscationPass.java
    OpaquePredicatePass.java
    BogusBlockPass.java
    FieldScramblePass.java
    IrreducibleFlowPass.java
    FakeTryCatchPass.java
    GotoObfuscationPass.java
    ControlFlowPass.java
    IllegalIdentifierPass.java
    SourceFileErasePass.java
```

## Disclaimer

This tool is intended for protecting code you own or have the rights to obfuscate (e.g. hardening your own release builds against reverse engineering). You are responsible for complying with the licenses of any code you process.

## License

MIT — see [LICENSE](LICENSE).
