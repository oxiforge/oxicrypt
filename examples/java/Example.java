import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;

/** Hashes, signs and establishes a shared secret through the oxicrypt C
 *  library, checking each result against the line examples/README.md
 *  expects.
 *
 *  <pre>
 *  java Example &lt;bundle-dir&gt; &lt;out-dir&gt;
 *  java Example &lt;bundle-dir&gt; decaps &lt;dk-file&gt; &lt;ct-file&gt;
 *  </pre> */
public class Example {
    static final String MESSAGE = "The quick brown fox jumps over the lazy dog";
    static final int SIG_FLIP_BYTE = 0;
    static final int CT_FLIP_BYTE = 0;
    static final String PERSONALIZATION = "oxicrypt example";
    static final String SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    static final int PK_LEN = 2592, SK_LEN = 4896, SIG_LEN = 4627;
    static final int EK_LEN = 1568, DK_LEN = 3168, CT_LEN = 1568, SS_LEN = 32;

    static final ValueLayout.OfInt INT = ValueLayout.JAVA_INT;
    static final MemoryLayout PTR = ValueLayout.ADDRESS;
    static final MemoryLayout SIZE = Linker.nativeLinker().canonicalLayouts().get("size_t");

    /** Thrown to end the program with status 1 once the arena has closed. */
    static final class Failure extends Exception {}

    final Arena arena;
    final SymbolLookup lib;
    final Linker linker = Linker.nativeLinker();
    final MemorySegment sk, dk, ss, ss2;
    MemorySegment rbg = MemorySegment.NULL;

    Example(Arena arena, String bundle) {
        String os = System.getProperty("os.name").toLowerCase();
        String name = os.startsWith("windows") ? "oxicrypt_ffi.dll"
                : os.startsWith("mac") ? "liboxicrypt_ffi.4.dylib"
                : "liboxicrypt_ffi.so.4";
        this.arena = arena;
        this.lib = SymbolLookup.libraryLookup(Path.of(bundle, name), arena);
        sk = arena.allocate(SK_LEN);
        dk = arena.allocate(DK_LEN);
        ss = arena.allocate(SS_LEN);
        ss2 = arena.allocate(SS_LEN);
    }

    MethodHandle fn(String symbol, MemoryLayout... args) {
        return linker.downcallHandle(lib.find(symbol).orElseThrow(), FunctionDescriptor.of(INT, args));
    }

    int call(String symbol, MemoryLayout[] layouts, Object... args) throws Throwable {
        return (int) fn(symbol, layouts).invokeWithArguments(args);
    }

    static MemoryLayout[] sig(MemoryLayout... layouts) { return layouts; }

    /** Frees the DRBG handle, which wipes its state, and wipes every secret.
     *  The secrets live in native memory, which is wiped here; the hex string
     *  printed for the shared secret is a Java String, which cannot be, and
     *  the collector may have copied the byte array it was formatted from. */
    void release() throws Throwable {
        linker.downcallHandle(lib.find("oxi_drbg_free").orElseThrow(), FunctionDescriptor.ofVoid(PTR))
                .invokeExact(rbg);
        rbg = MemorySegment.NULL;
        for (MemorySegment secret : new MemorySegment[] {sk, dk, ss, ss2}) {
            secret.fill((byte) 0);
        }
    }

    /** Prints {@code got} when it equals {@code want}; otherwise prints both and fails. */
    static void expect(String want, String got) throws Failure {
        if (!want.equals(got)) {
            System.err.println("expected: " + want + "\n     got: " + got);
            throw new Failure();
        }
        System.out.println(got);
    }

    static void expectOk(String what, int rc) throws Failure {
        expect(what + " ok", rc == 0 ? what + " ok" : what + " returned " + rc);
    }

    /** Fails naming the call when it returned other than Ok. */
    static void check(String call, int rc) throws Failure {
        if (rc != 0) {
            System.err.println(call + " returned " + rc);
            throw new Failure();
        }
    }

    /** Writes the file, readable and writable by its owner only when
     *  {@code ownerOnly} is set, as the decapsulation key is. An existing file
     *  keeps its mode through truncation, so the mode is set again. Where the
     *  file system has no POSIX permissions, as on Windows, the file takes
     *  the access control list of its directory. */
    static void write(String dir, String name, MemorySegment data, boolean ownerOnly) throws Failure {
        Path path = Path.of(dir, name);
        boolean posix = ownerOnly && path.getFileSystem().supportedFileAttributeViews().contains("posix");
        var ownerRw = PosixFilePermissions.fromString("rw-------");
        FileAttribute<?>[] attrs = posix
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(ownerRw)}
                : new FileAttribute<?>[0];
        try (FileChannel f = FileChannel.open(path, Set.of(StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE), attrs)) {
            if (posix) Files.setPosixFilePermissions(path, ownerRw);
            var b = data.asByteBuffer();
            while (b.hasRemaining()) f.write(b);
        } catch (IOException e) {
            System.err.println(e);
            throw new Failure();
        }
    }

    static void read(String path, MemorySegment into) throws Failure {
        try (FileChannel f = FileChannel.open(Path.of(path), StandardOpenOption.READ)) {
            if (f.size() != into.byteSize()) {
                System.err.println(path + ": expected " + into.byteSize() + " bytes");
                throw new Failure();
            }
            var b = into.asByteBuffer();
            while (b.hasRemaining() && f.read(b) >= 0) {}
            if (b.hasRemaining()) {
                System.err.println(path + ": expected " + into.byteSize() + " bytes");
                throw new Failure();
            }
        } catch (IOException e) {
            System.err.println(e);
            throw new Failure();
        }
    }

    static String hex(MemorySegment s) {
        byte[] bytes = s.toArray(ValueLayout.JAVA_BYTE);
        String text = HexFormat.of().formatHex(bytes);
        Arrays.fill(bytes, (byte) 0);
        return text;
    }

    /** Starts the module and reads its integrity result. Prints the
     *  fingerprint of the key the library trusts to stderr, and fails unless
     *  the module is operational with its integrity test passed (status 1),
     *  leading with the condition that failed. */
    void start() throws Throwable {
        int rc = call("oxi_init", sig(INT), 0);
        int status = call("oxi_integrity_status", sig());
        MemorySegment fp = arena.allocate(32);
        int fpRc = call("oxi_integrity_key_fingerprint", sig(PTR, SIZE), fp, fp.byteSize());
        String fpLine = "verify key sha256:" + hex(fp);
        if (rc == 0 && status == 1 && fpRc == 0) {
            System.err.println(fpLine);
            return;
        }
        if (rc != 0) {
            System.err.println("oxi_init returned " + rc + ": the module refused to start");
        } else if (status != 1) {
            System.err.println("oxi_init returned 0 but the integrity test reported status " + status
                    + ", not 1 (passed)");
        } else {
            System.err.println("oxi_integrity_key_fingerprint returned " + fpRc + " after the integrity test passed");
            throw new Failure();
        }
        System.err.println("integrity status " + status);
        System.err.println(fpRc == 0 ? fpLine : "oxi_integrity_key_fingerprint returned " + fpRc);
        throw new Failure();
    }

    /** Compares the two shared secrets in time independent of where they differ. */
    boolean sameSecret() {
        int diff = 0;
        for (long i = 0; i < SS_LEN; i++) {
            diff |= ss.get(ValueLayout.JAVA_BYTE, i) ^ ss2.get(ValueLayout.JAVA_BYTE, i);
        }
        return diff == 0;
    }

    void decaps(String dkPath, String ctPath) throws Throwable {
        start();
        MemorySegment ct = arena.allocate(CT_LEN);
        read(dkPath, dk);
        read(ctPath, ct);
        check("oxi_ml_kem_1024_decapsulate",
                call("oxi_ml_kem_1024_decapsulate", sig(PTR, PTR, PTR), dk, ct, ss));
        System.out.println("ml-kem-1024 ss " + hex(ss));
    }

    /** Decapsulates {@code ct} into ss2 and describes the result against ss. */
    String decapsLine(String what, MemorySegment ct) throws Throwable {
        int rc = call("oxi_ml_kem_1024_decapsulate", sig(PTR, PTR, PTR), dk, ct, ss2);
        if (rc != 0) return what + " returned " + rc;
        return what + (sameSecret() ? " match" : " differs");
    }

    void run(String out) throws Throwable {
        start();

        MemorySegment abc = arena.allocateFrom(ValueLayout.JAVA_BYTE, "abc".getBytes(StandardCharsets.US_ASCII));
        MemorySegment digest = arena.allocate(32);
        check("oxi_sha256", call("oxi_sha256", sig(PTR, SIZE, PTR), abc, abc.byteSize(), digest));
        expect("sha256 abc " + SHA256_ABC, "sha256 abc " + hex(digest));

        MemorySegment handle = arena.allocate(PTR);
        check("oxi_hmac_drbg_sha256_new_rbg", call("oxi_hmac_drbg_sha256_new_rbg", sig(PTR), handle));
        rbg = handle.get(ValueLayout.ADDRESS, 0);
        MemorySegment perso = arena.allocateFrom(ValueLayout.JAVA_BYTE,
                PERSONALIZATION.getBytes(StandardCharsets.US_ASCII));
        check("oxi_drbg_instantiate", call("oxi_drbg_instantiate", sig(PTR, PTR, SIZE), rbg, perso, perso.byteSize()));
        System.out.println("drbg instantiated");

        MemorySegment message = arena.allocateFrom(ValueLayout.JAVA_BYTE, MESSAGE.getBytes(StandardCharsets.US_ASCII));
        long msgLen = message.byteSize();
        MemorySegment pk = arena.allocate(PK_LEN), signature = arena.allocate(SIG_LEN);
        MemoryLayout[] signOrVerify = sig(PTR, PTR, SIZE, PTR, SIZE, PTR);
        expectOk("ml-dsa-87 keygen",
                call("oxi_ml_dsa_87_keygen_rbg", sig(PTR, PTR, PTR, PTR), rbg, pk, sk, MemorySegment.NULL));
        check("oxi_ml_dsa_87_sign", call("oxi_ml_dsa_87_sign", signOrVerify, sk, message, msgLen,
                MemorySegment.NULL, 0L, signature));
        write(out, "pk.bin", pk, false);
        write(out, "message.txt", message, false);
        write(out, "sig.bin", signature, false);
        expectOk("ml-dsa-87 verify", call("oxi_ml_dsa_87_verify", signOrVerify, pk, message, msgLen,
                MemorySegment.NULL, 0L, signature));
        MemorySegment tamperedSig = arena.allocate(SIG_LEN).copyFrom(signature);
        tamperedSig.set(ValueLayout.JAVA_BYTE, SIG_FLIP_BYTE,
                (byte) (tamperedSig.get(ValueLayout.JAVA_BYTE, SIG_FLIP_BYTE) ^ 0x01));
        int rc = call("oxi_ml_dsa_87_verify", signOrVerify, pk, message, msgLen, MemorySegment.NULL, 0L, tamperedSig);
        expect("ml-dsa-87 verify-tampered rejected 22",
                rc == 0 ? "ml-dsa-87 verify-tampered accepted" : "ml-dsa-87 verify-tampered rejected " + rc);

        MemorySegment ek = arena.allocate(EK_LEN), ct = arena.allocate(CT_LEN);
        expectOk("ml-kem-1024 keygen",
                call("oxi_ml_kem_1024_keygen_rbg", sig(PTR, PTR, PTR, PTR), rbg, ek, dk, MemorySegment.NULL));
        check("oxi_ml_kem_1024_encapsulate_rbg",
                call("oxi_ml_kem_1024_encapsulate_rbg", sig(PTR, PTR, PTR, PTR), ek, rbg, ss, ct));
        write(out, "ek.bin", ek, false);
        write(out, "dk.bin", dk, true);
        write(out, "ct.bin", ct, false);
        expect("ml-kem-1024 decaps match", decapsLine("ml-kem-1024 decaps", ct));
        MemorySegment tamperedCt = arena.allocate(CT_LEN).copyFrom(ct);
        tamperedCt.set(ValueLayout.JAVA_BYTE, CT_FLIP_BYTE,
                (byte) (tamperedCt.get(ValueLayout.JAVA_BYTE, CT_FLIP_BYTE) ^ 0x01));
        expect("ml-kem-1024 decaps-tampered differs", decapsLine("ml-kem-1024 decaps-tampered", tamperedCt));

        System.out.println("ml-kem-1024 ss " + hex(ss));
    }

    public static void main(String[] args) throws Throwable {
        boolean decapsMode = args.length == 4 && args[1].equals("decaps");
        if (!decapsMode && args.length != 2) {
            System.err.println("usage: java Example <bundle-dir> <out-dir>\n"
                    + "       java Example <bundle-dir> decaps <dk-file> <ct-file>");
            System.exit(2);
        }
        boolean failed = false;
        try (Arena arena = Arena.ofConfined()) {
            Example example = new Example(arena, args[0]);
            try {
                if (decapsMode) {
                    example.decaps(args[2], args[3]);
                } else {
                    example.run(args[1]);
                }
            } catch (Failure f) {
                failed = true;
            } finally {
                example.release();
            }
        }
        // System.out records a failed write instead of throwing it, and a
        // program that printed fewer than nine lines must not exit 0.
        if (System.out.checkError()) {
            System.err.println("stdout: a write failed");
            failed = true;
        }
        if (failed) System.exit(1);
    }
}
