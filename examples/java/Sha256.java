import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HexFormat;

/** Prints the SHA-256 digest of "abc", computed by the oxicrypt C library
 *  loaded from the bundle directory given as the first argument. */
public class Sha256 {
    public static void main(String[] args) throws Throwable {
        if (args.length != 1) {
            System.err.println("usage: java Sha256 <bundle-dir>");
            System.exit(2);
        }
        String os = System.getProperty("os.name").toLowerCase();
        String name = os.startsWith("windows") ? "oxicrypt_ffi.dll"
                : os.startsWith("mac") ? "liboxicrypt_ffi.1.dylib"
                : "liboxicrypt_ffi.so.1";
        Linker linker = Linker.nativeLinker();
        try (Arena arena = Arena.ofConfined()) {
            SymbolLookup lib = SymbolLookup.libraryLookup(Path.of(args[0], name), arena);
            MethodHandle oxiInit = linker.downcallHandle(lib.find("oxi_init").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
            // uintptr_t is 64 bits wide on every platform a bundle is built for.
            MethodHandle oxiSha256 = linker.downcallHandle(lib.find("oxi_sha256").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

            int rc = (int) oxiInit.invokeExact(0);
            if (rc != 0) {
                System.err.println("oxi_init returned " + rc + ": the module refused to start");
                System.exit(1);
            }
            byte[] abc = "abc".getBytes(StandardCharsets.US_ASCII);
            MemorySegment data = arena.allocateFrom(ValueLayout.JAVA_BYTE, abc);
            MemorySegment out = arena.allocate(32);
            rc = (int) oxiSha256.invokeExact(data, (long) abc.length, out);
            if (rc != 0) {
                System.err.println("oxi_sha256 returned " + rc);
                System.exit(1);
            }
            System.out.println(HexFormat.of().formatHex(out.toArray(ValueLayout.JAVA_BYTE)));
        }
    }
}
