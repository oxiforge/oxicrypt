// Hashes, signs and establishes a shared secret through the oxicrypt C
// library, checking each result against the line examples/README.md expects.
//
//   dotnet Example.dll <bundle-dir> <out-dir>
//   dotnet Example.dll <bundle-dir> decaps <dk-file> <ct-file>
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

bool decapsMode = args.Length == 4 && args[1] == "decaps";
if (!decapsMode && args.Length != 2)
{
    Console.Error.WriteLine("usage: dotnet Example.dll <bundle-dir> <out-dir>\n       dotnet Example.dll <bundle-dir> decaps <dk-file> <ct-file>");
    return 2;
}
string name = OperatingSystem.IsWindows() ? "oxicrypt_ffi.dll"
    : OperatingSystem.IsMacOS() ? "liboxicrypt_ffi.4.dylib"
    : "liboxicrypt_ffi.so.4";
string path = Path.Combine(args[0], name);
NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(),
    (library, _, _) => library == Oxi.Library ? NativeLibrary.Load(path) : IntPtr.Zero);

try
{
    if (decapsMode)
    {
        Example.Decaps(args[2], args[3]);
    }
    else
    {
        Example.Run(args[1]);
    }
}
catch (Example.Failure)
{
    return 1;
}
catch (IOException e)
{
    // A line lost to a full disk or a closed pipe: a program that printed
    // fewer than nine lines must not exit 0.
    Console.Error.WriteLine($"stdout: {e.Message}");
    return 1;
}
finally
{
    Example.Release();
}
return 0;

static class Example
{
    const string MESSAGE = "The quick brown fox jumps over the lazy dog";
    const int SIG_FLIP_BYTE = 0;
    const int CT_FLIP_BYTE = 0;
    const string PERSONALIZATION = "oxicrypt example";
    const string SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    const int PkLen = 2592, SkLen = 4896, SigLen = 4627;
    const int EkLen = 1568, DkLen = 3168, CtLen = 1568, SsLen = 32;

    /// <summary>Thrown to end the program with status 1.</summary>
    public sealed class Failure : Exception { }

    static IntPtr rbg = IntPtr.Zero;
    // Pinned so the collector never moves them, which would leave a copy
    // of the secret that Release could not wipe.
    static readonly byte[] sk = GC.AllocateArray<byte>(SkLen, pinned: true);
    static readonly byte[] dk = GC.AllocateArray<byte>(DkLen, pinned: true);
    static readonly byte[] ss = GC.AllocateArray<byte>(SsLen, pinned: true);
    static readonly byte[] ss2 = GC.AllocateArray<byte>(SsLen, pinned: true);

    /// <summary>Frees the DRBG handle, which wipes its state, and wipes every
    /// secret. The hex string printed for the shared secret is a .NET string,
    /// which cannot be wiped.</summary>
    public static void Release()
    {
        Oxi.DrbgFree(rbg);
        rbg = IntPtr.Zero;
        foreach (byte[] secret in new[] { sk, dk, ss, ss2 })
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>Prints <paramref name="got"/> when it equals
    /// <paramref name="want"/>; otherwise prints both and fails.</summary>
    static void Expect(string want, string got)
    {
        if (want != got)
        {
            Console.Error.WriteLine($"expected: {want}\n     got: {got}");
            throw new Failure();
        }
        Console.WriteLine(got);
    }

    static void ExpectOk(string what, int rc) => Expect($"{what} ok", rc == 0 ? $"{what} ok" : $"{what} returned {rc}");

    /// <summary>Fails naming the call when it returned other than Ok.</summary>
    static void Check(string call, int rc)
    {
        if (rc != 0)
        {
            Console.Error.WriteLine($"{call} returned {rc}");
            throw new Failure();
        }
    }

    /// <summary>Writes the file, readable and writable by its owner only when
    /// <paramref name="ownerOnly"/> is set, as the decapsulation key is. An
    /// existing file keeps its mode through truncation, so the mode is set
    /// again. On Windows the file takes the access control list of its
    /// directory.</summary>
    static void Write(string dir, string file, byte[] data, bool ownerOnly = false)
    {
        string path = Path.Combine(dir, file);
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
            if (ownerOnly && !OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }
            using (var f = new FileStream(path, options))
            {
                if (ownerOnly && !OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(f.SafeFileHandle, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
                f.Write(data);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(e.Message);
            throw new Failure();
        }
    }

    static void Read(string file, byte[] into)
    {
        try
        {
            using FileStream f = File.OpenRead(file);
            if (f.Length != into.Length)
            {
                Console.Error.WriteLine($"{file}: expected {into.Length} bytes");
                throw new Failure();
            }
            f.ReadExactly(into);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(e.Message);
            throw new Failure();
        }
    }

    static string Hex(byte[] b) => Convert.ToHexStringLower(b);

    /// <summary>Starts the module and reads its integrity result. Prints the
    /// fingerprint of the key the library trusts to stderr, and fails unless
    /// the module is operational with its integrity test passed (status 1),
    /// leading with the condition that failed.</summary>
    static void Start()
    {
        int rc = Oxi.Init(0);
        int status = Oxi.IntegrityStatus();
        byte[] fp = new byte[32];
        int fpRc = Oxi.IntegrityKeyFingerprint(fp, (nuint)fp.Length);
        string fpLine = $"verify key sha256:{Hex(fp)}";
        if (rc == 0 && status == 1 && fpRc == 0)
        {
            Console.Error.WriteLine(fpLine);
            return;
        }
        if (rc != 0)
        {
            Console.Error.WriteLine($"oxi_init returned {rc}: the module refused to start");
        }
        else if (status != 1)
        {
            Console.Error.WriteLine($"oxi_init returned 0 but the integrity test reported status {status}, not 1 (passed)");
        }
        else
        {
            Console.Error.WriteLine($"oxi_integrity_key_fingerprint returned {fpRc} after the integrity test passed");
            throw new Failure();
        }
        Console.Error.WriteLine($"integrity status {status}");
        Console.Error.WriteLine(fpRc == 0 ? fpLine : $"oxi_integrity_key_fingerprint returned {fpRc}");
        throw new Failure();
    }

    public static void Decaps(string dkFile, string ctFile)
    {
        Start();
        byte[] ct = new byte[CtLen];
        Read(dkFile, dk);
        Read(ctFile, ct);
        Check("oxi_ml_kem_1024_decapsulate", Oxi.MlKem1024Decapsulate(dk, ct, ss));
        Console.WriteLine($"ml-kem-1024 ss {Hex(ss)}");
    }

    /// <summary>Decapsulates <paramref name="ct"/> into ss2 and describes the
    /// result against ss.</summary>
    static string DecapsLine(string what, byte[] ct)
    {
        int rc = Oxi.MlKem1024Decapsulate(dk, ct, ss2);
        if (rc != 0)
        {
            return $"{what} returned {rc}";
        }
        return $"{what} {(CryptographicOperations.FixedTimeEquals(ss, ss2) ? "match" : "differs")}";
    }

    public static void Run(string outDir)
    {
        Start();

        byte[] abc = Encoding.ASCII.GetBytes("abc");
        byte[] digest = new byte[32];
        Check("oxi_sha256", Oxi.Sha256(abc, (nuint)abc.Length, digest));
        Expect($"sha256 abc {SHA256_ABC}", $"sha256 abc {Hex(digest)}");

        Check("oxi_hmac_drbg_sha256_new_rbg", Oxi.HmacDrbgSha256NewRbg(out rbg));
        byte[] perso = Encoding.ASCII.GetBytes(PERSONALIZATION);
        Check("oxi_drbg_instantiate", Oxi.DrbgInstantiate(rbg, perso, (nuint)perso.Length));
        Console.WriteLine("drbg instantiated");

        byte[] message = Encoding.ASCII.GetBytes(MESSAGE);
        nuint msgLen = (nuint)message.Length;
        byte[] pk = new byte[PkLen], sig = new byte[SigLen];
        ExpectOk("ml-dsa-87 keygen", Oxi.MlDsa87KeygenRbg(rbg, pk, sk, null));
        Check("oxi_ml_dsa_87_sign", Oxi.MlDsa87Sign(sk, message, msgLen, null, 0, sig));
        Write(outDir, "pk.bin", pk);
        Write(outDir, "message.txt", message);
        Write(outDir, "sig.bin", sig);
        ExpectOk("ml-dsa-87 verify", Oxi.MlDsa87Verify(pk, message, msgLen, null, 0, sig));
        byte[] tamperedSig = (byte[])sig.Clone();
        tamperedSig[SIG_FLIP_BYTE] ^= 0x01;
        int rc = Oxi.MlDsa87Verify(pk, message, msgLen, null, 0, tamperedSig);
        Expect("ml-dsa-87 verify-tampered rejected 22",
            rc == 0 ? "ml-dsa-87 verify-tampered accepted" : $"ml-dsa-87 verify-tampered rejected {rc}");

        byte[] ek = new byte[EkLen], ct = new byte[CtLen];
        ExpectOk("ml-kem-1024 keygen", Oxi.MlKem1024KeygenRbg(rbg, ek, dk, null));
        Check("oxi_ml_kem_1024_encapsulate_rbg", Oxi.MlKem1024EncapsulateRbg(ek, rbg, ss, ct));
        Write(outDir, "ek.bin", ek);
        Write(outDir, "dk.bin", dk, ownerOnly: true);
        Write(outDir, "ct.bin", ct);
        Expect("ml-kem-1024 decaps match", DecapsLine("ml-kem-1024 decaps", ct));
        byte[] tamperedCt = (byte[])ct.Clone();
        tamperedCt[CT_FLIP_BYTE] ^= 0x01;
        Expect("ml-kem-1024 decaps-tampered differs", DecapsLine("ml-kem-1024 decaps-tampered", tamperedCt));

        Console.WriteLine($"ml-kem-1024 ss {Hex(ss)}");
    }
}

static class Oxi
{
    public const string Library = "oxicrypt_ffi";

    [DllImport(Library, EntryPoint = "oxi_init")]
    public static extern int Init(int profile);

    [DllImport(Library, EntryPoint = "oxi_integrity_status")]
    public static extern int IntegrityStatus();

    [DllImport(Library, EntryPoint = "oxi_integrity_key_fingerprint")]
    public static extern int IntegrityKeyFingerprint([Out] byte[] fp, nuint fpLen);

    [DllImport(Library, EntryPoint = "oxi_sha256")]
    public static extern int Sha256(byte[] data, nuint dataLen, [Out] byte[] digest);

    [DllImport(Library, EntryPoint = "oxi_hmac_drbg_sha256_new_rbg")]
    public static extern int HmacDrbgSha256NewRbg(out IntPtr handle);

    [DllImport(Library, EntryPoint = "oxi_drbg_instantiate")]
    public static extern int DrbgInstantiate(IntPtr handle, byte[] perso, nuint persoLen);

    [DllImport(Library, EntryPoint = "oxi_drbg_free")]
    public static extern void DrbgFree(IntPtr handle);

    [DllImport(Library, EntryPoint = "oxi_ml_dsa_87_keygen_rbg")]
    public static extern int MlDsa87KeygenRbg(IntPtr rbg, [Out] byte[] pk, [Out] byte[] sk, [Out] byte[]? seed);

    [DllImport(Library, EntryPoint = "oxi_ml_dsa_87_sign")]
    public static extern int MlDsa87Sign(byte[] sk, byte[] msg, nuint msgLen, byte[]? ctx, nuint ctxLen, [Out] byte[] sig);

    [DllImport(Library, EntryPoint = "oxi_ml_dsa_87_verify")]
    public static extern int MlDsa87Verify(byte[] pk, byte[] msg, nuint msgLen, byte[]? ctx, nuint ctxLen, byte[] sig);

    [DllImport(Library, EntryPoint = "oxi_ml_kem_1024_keygen_rbg")]
    public static extern int MlKem1024KeygenRbg(IntPtr rbg, [Out] byte[] ek, [Out] byte[] dk, [Out] byte[]? seed);

    [DllImport(Library, EntryPoint = "oxi_ml_kem_1024_encapsulate_rbg")]
    public static extern int MlKem1024EncapsulateRbg(byte[] ek, IntPtr rbg, [Out] byte[] ss, [Out] byte[] ct);

    [DllImport(Library, EntryPoint = "oxi_ml_kem_1024_decapsulate")]
    public static extern int MlKem1024Decapsulate(byte[] dk, byte[] ct, [Out] byte[] ss);
}
