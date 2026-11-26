// Prints the SHA-256 digest of "abc", computed by the oxicrypt C library
// loaded from the bundle directory given as the first argument.
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

if (args.Length != 1)
{
    Console.Error.WriteLine("usage: dotnet run -- <bundle-dir>");
    return 2;
}
string name = OperatingSystem.IsWindows() ? "oxicrypt_ffi.dll"
    : OperatingSystem.IsMacOS() ? "liboxicrypt_ffi.3.dylib"
    : "liboxicrypt_ffi.so.3";
string path = Path.Combine(args[0], name);
NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(),
    (library, _, _) => library == Oxi.Library ? NativeLibrary.Load(path) : IntPtr.Zero);

int rc = Oxi.Init(0);
if (rc != 0)
{
    Console.Error.WriteLine($"oxi_init returned {rc}: the module refused to start");
    return 1;
}
byte[] data = "abc"u8.ToArray();
byte[] digest = new byte[32];
rc = Oxi.Sha256(data, (nuint)data.Length, digest);
if (rc != 0)
{
    Console.Error.WriteLine($"oxi_sha256 returned {rc}");
    return 1;
}
Console.WriteLine(Convert.ToHexStringLower(digest));
return 0;

static class Oxi
{
    public const string Library = "oxicrypt_ffi";

    [DllImport(Library, EntryPoint = "oxi_init")]
    public static extern int Init(int profile);

    [DllImport(Library, EntryPoint = "oxi_sha256")]
    public static extern int Sha256(byte[] data, nuint dataLen, [Out] byte[] digest);
}
