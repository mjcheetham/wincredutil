using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace wincred;

public static class Native
{
    private const string Advapi = "advapi32.dll";

    [DllImport(Advapi, EntryPoint = "CredReadW", CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredRead(
        string target,
        CredentialType type,
        int reserved,
        out IntPtr credential);

    [DllImport(Advapi, EntryPoint = "CredWriteW", CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredWrite(
        ref Win32Credential credential,
        int flags);

    [DllImport(Advapi, EntryPoint = "CredDeleteW", CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredDelete(
        string target,
        CredentialType type,
        int flags);

    [DllImport(Advapi, EntryPoint = "CredFree", CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern void CredFree(
        IntPtr credential);

    [DllImport(Advapi, EntryPoint = "CredEnumerateW", CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredEnumerate(
        string? filter,
        CredentialEnumerateFlags flags,
        out int count,
        out IntPtr credentialsList);

    [DllImport(Advapi, EntryPoint = "CredGetSessionTypes", CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredGetSessionTypes(
        uint maximumPersistCount,
        [In, Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)]
        CredentialPersist[] maximumPersist);

    // Values from wincred.h
    public const uint CRED_TYPE_MAXIMUM = 7;
    public const uint CRED_TYPE_MAXIMUM_EX = CRED_TYPE_MAXIMUM + 1000;
    
    public static int GetLastError(bool result)
    {
        return result ? 0 : Marshal.GetLastWin32Error();
    }

    public static void ThrowIfError(int error)
    {
        switch (error)
        {
            case 0:
                return;
            default:
                // The Win32Exception constructor will automatically get the human-readable
                // message for the error code.
                throw new Win32Exception(error);
        }
    }

    public static void ThrowIfError(bool result)
    {
        ThrowIfError(GetLastError(result));
    }
}

// Enum values from wincred.h
public enum CredentialType
{
    Generic = 1,
    DomainPassword = 2,
    DomainCertificate = 3,
    DomainVisiblePassword = 4,
    GenericCertificate = 5,
    DomainExtended = 6
}

public enum CredentialPersist
{
    None = 0,
    Session = 1,
    LocalMachine = 2,
    Enterprise = 3,
}

[Flags]
public enum CredentialEnumerateFlags
{
    None = 0,
    AllCredentials = 0x1
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct Win32Credential
{
    public int Flags;
    public CredentialType Type;
    [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
    [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
    public FILETIME LastWritten;
    public int CredentialBlobSize;
    public IntPtr CredentialBlob;
    public CredentialPersist Persist;
    public int AttributeCount;
    public IntPtr Attributes;
    [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
    [MarshalAs(UnmanagedType.LPWStr)] public string? UserName;

    public DateTime LastWrittenDateTime => DateTime.FromFileTime(
        ((long)LastWritten.dwHighDateTime << 32) + LastWritten.dwLowDateTime
    );

    public string? GetCredentialBlobAsString()
    {
        if (CredentialBlobSize != 0 && CredentialBlob != IntPtr.Zero)
        {
            var passwordBytes = new byte[CredentialBlobSize];
            Marshal.Copy(CredentialBlob, passwordBytes, 0, passwordBytes.Length);
            return Encoding.Unicode.GetString(passwordBytes);
        }

        return null;
    }
}