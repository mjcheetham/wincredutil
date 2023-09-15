using System.CommandLine;
using System.Runtime.InteropServices;
using wincred;
using static wincred.Native;

var rootCmd = new RootCommand("Utility for interacting with the Windows Credential Manager.");

var listCmd = new Command("list", "List credential entries.");
var filterArg = new Option<string>("--filter", "Wildcard filter to match credentials.");
var countArg = new Option<bool>("--count", "Print the number of returned entries only.");
var showSecretArg = new Option<bool>("-w", "Print secret values as a string."); 
listCmd.AddOption(filterArg);
listCmd.AddOption(countArg);
listCmd.AddOption(showSecretArg);
listCmd.SetHandler(List, filterArg, countArg, showSecretArg);
rootCmd.AddCommand(listCmd);

return await rootCmd.InvokeAsync(args);

void PrintCredential(Win32Credential c, bool showSecret)
{
    Console.WriteLine("Target name   : {0}", c.TargetName);
    Console.WriteLine("User name     : {0}", c.UserName);
    Console.WriteLine("Type          : {0}", c.Type.ToString());
    Console.WriteLine("Last modified : {0:u}", c.LastWrittenDateTime);

    if (showSecret)
    {
        string? secretStr = c.GetCredentialBlobAsString();
        Console.WriteLine("Secret        : {0}", secretStr);
    }
    else
    {
        Console.WriteLine("Secret        : ********");
    }

    Console.WriteLine();
}

void List(string? filter, bool countOnly, bool showSecret)
{
    var flags = string.IsNullOrWhiteSpace(filter)
        ? CredentialEnumerateFlags.AllCredentials
        : CredentialEnumerateFlags.None;
    
    IntPtr credList = IntPtr.Zero;

    try
    {
        ThrowIfError(
            CredEnumerate(filter, flags, out int count, out credList)
        );

        if (countOnly)
        {
            Console.WriteLine(count);
            return;
        }

        int ptrSize = Marshal.SizeOf<IntPtr>();
        for (int i = 0; i < count; i++)
        {
            IntPtr credPtr = Marshal.ReadIntPtr(credList, i * ptrSize);
            Win32Credential credential = Marshal.PtrToStructure<Win32Credential>(credPtr);

            PrintCredential(credential, showSecret);
        }

    }
    finally
    {
        if (credList != IntPtr.Zero)
        {
            CredFree(credList);
        }
    }
}
