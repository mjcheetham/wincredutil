using System.CommandLine;
using System.Runtime.InteropServices;
using System.Text;
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

var addCmd = new Command("add", "Add a new credential.");
var nameArg = new Option<string>("--name", "Target name of the credential.") { IsRequired = true };
var userArg = new Option<string>("--username", "User name associated with the credential.");
var secretArg = new Option<string>("--secret", "Secret value.") { IsRequired = true };
addCmd.AddOption(nameArg);
addCmd.AddOption(userArg);
addCmd.AddOption(secretArg);
addCmd.SetHandler(Add, nameArg, userArg, secretArg);
rootCmd.AddCommand(addCmd);

var deleteCmd = new Command("delete", "Delete an existing credential.");
deleteCmd.AddOption(nameArg);
deleteCmd.SetHandler(Delete, nameArg);
rootCmd.AddCommand(deleteCmd);

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

void Add(string name, string? userName, string secret)
{
    IntPtr credBlob = IntPtr.Zero;
    
    try
    {
        var cred = new Win32Credential
        {
            Type = CredentialType.Generic,
            TargetName = name,
            UserName = userName,
            Persist = CredentialPersist.LocalMachine
        };

        byte[] secretBytes = Encoding.Unicode.GetBytes(secret);
        credBlob = Marshal.AllocHGlobal(secretBytes.Length);
        Marshal.Copy(secretBytes, 0, credBlob, secretBytes.Length);

        cred.CredentialBlob = credBlob;
        cred.CredentialBlobSize = secretBytes.Length;
        
        ThrowIfError(
            CredWrite(ref cred, 0)
        );

    }
    finally
    {
        if (credBlob != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(credBlob);
        }
    }
}


void Delete(string name)
{
    ThrowIfError(
        CredDelete(name, CredentialType.Generic, 0)
    );
}
