﻿using System.CommandLine;
using System.Runtime.InteropServices;
using wincred;
using static wincred.Native;

var rootCmd = new RootCommand("Utility for interacting with the Windows Credential Manager.");

var listCmd = new Command("list", "List credential entries.");
var filterArg = new Option<string>("--filter", "Wildcard filter to match credentials.");
listCmd.AddOption(filterArg);
listCmd.SetHandler(List, filterArg);
rootCmd.AddCommand(listCmd);

return await rootCmd.InvokeAsync(args);

void PrintCredential(Win32Credential c)
{
    Console.WriteLine("Target name   : {0}", c.TargetName);
    Console.WriteLine("User name     : {0}", c.UserName);
    Console.WriteLine("Type          : {0}", c.Type.ToString());
    Console.WriteLine("Last modified : {0:u}", c.LastWrittenDateTime);
    Console.WriteLine();
}

void List(string? filter)
{
    var flags = string.IsNullOrWhiteSpace(filter)
        ? CredentialEnumerateFlags.AllCredentials
        : CredentialEnumerateFlags.None;
    
    ThrowIfError(
        CredEnumerate(filter, flags, out int count, out IntPtr ptr)
    );

    int ptrSize = Marshal.SizeOf<IntPtr>();
    for (int i = 0; i < count; i++)
    {
        IntPtr credPtr = Marshal.ReadIntPtr(ptr, i * ptrSize);
        Win32Credential credential = Marshal.PtrToStructure<Win32Credential>(credPtr);

        PrintCredential(credential);
    }
}
