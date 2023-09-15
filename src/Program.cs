using System.CommandLine;

var cmd = new RootCommand("Utility for interacting with the Windows Credential Manager.");
return await cmd.InvokeAsync(args);
