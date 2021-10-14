# ProcessInjectionTests

This is a small repo for testing process injection techniques as I learn to write them. It consists of multiple projects under a single solution, with the 'Inject' project being a C# DLL used for injection testing.


## ProcessInjection_Test1

This project contains a number of methods for injection DLLs and shellcode into the memory space of different processes.

The crt_Injection() function uses the classic CreateRemoteThread() workflow, obviously. It's no different than other C# implementations of the same, I wrote it to learn more about the Windows API and get my hands wet with C# again. I found a nice resource in C++ and worked to convert it.


Current Usage:

		.\ProcessInjection_Test1.exe Target_Proc Type
	e.g.
		.\ProcessInjection_Test1.exe notepad crt
