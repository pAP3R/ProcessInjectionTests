# ProcessInjectionTests

This is a small repo for testing process injection techniques as I learn to write them. It consists of multiple projects under a single solution, with the 'Inject' project being a C# DLL used for injection testing.



## ProcessInjection_Test1

This project utilizes the CreateRemoteThread() API to inject a specified DLL into another processes memory space. It's no different than other C# implementations of the same, I wrote it to learn more about the Windows API and get my hands wet with C# again. I found a nice resource in C++ and worked to convert it.


Usage:

  .\ProcessInjection_Test1.exe DLL_PATH TargetProgram
  e.g.
    .\ProcessInjection_Test1.exe "C:\\Users\\Howard\\Desktop\\calc.dll" notepad
