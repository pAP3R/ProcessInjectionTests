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
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);
        [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);



        public void sir_Injection(string processName, bool path)
        {
            // SuspendThread
            // OpenProcess (For DLL)
            // VirtualAllocEx
            // LoadLibraryA (For DLL)
            // WriteProcessMemory
            // PTHREAD_START_ROUTINE
            // QueueUserAPC
            // ResumeThread

            Console.WriteLine("[+] Attempting to find " + processName);
            Process proc = Process.GetProcessesByName(processName)[0];

            // Suspend process and threads
            // https://stackoverflow.com/questions/71257/suspend-process-in-c-sharp

            Console.WriteLine("[+] Process has " + proc.Threads.Count + " threads, attempting to suspend them");

            foreach (ProcessThread pT in proc.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                SuspendThread(pOpenThread);
                CloseHandle(pOpenThread);
            }





            // Finally, resume the process
            Console.WriteLine("[+] Resuming process...");
            foreach (ProcessThread pT in proc.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                var suspendCount = 0;
                do
                {
                    suspendCount = ResumeThread(pOpenThread);
                } while (suspendCount > 0);

                CloseHandle(pOpenThread);
                Console.WriteLine("[+] Process resumed!");
            }

        }
    }
}
