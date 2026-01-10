using System;
using System.Runtime.InteropServices;

namespace wpfapp.IPC.Ptr
{
    public static class PutdevPtr
    {
        [DllImport("sniffer_packages.dll", EntryPoint = "fnPutdevCPPDLL", CallingConvention = CallingConvention.StdCall)]
        private static extern void fnPutdevCPPDLL(int dev);

        public static void PutDev(int dev)
        {
            fnPutdevCPPDLL(dev);
        }
    }
}
