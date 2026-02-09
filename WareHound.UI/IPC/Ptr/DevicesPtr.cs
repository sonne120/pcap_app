using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WareHound.UI.IPC.Ptr
{
    public static class DevicesPtr
    {
        private const string DllName = "WareHound.Sniffer.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "fnDevCPPDLL")]
        private static extern void fnDevCPPDLL(nint[]? data, int[]? sizes, ref int count);
        public static IEnumerable<string> GetAllDevices()
        {
            int count = 0;
            fnDevCPPDLL(null, null, ref count);

            if (count <= 0)
                yield break;

            nint[] data = new nint[count];
            int[] sizes = new int[count];

            fnDevCPPDLL(data, sizes, ref count);

            for (int i = 0; i < count; i++)
            {
                if (data[i] != nint.Zero)
                {
                    string? deviceName = Marshal.PtrToStringAnsi(data[i], sizes[i]);
                    yield return deviceName ?? string.Empty;
                }
            }
        }
    }
}
