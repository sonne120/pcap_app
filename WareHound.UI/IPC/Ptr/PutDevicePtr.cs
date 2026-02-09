using System.Runtime.InteropServices;

namespace WareHound.UI.IPC.Ptr
{
    public static class PutDevicePtr
    {
        private const string DllName = "WareHound.Sniffer.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "fnPutdevCPPDLL")]
        private static extern void fnPutdevCPPDLL(int dev);

        public static void SelectDevice(int deviceIndex)
        {
            fnPutdevCPPDLL(deviceIndex);
        }
    }
}
