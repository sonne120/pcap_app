using System.Runtime.InteropServices;

namespace wpfapp.IPC.Ptr
{
    /// <summary>
    /// P/Invoke wrapper for fnStopCapture - signals C++ to stop packet capture
    /// </summary>
    public static class StopCapturePtr
    {
        [DllImport("sniffer_packages.dll", EntryPoint = "fnStopCapture", CallingConvention = CallingConvention.StdCall)]
        private static extern void fnStopCapture();

        public static void Stop()
        {
            System.Diagnostics.Debug.WriteLine("[StopCapturePtr] Calling fnStopCapture()...");
            fnStopCapture();
            System.Diagnostics.Debug.WriteLine("[StopCapturePtr] fnStopCapture() completed");
        }
    }
}
