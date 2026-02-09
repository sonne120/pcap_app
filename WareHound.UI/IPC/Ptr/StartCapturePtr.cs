using System.Diagnostics;
using WareHound.UI.Infrastructure.Services;
using System.Runtime.InteropServices;

namespace WareHound.UI.IPC.Ptr
{

    public static class StartCapturePtr
    {
        private static ILoggerService? _logger;

        public static void SetLogger(ILoggerService logger) => _logger = logger;

        private const string DllName = "WareHound.Sniffer.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "fnStartCapture")]
        private static extern void fnStartCapture();
        public static void Start()
        {
            _logger?.LogDebug("[StartCapturePtr] Calling fnStartCapture()...");
            fnStartCapture();
            _logger?.LogDebug("[StartCapturePtr] fnStartCapture() completed");
        }
    }
}
