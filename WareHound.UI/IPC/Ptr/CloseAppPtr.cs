using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using WareHound.UI.Infrastructure.Services;

namespace WareHound.UI.IPC.Ptr
{
    public static class CloseAppPtr
    {
        private static ILoggerService? _logger;

        public static void SetLogger(ILoggerService logger) => _logger = logger;

        private const string DllName = "WareHound.Sniffer.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "fnCloseApp")]
        private static extern void fnCloseApp();

        public static void Close()
        {
            _logger?.LogDebug("[CloseAppPtr] Close called, invoking fnCloseApp with timeout...");

            var closeTask = Task.Run(() =>
            {
                try
                {
                    fnCloseApp();
                    _logger?.LogDebug("[CloseAppPtr] fnCloseApp completed");
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"[CloseAppPtr] fnCloseApp error: {ex.Message}", ex);
                }
            });

            if (!closeTask.Wait(TimeSpan.FromSeconds(5)))
            {
                _logger?.LogError("[CloseAppPtr] WARNING: fnCloseApp timed out after 5 seconds");
            }
            else
            {
                _logger?.LogDebug("[CloseAppPtr] fnCloseApp completed successfully");
            }
        }
    }
}
