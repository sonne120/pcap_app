using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using WareHound.UI.Infrastructure.Services;

namespace WareHound.UI.IPC.Ptr
{
    public static class StreamPtr
    {
        private static ILoggerService? _logger;

        public static void SetLogger(ILoggerService logger) => _logger = logger;

        private const string DllName = "WareHound.Sniffer.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "fnCPPDLL")]
        private static extern void fnCPPDLL(int dev);

        private static readonly object _sync = new();
        private static bool _isInitialized;
        private static Thread? _workerThread;
        private static int _activeDevice = -1;

        public static bool IsLoaded => _isInitialized;

        public static bool IsRunning => _workerThread is { IsAlive: true };

        public static void StartStream(int deviceIndex)
        {
            lock (_sync)
            {
                if (_isInitialized)
                    return;

                _activeDevice = deviceIndex;
                _workerThread = new Thread(() =>
                {
                    try
                    {
                        fnCPPDLL(deviceIndex);
                    }
                    catch (DllNotFoundException ex)
                    {
                        _logger?.LogError($"[StreamPtr] ERROR: DLL not found: {ex.Message}", ex);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogError($"[StreamPtr] Worker thread error: {ex.GetType().Name} - {ex.Message}", ex);
                    }
                })
                {
                    IsBackground = true,
                    Name = "SnifferCaptureThread"
                };

                _workerThread.Start();
                _isInitialized = true;
            }
        }
       
        public static void Reset()
        {
            lock (_sync)
            {
                if (_workerThread is { IsAlive: true })
                {
                    _logger?.LogDebug("[StreamPtr] Waiting for worker thread to terminate...");
                    _workerThread.Join(2000); 
                    
                    if (_workerThread.IsAlive)
                    {
                        _logger?.LogDebug("[StreamPtr] Worker thread did not terminate in time");
                    }
                    else
                    {
                        _logger?.LogDebug("[StreamPtr] Worker thread terminated successfully");
                    }
                }
                
                _workerThread = null;
                _isInitialized = false;
                _activeDevice = -1;
            }
        }
    }
}
