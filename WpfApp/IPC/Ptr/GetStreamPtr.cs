using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace wpfapp.IPC.Ptr
{
    public static class GetStreamPtr
    {

        [DllImport("sniffer_packages.dll", EntryPoint = "fnCPPDLL", CallingConvention = CallingConvention.StdCall)]
        private static extern void fnCPPDLL(int dev);

        private static readonly object _sync = new();
        private static bool _isInitialized = false;
        private static Thread? _workerThread;
        private static int _activeDev = -1;
        private static string? _customPath;
        private static Action<string>? _logger;

        public static void SetCustomPath(string absolutePath)
        {
            if (string.IsNullOrWhiteSpace(absolutePath))
                throw new ArgumentException("Path is empty.", nameof(absolutePath));
            if (!Path.IsPathFullyQualified(absolutePath))
                throw new ArgumentException("Path must be absolute.", nameof(absolutePath));
            _customPath = absolutePath;
        }

        public static void SetLogger(Action<string> logger) => _logger = logger;

        public static bool IsLoaded => _isInitialized;
        public static bool IsRunning => _workerThread is { IsAlive: true };

    
        public static void StartStream(int dev)
        {
            lock (_sync)
            {
                if (_isInitialized)
                {
                    return;
                }

                _activeDev = dev;
                _workerThread = new Thread(() =>
                {
                    try
                    {
                        fnCPPDLL(dev);
                    }
                    catch (DllNotFoundException ex)
                    {
                        _logger?.Invoke($"GetStreamPtr  ERROR: sniffer_packages.dll not found: {ex.Message}");
                    }
                    catch (Exception ex)
                    {
                        _logger?.Invoke($"GetStreamPtr Worker thread error: {ex.GetType().Name} - {ex.Message}");
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
                _isInitialized = false;
                _activeDev = -1;
            }
        }
    }
}

