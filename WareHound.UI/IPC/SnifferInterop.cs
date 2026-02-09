using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using WareHound.UI.IPC.Ptr;

namespace WareHound.UI.IPC
{
    public class SnifferInterop : ISnifferInterop
    {
        private const string DllName = "WareHound.Sniffer.dll";
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr Sniffer_Create();
        
        private static IntPtr _snifferHandle = IntPtr.Zero;
        private bool _disposed;

        public List<string> GetDevices()
        {
            return new List<string>(DevicesPtr.GetAllDevices());
        }

        public void Initialize(int deviceIndex)
        {
            if (_snifferHandle == IntPtr.Zero)
            {
                try
                {
                    _snifferHandle = Sniffer_Create();
                }
                catch
                {
                    _snifferHandle = IntPtr.Zero;
                }
            }
            
            StreamPtr.StartStream(deviceIndex);
        }

        public void SelectDevice(int deviceIndex)
        {
            PutDevicePtr.SelectDevice(deviceIndex);
        }

        public void Start()
        {
            StartCapturePtr.Start();
        }

        public void Stop()
        {
            StopCapturePtr.Stop();
            Thread.Sleep(200);
        
            StreamPtr.Reset();
        }
        
        public IntPtr GetSnifferHandle()
        {
            return _snifferHandle;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                CloseAppPtr.Close();
                StreamPtr.Reset();
                _snifferHandle = IntPtr.Zero;
                _disposed = true;
            }
        }
    }
}
