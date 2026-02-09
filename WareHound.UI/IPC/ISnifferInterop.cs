using System.Collections.Generic;

namespace WareHound.UI.IPC
{
    public interface ISnifferInterop : System.IDisposable
    {
        List<string> GetDevices();
        void Initialize(int deviceIndex);
        void SelectDevice(int deviceIndex);
        void Start();
        void Stop();
        IntPtr GetSnifferHandle();
    }
}
