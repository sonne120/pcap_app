using System.Collections.ObjectModel;
using System.Runtime.CompilerServices;
using WareHound.UI.Models;

namespace WareHound.UI.Services
{
    public interface ISnifferService : IDisposable
    {
        ObservableCollection<NetworkDevice> Devices { get; }
        IAsyncEnumerable<IList<PacketInfo>> GetPacketBatchesAsync(CancellationToken ct = default);
        bool IsCapturing { get; }
        int SelectedDeviceIndex { get; }
        bool IsLoadingDevices { get; }
        void LoadDevices();
        Task LoadDevicesAsync(CancellationToken cancellationToken = default);
        Task LoadDevicesAsync(TimeSpan timeout);
        void SelectDevice(int deviceIndex);
        void StartCapture();
        void StartCapture(int deviceIndex);
        void StopCapture(); 
        IntPtr GetSnifferHandle();
       
        event Action<string>? ErrorOccurred;
        event Action? DevicesLoaded;
        event Action? DevicesLoadingStarted;
    }
}
