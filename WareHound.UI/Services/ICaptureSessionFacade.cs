using System.Collections.ObjectModel;
using WareHound.UI.Models;

namespace WareHound.UI.Services
{

    public interface ICaptureSessionFacade
    {
        ObservableCollection<NetworkDevice> Devices { get; }
        NetworkDevice? SelectedDevice { get; }
        bool IsLoadingDevices { get; }
        Task LoadDevicesAsync(TimeSpan timeout);
        void SelectDevice(int deviceIndex);
        bool IsCapturing { get; }
        void StartCapture();
        void StopCapture();
        IAsyncEnumerable<IList<PacketInfo>> GetPacketBatchesAsync(CancellationToken ct);
        Task<IList<PacketInfo>> LoadPcapAsync(string filePath);
        Task SavePcapAsync(string filePath, IList<PacketInfo> packets);

        event Action<bool>? CaptureStateChanged;
        event Action<string>? ErrorOccurred;
        event Action? DevicesLoaded;
    }
}
