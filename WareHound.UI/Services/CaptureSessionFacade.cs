using System.Collections.ObjectModel;
using WareHound.UI.Infrastructure.Services;
using WareHound.UI.Models;

namespace WareHound.UI.Services
{

    public class CaptureSessionFacade : ICaptureSessionFacade
    {
        private readonly ISnifferService _snifferService;
        private readonly PcapFileServiceFactory _pcapFactory;
        private readonly ILoggerService _logger;

        private NetworkDevice? _selectedDevice;
        private bool _isLoadingDevices;

        public ObservableCollection<NetworkDevice> Devices => _snifferService.Devices;

        public NetworkDevice? SelectedDevice => _selectedDevice;

        public bool IsLoadingDevices => _isLoadingDevices;

        public bool IsCapturing => _snifferService.IsCapturing;

        public event Action<bool>? CaptureStateChanged;
        public event Action<string>? ErrorOccurred;
        public event Action? DevicesLoaded;

        public CaptureSessionFacade(
            ISnifferService snifferService,
            PcapFileServiceFactory pcapFactory,
            ILoggerService logger)
        {
            _snifferService = snifferService ?? throw new ArgumentNullException(nameof(snifferService));
            _pcapFactory = pcapFactory ?? throw new ArgumentNullException(nameof(pcapFactory));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _snifferService.ErrorOccurred += OnSnifferError;
        }

        private void OnSnifferError(string error)
        {
            _logger.LogError($" Sniffer error: {error}");
            ErrorOccurred?.Invoke(error);
        }

        public async Task LoadDevicesAsync(TimeSpan timeout)
        {
            _isLoadingDevices = true;
            _logger.Log("Loading devices...");

            try
            {
                await _snifferService.LoadDevicesAsync(timeout);

                if (Devices.Count > 0 && _selectedDevice == null)
                {
                    SelectDevice(0);
                }

                _logger.Log($" Loaded {Devices.Count} devices");
                DevicesLoaded?.Invoke();
            }
            catch (TimeoutException ex)
            {
                _logger.LogError("Device loading timed out", ex);
                ErrorOccurred?.Invoke("Device loading timed out. Please retry.");
                throw;
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Device loading was cancelled");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError($" Failed to load devices: {ex.Message}", ex);
                ErrorOccurred?.Invoke($"Failed to load devices: {ex.Message}");
                throw;
            }
            finally
            {
                _isLoadingDevices = false;
            }
        }

        public void SelectDevice(int deviceIndex)
        {
            if (deviceIndex >= 0 && deviceIndex < Devices.Count)
            {
                _selectedDevice = Devices[deviceIndex];
                _snifferService.SelectDevice(deviceIndex);
                _logger.LogDebug($"Selected device: {_selectedDevice.Name}");
            }
        }

        public void StartCapture()
        {
            if (_selectedDevice == null)
            {
                _logger.LogWarning("Cannot start capture: no device selected");
                ErrorOccurred?.Invoke("No device selected");
                return;
            }

            _logger.Log($"Starting capture on {_selectedDevice.Name}");
            _snifferService.StartCapture();

            if (_snifferService.IsCapturing)
            {
                CaptureStateChanged?.Invoke(true);
            }
        }

        public void StopCapture()
        {
            _logger.Log("[CaptureSessionFacade] Stopping capture");
            _snifferService.StopCapture();
            CaptureStateChanged?.Invoke(false);
        }

        public IAsyncEnumerable<IList<PacketInfo>> GetPacketBatchesAsync(CancellationToken ct)
        {
            return _snifferService.GetPacketBatchesAsync(ct);
        }

        public async Task<IList<PacketInfo>> LoadPcapAsync(string filePath)
        {
            _logger.Log($" Loading PCAP: {filePath}");

            try
            {
                var service = _pcapFactory.GetService();
                var packets = await service.LoadAsync(filePath);
                _logger.Log($"Loaded {packets.Count} packets from PCAP");
                return packets;
            }
            catch (Exception ex)
            {
                _logger.LogError($" Failed to load PCAP: {ex.Message}", ex);
                throw;
            }
        }

        public async Task SavePcapAsync(string filePath, IList<PacketInfo> packets)
        {
            _logger.Log($" Saving {packets.Count} packets to: {filePath}");

            try
            {
                var service = _pcapFactory.GetService();
                await service.SaveAsync(filePath, packets);
                _logger.Log($"Saved {packets.Count} packets");
            }
            catch (Exception ex)
            {
                _logger.LogError($" Failed to save PCAP: {ex.Message}", ex);
                throw;
            }
        }
    }
}
