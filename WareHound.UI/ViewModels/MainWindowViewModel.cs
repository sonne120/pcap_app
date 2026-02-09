using Microsoft.Win32;
using Prism.Commands;
using Prism.Events;
using Prism.Regions;
using System.Collections.ObjectModel;
using System.Windows.Threading;
using WareHound.UI.Infrastructure.Events;
using WareHound.UI.Infrastructure.Services;
using WareHound.UI.Infrastructure.ViewModels;
using WareHound.UI.Models;
using WareHound.UI.Services;

namespace WareHound.UI.ViewModels
{
    public class MainWindowViewModel : BaseViewModel
    {
        private readonly IRegionManager _regionManager;
        private readonly ICaptureSessionFacade _captureSession;
        private readonly DispatcherTimer _statusTimer;

        private string _statusText = "Ready";
        private int _packetCount;
        private DateTime _currentTime;
        private bool _isCapturing;
        private NetworkDevice? _selectedDevice;
        private bool _isLoadingDevices;
        private string _deviceLoadError = "";
        private bool _isSavingOrLoading;

        public string StatusText
        {
            get => _statusText;
            set => SetProperty(ref _statusText, value);
        }

        public int PacketCount
        {
            get => _packetCount;
            set => SetProperty(ref _packetCount, value);
        }

        public DateTime CurrentTime
        {
            get => _currentTime;
            set => SetProperty(ref _currentTime, value);
        }

        public bool IsCapturing
        {
            get => _isCapturing;
            set => SetProperty(ref _isCapturing, value);
        }

        public bool IsLoadingDevices
        {
            get => _isLoadingDevices;
            set => SetProperty(ref _isLoadingDevices, value);
        }

        public string DeviceLoadError
        {
            get => _deviceLoadError;
            set
            {
                if (SetProperty(ref _deviceLoadError, value))
                {
                    RaisePropertyChanged(nameof(HasDeviceLoadError));
                }
            }
        }

        public bool HasDeviceLoadError => !string.IsNullOrEmpty(DeviceLoadError);

        public NetworkDevice? SelectedDevice
        {
            get => _selectedDevice;
            set
            {
                if (SetProperty(ref _selectedDevice, value) && value != null)
                {
                    _captureSession.SelectDevice(value.Index);
                }
            }
        }

        public ObservableCollection<NetworkDevice> Devices => _captureSession.Devices;
        public DelegateCommand<string> NavigateCommand { get; }
        public DelegateCommand StartCaptureCommand { get; }
        public DelegateCommand StopCaptureCommand { get; }
        public DelegateCommand ClearCommand { get; }
        public DelegateCommand RetryLoadDevicesCommand { get; }
        public DelegateCommand ClearFilterCommand { get; }
        public DelegateCommand OpenPcapCommand { get; }
        public DelegateCommand SavePcapCommand { get; }

        public bool IsSavingOrLoading
        {
            get => _isSavingOrLoading;
            set => SetProperty(ref _isSavingOrLoading, value);
        }

        public ObservableCollection<FilterTypeOption> FilterTypes { get; } = new()
        {
            new FilterTypeOption { Type = FilterType.All, DisplayName = "All Fields" },
            new FilterTypeOption { Type = FilterType.Protocol, DisplayName = "Protocol" },
            new FilterTypeOption { Type = FilterType.SourceIP, DisplayName = "Source IP" },
            new FilterTypeOption { Type = FilterType.DestIP, DisplayName = "Dest IP" },
            new FilterTypeOption { Type = FilterType.SourcePort, DisplayName = "Source Port" },
            new FilterTypeOption { Type = FilterType.DestPort, DisplayName = "Dest Port" }
        };

        private FilterTypeOption? _selectedFilterType;
        public FilterTypeOption? SelectedFilterType
        {
            get => _selectedFilterType;
            set
            {
                if (SetProperty(ref _selectedFilterType, value))
                {
                    RaisePropertyChanged(nameof(IsFilterTypeSelected));
                    RaisePropertyChanged(nameof(FilterPlaceholder));
                    PublishFilter();
                }
            }
        }

        public bool IsFilterTypeSelected => SelectedFilterType != null && SelectedFilterType.Type != FilterType.All;

        public string FilterPlaceholder => SelectedFilterType?.Type switch
        {
            FilterType.Protocol => "e.g. TCP, UDP, HTTP",
            FilterType.SourceIP => "e.g. 192.168.1.1",
            FilterType.DestIP => "e.g. 10.0.0.1",
            FilterType.SourcePort => "e.g. 443, 80",
            FilterType.DestPort => "e.g. 8080",
            _ => "Enter filter value..."
        };

        private string _filterText = "";
        public string FilterText
        {
            get => _filterText;
            set
            {
                if (SetProperty(ref _filterText, value))
                {
                    PublishFilter();
                }
            }
        }

        private void PublishFilter()
        {
            var criteria = new FilterCriteria
            {
                Type = SelectedFilterType?.Type ?? FilterType.All,
                Value = FilterText
            };
            Publish<FilterChangedEvent, FilterCriteria>(criteria);
        }

        public MainWindowViewModel(IRegionManager regionManager, ICaptureSessionFacade captureSession, 
            IEventAggregator eventAggregator, ILoggerService logger)
            : base(eventAggregator, logger)
        {
            _regionManager = regionManager ?? throw new ArgumentNullException(nameof(regionManager));
            _captureSession = captureSession ?? throw new ArgumentNullException(nameof(captureSession));

            // Subscribe to facade events
            _captureSession.CaptureStateChanged += OnFacadeCaptureStateChanged;
            _captureSession.ErrorOccurred += OnFacadeError;
            _captureSession.DevicesLoaded += OnFacadeDevicesLoaded;

            NavigateCommand = new DelegateCommand<string>(Navigate);
            StartCaptureCommand = new DelegateCommand(StartCapture, CanStartCapture)
                .ObservesProperty(() => IsCapturing)
                .ObservesProperty(() => SelectedDevice)
                .ObservesProperty(() => IsLoadingDevices);
            StopCaptureCommand = new DelegateCommand(StopCapture, CanStopCapture)
                .ObservesProperty(() => IsCapturing);
            ClearCommand = new DelegateCommand(ClearPackets);
            RetryLoadDevicesCommand = new DelegateCommand(async () => await LoadDevicesAsync(), () => !IsLoadingDevices)
                .ObservesProperty(() => IsLoadingDevices);
            ClearFilterCommand = new DelegateCommand(ClearFilter);
            OpenPcapCommand = new DelegateCommand(async () => await OpenPcapAsync(), () => !IsCapturing && !IsSavingOrLoading)
                .ObservesProperty(() => IsCapturing)
                .ObservesProperty(() => IsSavingOrLoading);
            SavePcapCommand = new DelegateCommand(async () => await SavePcapAsync(), () => PacketCount > 0 && !IsCapturing && !IsSavingOrLoading)
                .ObservesProperty(() => PacketCount)
                .ObservesProperty(() => IsCapturing)
                .ObservesProperty(() => IsSavingOrLoading);

            Subscribe<PacketCapturedEvent, PacketInfo>(OnPacketReceived);

            // Status update timer
            _statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _statusTimer.Tick += OnStatusTimerTick;
            _statusTimer.Start();

            CurrentTime = DateTime.Now;

            _ = InitializeAsync();
        }

        private async Task InitializeAsync()
        {
            await LoadDevicesAsync();
        }

        private async Task LoadDevicesAsync()
        {
            IsLoadingDevices = true;
            DeviceLoadError = "";
            Publish<DevicesLoadingEvent, bool>(true);

            try
            {
                await _captureSession.LoadDevicesAsync(TimeSpan.FromSeconds(30));
                
                if (Devices.Count > 0 && SelectedDevice == null)
                {
                    SelectedDevice = Devices[0];
                }
                
                Publish<DevicesLoadedEvent>();
            }
            catch (TimeoutException ex)
            {
                DeviceLoadError = "Device loading timed out. Please retry.";
                LogError("[MainWindowViewModel] Device loading timed out", ex);
                Publish<DevicesLoadFailedEvent, string>(ex.Message);
            }
            catch (OperationCanceledException)
            {
                LogWarning("[MainWindowViewModel] Device loading was cancelled");
            }
            catch (Exception ex)
            {
                DeviceLoadError = $"Failed to load devices: {ex.Message}";
                LogError($"[MainWindowViewModel] Failed to load devices", ex);
                Publish<DevicesLoadFailedEvent, string>(ex.Message);
            }
            finally
            {
                IsLoadingDevices = false;
                Publish<DevicesLoadingEvent, bool>(false);
            }
        }

        private void ClearPackets()
        {
            Publish<ClearPacketsEvent>();
            PacketCount = 0;
        }

        private void Navigate(string viewName)
        {
            if (string.IsNullOrEmpty(viewName)) return;

            _regionManager.RequestNavigate("ContentRegion", viewName);
        }

        private void StartCapture()
        {
            if (SelectedDevice == null || IsCapturing) return;

            _captureSession.StartCapture();
            
            if (_captureSession.IsCapturing)
            {
                IsCapturing = true;
                Publish<CaptureStateChangedEvent, bool>(true);
            }
        }

        private bool CanStartCapture() => SelectedDevice != null && !IsCapturing && !IsLoadingDevices;

        private void StopCapture()
        {
            if (!IsCapturing) return;

            _captureSession.StopCapture();
            IsCapturing = false;
            Publish<CaptureStateChangedEvent, bool>(false);
        }

        private bool CanStopCapture() => IsCapturing;

        private void OnPacketReceived(PacketInfo packet)
        {
            PacketCount++;
        }

        private void ClearFilter()
        {
            SelectedFilterType = FilterTypes[0]; 
            FilterText = "";
        }

        private void OnStatusTimerTick(object? sender, EventArgs e)
        {
            CurrentTime = DateTime.Now;
            IsCapturing = _captureSession.IsCapturing;
            StatusText = IsCapturing ? "Capturing..." : "Ready";
        }

        private async Task OpenPcapAsync()
        {
            var dialog = new OpenFileDialog
            {
                Filter = "PCAP Files (*.pcap;*.pcapng;*.cap)|*.pcap;*.pcapng;*.cap|All Files (*.*)|*.*",
                Title = "Open Packet Capture File"
            };

            if (dialog.ShowDialog() != true) return;

            IsSavingOrLoading = true;
            StatusText = "Loading...";

            try
            {
                var packets = await _captureSession.LoadPcapAsync(dialog.FileName);
                
                // Publish event to load packets into CaptureViewModel
                Publish<PcapLoadedEvent, IList<PacketInfo>>(packets);
                
                PacketCount = packets.Count;
                StatusText = $"Loaded {packets.Count} packets";
            }
            catch (Exception ex)
            {
                LogError("[MainWindowViewModel] Failed to open PCAP file", ex);
                System.Windows.MessageBox.Show(
                    $"Failed to open PCAP file:\n{ex.Message}", 
                    "Error", 
                    System.Windows.MessageBoxButton.OK, 
                    System.Windows.MessageBoxImage.Error);
                StatusText = "Load failed";
            }
            finally
            {
                IsSavingOrLoading = false;
            }
        }

        private async Task SavePcapAsync()
        {
            var dialog = new SaveFileDialog
            {
                Filter = "PCAP File (*.pcap)|*.pcap|PCAPNG File (*.pcapng)|*.pcapng",
                Title = "Save Packet Capture",
                FileName = $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap"
            };

            if (dialog.ShowDialog() != true) return;

            IsSavingOrLoading = true;
            StatusText = "Saving...";

            try
            {
                // Request packets from CaptureViewModel via event
                var packetsTask = new TaskCompletionSource<IList<PacketInfo>>();
                
                // Subscribe to response
                Subscribe<PcapSaveResponseEvent, IList<PacketInfo>>(packets =>
                {
                    packetsTask.TrySetResult(packets);
                });
                
                // Request packets
                Publish<PcapSaveRequestEvent>();
                
                var packets = await Task.WhenAny(packetsTask.Task, Task.Delay(5000)) == packetsTask.Task
                    ? packetsTask.Task.Result
                    : new List<PacketInfo>();

                if (packets.Count == 0)
                {
                    LogWarning("[MainWindowViewModel] No packets with raw data to save");
                    System.Windows.MessageBox.Show(
                        "No packets with raw data to save. Packets must have been captured (not loaded from metadata).",
                        "Warning",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Warning);
                    return;
                }

                await _captureSession.SavePcapAsync(dialog.FileName, packets);
                
                StatusText = $"Saved {packets.Count} packets";
            }
            catch (Exception ex)
            {
                LogError("[MainWindowViewModel] Failed to save PCAP file", ex);
                System.Windows.MessageBox.Show(
                    $"Failed to save PCAP file:\n{ex.Message}",
                    "Error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Error);
                StatusText = "Save failed";
            }
            finally
            {
                IsSavingOrLoading = false;
            }
        }

        protected override void OnDispose()
        {
            _statusTimer.Stop();
            _captureSession.CaptureStateChanged -= OnFacadeCaptureStateChanged;
            _captureSession.ErrorOccurred -= OnFacadeError;
            _captureSession.DevicesLoaded -= OnFacadeDevicesLoaded;
        }

        private void OnFacadeCaptureStateChanged(bool isCapturing)
        {
            IsCapturing = isCapturing;
        }

        private void OnFacadeError(string error)
        {
            LogError($"[MainWindowViewModel] Capture error: {error}");
        }

        private void OnFacadeDevicesLoaded()
        {
            if (Devices.Count > 0 && SelectedDevice == null)
            {
                SelectedDevice = Devices[0];
            }
        }
    }

    public class FilterTypeOption
    {
        public FilterType Type { get; set; }
        public string DisplayName { get; set; } = "";

        public override string ToString() => DisplayName;
    }
}
