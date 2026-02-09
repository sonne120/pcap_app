using Prism.Events;
using WareHound.UI.Infrastructure.Events;
using WareHound.UI.Infrastructure.Services;
using WareHound.UI.Infrastructure.ViewModels;
using WareHound.UI.Services;

namespace WareHound.UI.ViewModels
{
    public class SettingsViewModel : BaseViewModel
    {
        private bool _darkModeEnabled;
        private int _maxPacketBuffer = 10000;
        private bool _autoScroll = true;
        private bool _showMacAddresses = true;
        private string _captureFilter = "";
        private int _selectedTimeFormatIndex = 0;
        private int _selectedThemeIndex = 0;
        private int _selectedPcapBackendIndex = 1; 
        private bool _grpcEnabled = false;
        private string _grpcServerAddress = "https://localhost:5001";

        public string[] TimeFormats { get; } = { "Relative", "Absolute", "Delta" };
        public string[] Themes { get; } = { "Light", "Dark" };
        public string[] PcapBackends { get; } = { "Native (C++ pcap)", "SharpPcap (Managed)" };

        public bool DarkModeEnabled
        {
            get => _darkModeEnabled;
            set => SetProperty(ref _darkModeEnabled, value);
        }
        public int MaxPacketBuffer
        {
            get => _maxPacketBuffer;
            set => SetProperty(ref _maxPacketBuffer, value);
        }

        public bool AutoScroll
        {
            get => _autoScroll;
            set
            {
                if (SetProperty(ref _autoScroll, value))
                {
                    Publish<AutoScrollChangedEvent, bool>(value);
                }
            }
        }

        public bool ShowMacAddresses
        {
            get => _showMacAddresses;
            set
            {
                if (SetProperty(ref _showMacAddresses, value))
                {
                    Publish<ShowMacAddressesChangedEvent, bool>(value);
                }
            }
        }

        /// <summary>
        /// Enable/disable gRPC streaming to srv_pub microservice
        /// </summary>
        public bool GrpcEnabled
        {
            get => _grpcEnabled;
            set
            {
                if (SetProperty(ref _grpcEnabled, value))
                {
                    PublishGrpcSettings();
                }
            }
        }

        public string GrpcServerAddress
        {
            get => _grpcServerAddress;
            set
            {
                if (SetProperty(ref _grpcServerAddress, value))
                {
                    if (_grpcEnabled)
                    {
                        PublishGrpcSettings();
                    }
                }
            }
        }

        private void PublishGrpcSettings()
        {
            Publish<GrpcEnabledChangedEvent, GrpcSettings>(new GrpcSettings
            {
                Enabled = _grpcEnabled,
                ServerAddress = _grpcServerAddress
            });
        }

        public int SelectedTimeFormatIndex
        {
            get => _selectedTimeFormatIndex;
            set
            {
                if (SetProperty(ref _selectedTimeFormatIndex, value))
                {
                    var format = (TimeFormatType)value;
                    Publish<TimeFormatChangedEvent, TimeFormatType>(format);
                }
            }
        }

        public int SelectedThemeIndex
        {
            get => _selectedThemeIndex;
            set
            {
                if (SetProperty(ref _selectedThemeIndex, value))
                {
                    _darkModeEnabled = value == 1;
                    Publish<ThemeChangedEvent, bool>(_darkModeEnabled);
                }
            }
        }
        public string CaptureFilter
        {
            get => _captureFilter;
            set => SetProperty(ref _captureFilter, value);
        }
        
        public int SelectedPcapBackendIndex
        {
            get => _selectedPcapBackendIndex;
            set
            {
                if (SetProperty(ref _selectedPcapBackendIndex, value))
                {
                    var backend = (PcapBackend)value;
                    Publish<PcapBackendChangedEvent, PcapBackend>(backend);
                }
            }
        }
        
        public PcapBackend SelectedPcapBackend => (PcapBackend)_selectedPcapBackendIndex;
        
        public SettingsViewModel(IEventAggregator eventAggregator, ILoggerService logger)
            : base(eventAggregator, logger)
        {
        }
    }
}
