using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using System.ComponentModel;
using System.Windows.Data;
using Prism.Commands;
using Prism.Events;
using WareHound.UI.Infrastructure.Events;
using WareHound.UI.Infrastructure.ViewModels;
using WareHound.UI.Infrastructure.Filters;
using WareHound.UI.Models;
using WareHound.UI.Services;
using WareHound.UI.Infrastructure.Services;
using WareHound.UI.Controls;

namespace WareHound.UI.ViewModels
{
    public class CaptureViewModel : BaseViewModel
    {
        private readonly ISnifferService _snifferService;
        private readonly IPacketCollectionService _collectionService;
        private readonly ILoggerService _logger;
        private readonly IStatisticsChannel _statisticsChannel;

        private ICollectionView _packetsView;
        private IPacketFilter _currentFilter = new NoOpFilter();
        private CancellationTokenSource? _chartsCts;
        
        // ScottPlot data (60 points = 60 seconds)
        private readonly double[] _packetsData = new double[60];
        
        // Event for chart updates
        public event EventHandler<double[]>? ChartUpdateRequested;

        private NetworkDevice? _selectedDevice;
        private FilterCriteria _filterCriteria = FilterCriteria.Empty;
        private bool _isCapturing;
        private PacketInfo? _selectedPacket;
        private ObservableCollection<TreeNode> _packetDetails = new();
        private string _packetHexDump = "";
        private bool _autoScroll = true;
        private bool _showMacAddresses = true;
        private bool _isStatsPanelExpanded = true;
        private int _selectedStatsTabIndex;

        private CancellationTokenSource? _captureCts;
        private bool _hasPackets;
        
        // Stats display properties
        private string _totalPacketsDisplay = "0";
        private string _packetsPerSecDisplay = "0.0";
        private string _dataVolumeDisplay = "0 B";
        private string _captureTimeDisplay = "00:00:00";
        private double _currentPps;
        private double _averagePps;
        private double _maxPps;
        
        // Local stats tracking (independent of StatisticsViewModel)
        private System.Windows.Threading.DispatcherTimer? _localStatsTimer;
        private DateTime _captureStartTime = DateTime.Now;
        private long _lastPacketCount;
        private readonly Queue<double> _ppsHistory = new();
        private double _localMaxPps;
        private long _totalBytes;
        
        // Protocol bar data
        private ObservableCollection<ProtocolBarItem> _protocolBars = new();
        
        // Top talkers data
        private ObservableCollection<TopTalkerDisplayItem> _topTalkers = new();

        public ObservableCollection<PacketInfo> Packets { get; } = new();
        public ObservableCollection<NetworkDevice> Devices => _snifferService.Devices;

        public bool AutoScroll
        {
            get => _autoScroll;
            set => SetProperty(ref _autoScroll, value);
        }

        public bool ShowMacAddresses
        {
            get => _showMacAddresses;
            set => SetProperty(ref _showMacAddresses, value);
        }

        public NetworkDevice? SelectedDevice
        {
            get => _selectedDevice;
            set => SetProperty(ref _selectedDevice, value);
        }

        public FilterCriteria FilterCriteria
        {
            get => _filterCriteria;
            set => SetProperty(ref _filterCriteria, value);
        }

        public string FilterText => _filterCriteria.Value;

        public bool IsCapturing
        {
            get => _isCapturing;
            set => SetProperty(ref _isCapturing, value);
        }

        public PacketInfo? SelectedPacket
        {
            get => _selectedPacket;
            set
            {
                if (SetProperty(ref _selectedPacket, value))
                {
                    UpdatePacketDetails();
                }
            }
        }
        public ObservableCollection<TreeNode> PacketDetails
        {
            get => _packetDetails;
            set => SetProperty(ref _packetDetails, value);
        }
        public string PacketHexDump
        {
            get => _packetHexDump;
            set => SetProperty(ref _packetHexDump, value);
        }

        public DelegateCommand ToggleCaptureCommand { get; }
        public DelegateCommand ClearCommand { get; }
        public DelegateCommand SaveToDashboardCommand { get; }
        public DelegateCommand<string> CopyCommand { get; }
        public DelegateCommand ToggleStatsPanelCommand { get; }

        // Stats panel expansion
        public bool IsStatsPanelExpanded
        {
            get => _isStatsPanelExpanded;
            set => SetProperty(ref _isStatsPanelExpanded, value);
        }
        
        // Selected tab index (0=Overview, 1=Protocols, 2=Top IPs)
        public int SelectedStatsTabIndex
        {
            get => _selectedStatsTabIndex;
            set => SetProperty(ref _selectedStatsTabIndex, value);
        }
        
        // Stat card display values
        public string TotalPacketsDisplay
        {
            get => _totalPacketsDisplay;
            set => SetProperty(ref _totalPacketsDisplay, value);
        }
        
        public string PacketsPerSecDisplay
        {
            get => _packetsPerSecDisplay;
            set => SetProperty(ref _packetsPerSecDisplay, value);
        }
        
        public string DataVolumeDisplay
        {
            get => _dataVolumeDisplay;
            set => SetProperty(ref _dataVolumeDisplay, value);
        }
        
        public string CaptureTimeDisplay
        {
            get => _captureTimeDisplay;
            set => SetProperty(ref _captureTimeDisplay, value);
        }
        
        public double CurrentPps
        {
            get => _currentPps;
            set => SetProperty(ref _currentPps, value);
        }
        
        public double AveragePps
        {
            get => _averagePps;
            set => SetProperty(ref _averagePps, value);
        }
        
        public double MaxPps
        {
            get => _maxPps;
            set => SetProperty(ref _maxPps, value);
        }
        
        // Protocol distribution bars
        public ObservableCollection<ProtocolBarItem> ProtocolBars
        {
            get => _protocolBars;
            set => SetProperty(ref _protocolBars, value);
        }
        
        // Top talkers list
        public ObservableCollection<TopTalkerDisplayItem> TopTalkers
        {
            get => _topTalkers;
            set => SetProperty(ref _topTalkers, value);
        }

        public bool HasChartData => _packetsData.Any(v => v > 0) || ProtocolBars.Count > 0;
        
        // Statistics Status Bar ViewModel for the bottom panel
        public StatisticsStatusBarViewModel StatisticsStatusBarViewModel { get; } = new StatisticsStatusBarViewModel();

        public CaptureViewModel(ISnifferService snifferService, IPacketCollectionService collectionService, IEventAggregator eventAggregator, ILoggerService logger, IStatisticsChannel statisticsChannel)
            : base(eventAggregator, logger)
        {
            _snifferService = snifferService ?? throw new ArgumentNullException(nameof(snifferService));
            _collectionService = collectionService ?? throw new ArgumentNullException(nameof(collectionService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _statisticsChannel = statisticsChannel ?? throw new ArgumentNullException(nameof(statisticsChannel));
            
            // Initialize chart data with zeros
            Array.Clear(_packetsData, 0, _packetsData.Length);
            
            _packetsView = CollectionViewSource.GetDefaultView(Packets);
            _packetsView.Filter = FilterPacket;

            Subscribe<CaptureStateChangedEvent, bool>(OnCaptureStateChanged);
            Subscribe<ClearPacketsEvent>(Clear);
            Subscribe<FilterChangedEvent, FilterCriteria>(OnFilterChanged);
            Subscribe<AutoScrollChangedEvent, bool>(enabled => AutoScroll = enabled);
            Subscribe<ShowMacAddressesChangedEvent, bool>(enabled => ShowMacAddresses = enabled);
            Subscribe<TimeFormatChangedEvent, TimeFormatType>(OnTimeFormatChanged);
            Subscribe<DevicesLoadedEvent>(OnDevicesLoaded);
            Subscribe<PcapLoadedEvent, IList<PacketInfo>>(OnPcapLoaded);
            Subscribe<PcapSaveRequestEvent>(OnPcapSaveRequest);

            ToggleCaptureCommand = new DelegateCommand(ToggleCapture);
            ClearCommand = new DelegateCommand(Clear);
            SaveToDashboardCommand = new DelegateCommand(SaveToDashboard, () => Packets.Count > 0);
            CopyCommand = new DelegateCommand<string>(Copy);
            ToggleStatsPanelCommand = new DelegateCommand(() => IsStatsPanelExpanded = !IsStatsPanelExpanded);
            
            
            _chartsCts = new CancellationTokenSource();
            _ = ConsumeStatisticsAsync(_chartsCts.Token);
            
            _localStatsTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(300)
            };
            _localStatsTimer.Tick += (s, e) => ComputeLocalStats();
            
            if (_snifferService.IsCapturing)
            {
               OnCaptureStateChanged(true);
            }

            _snifferService.ErrorOccurred += OnError;

        
            if (Devices.Count > 0 && SelectedDevice == null)
                SelectedDevice = Devices[0];
        }

        private void OnPcapLoaded(IList<PacketInfo> packets)
        {
            RunOnUI(() =>
            {
                Packets.Clear();
                foreach (var packet in packets)
                {
                    Packets.Add(packet);
                }
                
                if (Packets.Count > 0)
                {
                    _hasPackets = true;
                    SaveToDashboardCommand.RaiseCanExecuteChanged();
                }
            });
        }

        private void OnFilterChanged(FilterCriteria criteria)
        {
            FilterCriteria = criteria;
            _currentFilter = FilterFactory.Create(criteria);
            _packetsView.Refresh();
        }

        private bool FilterPacket(object obj)
        {
            if (obj is PacketInfo packet)
            {
                return _currentFilter.IsMatch(packet);
            }
            return false;
        }

        private void OnPcapSaveRequest()
        {
            var packetsWithRawData = Packets.Where(p => p.RawData != null && p.CaptureLen > 0).ToList();
            Publish<PcapSaveResponseEvent, IList<PacketInfo>>(packetsWithRawData);
        }

        private void OnDevicesLoaded()
        {
            if (Devices.Count > 0 && SelectedDevice == null)
            {
                SelectedDevice = Devices[0];
            }
        }

        private void OnTimeFormatChanged(TimeFormatType format)
        {
            PacketInfo.SetTimeFormat(format);
            foreach (var packet in Packets)
            {
                packet.NotifyTimeDisplayChanged();
            }
        }

        private void OnCaptureStateChanged(bool isCapturing)
        {
            if (isCapturing)
            {
                if (!IsCapturing && _snifferService.IsCapturing)
                {
                    IsCapturing = true;
                    _captureStartTime = DateTime.Now;
                    _lastPacketCount = 0;
                    _ppsHistory.Clear();
                    _localMaxPps = 0;
                    _totalBytes = 0;
                    _captureCts = new CancellationTokenSource();
                    _ = ConsumePacketsAsync(_captureCts.Token);
                    _localStatsTimer?.Start();
                }
            }
            else
            {
                if (IsCapturing)
                {
                   _captureCts?.Cancel();
                   IsCapturing = false;
                   
                   // Stop local stats timer
                   _localStatsTimer?.Stop();
                }
            }
        }

        private void ToggleCapture()
        {
            if (IsCapturing)
            {
                // 1. Cancel the packet consumer task (background loop)
                _captureCts?.Cancel();
                
                // 2. Stop the underlying sniffer service (closes pipes, native threads)
                _snifferService.StopCapture();
                
                // 3. Update UI state (enables/disables buttons)
                IsCapturing = false;
            }
            else
            {
                // 1. Validation: Ensure a device is selected
                if (SelectedDevice == null)
                {
                    MessageBox.Show("Please select a network interface.", "WareHound",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // 2. Start the service. 
                _snifferService.StartCapture(SelectedDevice.Index);
             
                if (_snifferService.IsCapturing)
                {
                    IsCapturing = true;
                    
                    _captureCts = new CancellationTokenSource();
                    
                    // 5. Fire-and-forget the packet consumer loop                  
                    _ = ConsumePacketsAsync(_captureCts.Token);
                }
                else
                {                 
                    IsCapturing = false; 
                }
            }
        }

        private void Clear()
        {
            Packets.Clear();
            SelectedPacket = null;
            _hasPackets = false;
            SaveToDashboardCommand.RaiseCanExecuteChanged();
            
            // Reset the statistics status bar
            StatisticsStatusBarViewModel.Reset();
        }

        private void SaveToDashboard()
        {
            if (Packets.Count == 0) return;

            var name = $"Capture_{DateTime.Now:yyyyMMdd_HHmmss}";
            _collectionService.CreateCollection(name, Packets);
            MessageBox.Show($"Saved {Packets.Count} packets to: {name}", "WareHound",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void Copy(string field)
        {
            if (SelectedPacket == null) return;

            var text = field switch
            {
                "SourceIp" => SelectedPacket.SourceIp,
                "DestIp" => SelectedPacket.DestIp,
                _ => ""
            };

            if (!string.IsNullOrEmpty(text))
                Clipboard.SetText(text);
        }

        private async Task ConsumePacketsAsync(CancellationToken ct)
        {
            try
            {
                await foreach (var batch in _snifferService.GetPacketBatchesAsync(ct))
                {
                    await FlushBatchToUIAsync(batch);
                }
            }
            catch (OperationCanceledException ex)
            {
                _logger.LogError($"[ConsumePacketsAsync] Error: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                _logger.LogError($"[ConsumePacketsAsync] Error: {ex.Message}", ex);
            }
        }

        private async Task FlushBatchToUIAsync(IList<PacketInfo> batch)
        {
            var packetsToAdd = batch.ToArray(); 

            await Application.Current.Dispatcher.InvokeAsync(() =>
            {
                foreach (var p in packetsToAdd)
                {
                    Packets.Add(p);               
                    Publish<PacketCapturedEvent, PacketInfo>(p);
                    
                    // Update the statistics status bar
                    StatisticsStatusBarViewModel.AddPacket(
                        (int)p.CaptureLen,
                        p.Protocol ?? "Other",
                        p.SourceIp ?? "0.0.0.0",
                        p.DestIp
                    );
                }

                if (!_hasPackets && Packets.Count > 0)
                {
                    _hasPackets = true;
                    SaveToDashboardCommand.RaiseCanExecuteChanged();
                }
            }, DispatcherPriority.Background);
        }

        private void OnError(string error)
        {
            BeginOnUI(() =>
            {
                MessageBox.Show(error, "WareHound Error", MessageBoxButton.OK, MessageBoxImage.Error);
                IsCapturing = false;
            });
        }

        private void UpdatePacketDetails()
        {
            PacketDetails.Clear();
            PacketHexDump = "";

            if (SelectedPacket == null) return;

            var p = SelectedPacket;

            // Frame info
            var frame = new TreeNode($"▶ Packet #{p.Number}: {p.Protocol}");
            frame.AddChild($"    Capture Time: {p.CaptureTime:yyyy-MM-dd HH:mm:ss.fff}");
            frame.AddChild($"    Packet ID: {p.Id}");
            PacketDetails.Add(frame);

            // Ethernet
            var eth = new TreeNode($"▶ Ethernet II, Src: {p.SourceMac}, Dst: {p.DestMac}");
            eth.AddChild($"    Source MAC: {p.SourceMac}");
            eth.AddChild($"    Destination MAC: {p.DestMac}");
            eth.AddChild($"    Type: IPv4 (0x0800)");
            PacketDetails.Add(eth);

            // IP
            var ip = new TreeNode($"▶ Internet Protocol Version 4, Src: {p.SourceIp}, Dst: {p.DestIp}");
            ip.AddChild($"    Version: 4");
            ip.AddChild($"    Source Address: {p.SourceIp}");
            ip.AddChild($"    Destination Address: {p.DestIp}");
            ip.AddChild($"    Protocol: {p.Protocol}");
            PacketDetails.Add(ip);

            // Protocol specific
            var proto = new TreeNode($"▶ {p.Protocol}, Src Port: {p.SourcePort}, Dst Port: {p.DestPort}");
            proto.AddChild($"    Source Port: {p.SourcePort}");
            proto.AddChild($"    Destination Port: {p.DestPort}");
            if (!string.IsNullOrEmpty(p.HostName))
                proto.AddChild($"    Host: {p.HostName}");
            PacketDetails.Add(proto);

            // Generate hex dump
            PacketHexDump = GenerateHexDump(p);
        }

        private string GenerateHexDump(PacketInfo p)
        {
            var packetBytes = BuildPacketBytes(p);
            return FormatHexDump(packetBytes);
        }

        private byte[] BuildPacketBytes(PacketInfo p)
        {
            var bytes = new List<byte>();

            // Ethernet Header (14 bytes)
            bytes.AddRange(ParseMacAddress(p.DestMac));
            bytes.AddRange(ParseMacAddress(p.SourceMac));
            bytes.Add(0x08); bytes.Add(0x00); // IPv4

            // IP Header (20 bytes)
            bytes.Add(0x45); // Version + IHL
            bytes.Add(0x00); // DSCP/ECN
            bytes.Add(0x00); bytes.Add(0x40); // Total Length
            bytes.Add((byte)((p.Id >> 8) & 0xFF));
            bytes.Add((byte)(p.Id & 0xFF));
            bytes.Add(0x40); bytes.Add(0x00); // Flags + Fragment
            bytes.Add(0x40); // TTL
            bytes.Add(GetProtocolNumber(p.Protocol));
            bytes.Add(0x00); bytes.Add(0x00); // Checksum
            bytes.AddRange(ParseIpAddress(p.SourceIp));
            bytes.AddRange(ParseIpAddress(p.DestIp));

            // Transport Header (8 bytes)
            bytes.Add((byte)((p.SourcePort >> 8) & 0xFF));
            bytes.Add((byte)(p.SourcePort & 0xFF));
            bytes.Add((byte)((p.DestPort >> 8) & 0xFF));
            bytes.Add((byte)(p.DestPort & 0xFF));
            bytes.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });

            // Payload
            bytes.AddRange(Encoding.ASCII.GetBytes($"Packet #{p.Number}"));

            // Pad to 64 bytes
            while (bytes.Count < 64) bytes.Add(0x00);

            return bytes.ToArray();
        }

        private string FormatHexDump(byte[] bytes)
        {
            var sb = new StringBuilder();

            for (int i = 0; i < bytes.Length; i += 16)
            {
                sb.Append($"{i:X8}  ");

                // First 8 hex bytes
                for (int j = 0; j < 8; j++)
                    sb.Append(i + j < bytes.Length ? $"{bytes[i + j]:X2} " : "   ");

                sb.Append(" ");

                // Second 8 hex bytes
                for (int j = 8; j < 16; j++)
                    sb.Append(i + j < bytes.Length ? $"{bytes[i + j]:X2} " : "   ");

                sb.Append(" ");

                // ASCII
                for (int j = 0; j < 16 && i + j < bytes.Length; j++)
                {
                    byte b = bytes[i + j];
                    sb.Append(b >= 32 && b < 127 ? (char)b : '.');
                }

                sb.AppendLine();
            }

            return sb.ToString();
        }

        private static byte[] ParseMacAddress(string mac)
        {
            if (string.IsNullOrEmpty(mac))
                return new byte[6];

            try
            {
                var parts = mac.Replace("-", ":").Split(':');
                if (parts.Length == 6)
                    return parts.Select(p => Convert.ToByte(p, 16)).ToArray();
            }
            catch { }

            return new byte[6];
        }

        private static byte[] ParseIpAddress(string ip)
        {
            if (string.IsNullOrEmpty(ip))
                return new byte[4];

            try
            {
                var parts = ip.Split('.');
                if (parts.Length == 4)
                    return parts.Select(byte.Parse).ToArray();
            }
            catch { }

            return new byte[4];
        }

        private static byte GetProtocolNumber(string protocol) => protocol?.ToUpperInvariant() switch
        {
            "TCP" => 6,
            "UDP" => 17,
            "ICMP" => 1,
            _ => 0
        };

        #region LiveCharts Chart Methods
        
        /// <summary>
        /// Computes local stats from the Packets collection when StatisticsViewModel is not active.
        /// This ensures charts work even without navigating to Statistics view.
        /// </summary>
        private void ComputeLocalStats()
        {
            if (!IsCapturing || Packets.Count == 0) return;
            
            var currentCount = Packets.Count;
            var pps = (currentCount - _lastPacketCount) * 2.0; // *2 because timer is 500ms
            _lastPacketCount = currentCount;
            
            // Update PPS history
            _ppsHistory.Enqueue(pps);
            while (_ppsHistory.Count > 60) _ppsHistory.Dequeue();
            
            if (pps > _localMaxPps) _localMaxPps = pps;
            var avgPps = _ppsHistory.Count > 0 ? _ppsHistory.Average() : 0;
            
            // Capture elapsed time
            var elapsed = DateTime.Now - _captureStartTime;
            
            // Estimate total bytes from packets (sum of CaptureLen)
            _totalBytes = Packets.Sum(p => (long)p.CaptureLen);
            
            // Compute protocol distribution
            var protocolGroups = Packets
                .GroupBy(p => p.Protocol ?? "Unknown")
                .OrderByDescending(g => g.Count())
                .Take(5)
                .ToList();
            
            var totalPackets = Packets.Count;
            var protocolStats = protocolGroups.Select(g => new ProtocolStatItem(
                g.Key, 
                g.Count(), 
                totalPackets > 0 ? (double)g.Count() / totalPackets * 100 : 0
            )).ToList();
            
            // Compute top talkers (source IPs)
            var sourceIpGroups = Packets
                .Where(p => !string.IsNullOrEmpty(p.SourceIp))
                .GroupBy(p => p.SourceIp!)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .ToList();
            
            var topTalkers = sourceIpGroups.Select(g => new TopTalkerItem(
                g.Key,
                g.Count(),
                totalPackets > 0 ? (double)g.Count() / totalPackets * 100 : 0
            )).ToList();
            
            // Create snapshot and update UI
            var snapshot = new StatisticsSnapshot
            {
                TotalPackets = totalPackets,
                PacketsPerSecond = pps,
                Timestamp = DateTime.Now,
                ProtocolStats = protocolStats,
                TotalBytes = _totalBytes,
                UniqueProtocols = protocolGroups.Count,
                UniqueIps = Packets.Select(p => p.SourceIp).Distinct().Count(),
                CaptureElapsed = elapsed,
                TopTalkers = topTalkers,
                CurrentPps = pps,
                AveragePps = avgPps,
                MaxPps = _localMaxPps
            };
            
            UpdateStatCards(snapshot);
            UpdateProtocolBars(snapshot);
            UpdateTopTalkers(snapshot);
            UpdatePacketRateChart(snapshot);
            RaisePropertyChanged(nameof(HasChartData));
        }

        private async Task ConsumeStatisticsAsync(CancellationToken ct)
        {
            try
            {
                await foreach (var snapshot in _statisticsChannel.Reader.ReadAllAsync(ct))
                {
                    await Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        UpdateStatCards(snapshot);
                        UpdateProtocolBars(snapshot);
                        UpdateTopTalkers(snapshot);
                        UpdatePacketRateChart(snapshot);
                        RaisePropertyChanged(nameof(HasChartData));
                    });
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when disposing
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error consuming statistics: {ex.Message}");
            }
        }

        private void UpdateStatCards(StatisticsSnapshot snapshot)
        {
            // Format total packets with thousand separators
            TotalPacketsDisplay = snapshot.TotalPackets.ToString("N0");
            
            // Format packets per second
            PacketsPerSecDisplay = snapshot.PacketsPerSecond.ToString("F1");
            
            // Format data volume
            DataVolumeDisplay = FormatBytes(snapshot.TotalBytes);
            
            // Format capture time
            CaptureTimeDisplay = snapshot.CaptureElapsed.ToString(@"hh\:mm\:ss");
            
            // PPS indicators
            CurrentPps = snapshot.CurrentPps;
            AveragePps = snapshot.AveragePps;
            MaxPps = snapshot.MaxPps;
        }
        
        private static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double len = bytes;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:F1} {sizes[order]}";
        }

        private void UpdateProtocolBars(StatisticsSnapshot snapshot)
        {
            // Define colors for protocols (matching the mockup)
            var colors = new[]
            {
                "#3B82F6", // TLS - Blue
                "#10B981", // QUIC - Green  
                "#F59E0B", // HTTP - Orange
                "#8B5CF6", // DNS - Purple
                "#6B7280", // Other - Gray
                "#EF4444", // Red
                "#06B6D4", // Cyan
                "#EC4899", // Pink
                "#84CC16", // Lime
                "#F97316"  // Orange-red
            };

            var bars = snapshot.ProtocolStats.Take(5).Select((stat, i) => new ProtocolBarItem
            {
                Protocol = stat.Protocol,
                Percentage = stat.Percentage,
                Color = colors[i % colors.Length],
                PacketCount = stat.PacketCount
            }).ToList();

            ProtocolBars.Clear();
            foreach (var bar in bars)
            {
                ProtocolBars.Add(bar);
            }
        }

        private void UpdateTopTalkers(StatisticsSnapshot snapshot)
        {
            TopTalkers.Clear();
            foreach (var talker in snapshot.TopTalkers.Take(5))
            {
                TopTalkers.Add(new TopTalkerDisplayItem
                {
                    IpAddress = talker.IpAddress,
                    PacketCount = talker.PacketCount,
                    Percentage = talker.Percentage
                });
            }
        }

        private void UpdatePacketRateChart(StatisticsSnapshot snapshot)
        {
            // Shift data left
            for (int i = 0; i < _packetsData.Length - 1; i++)
                _packetsData[i] = _packetsData[i + 1];
            
            // Add new value at the end
            _packetsData[^1] = snapshot.PacketsPerSecond;
            
            // Request chart update via event (to be handled by View)
            ChartUpdateRequested?.Invoke(this, (double[])_packetsData.Clone());
        }

        #endregion

        protected override void OnDispose()
        {
            _localStatsTimer?.Stop();
            _chartsCts?.Cancel();
            _chartsCts?.Dispose();
            _captureCts?.Cancel();
            _captureCts?.Dispose();

            _snifferService.ErrorOccurred -= OnError;
        }
    }
}
