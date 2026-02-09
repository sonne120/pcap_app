using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows.Media;
using System.Windows.Threading;

namespace WareHound.UI.Controls
{
    public class StatisticsStatusBarViewModel : INotifyPropertyChanged
    {
        private readonly DispatcherTimer _updateTimer;
        private readonly double[] _packetsData = new double[60];

        public event EventHandler<double[]>? ChartUpdateRequested;

        #region Bindable Properties

        private string _totalPackets = "0";
        public string TotalPackets
        {
            get => _totalPackets;
            set { _totalPackets = value; OnPropertyChanged(); }
        }

        private string _packetsPerSecond = "0.0";
        public string PacketsPerSecond
        {
            get => _packetsPerSecond;
            set { _packetsPerSecond = value; OnPropertyChanged(); }
        }

        private string _totalDataSize = "0 B";
        public string TotalDataSize
        {
            get => _totalDataSize;
            set { _totalDataSize = value; OnPropertyChanged(); }
        }

        private string _captureTime = "00:00:00";
        public string CaptureTime
        {
            get => _captureTime;
            set { _captureTime = value; OnPropertyChanged(); }
        }

        private int _currentPPS;
        public int CurrentPPS
        {
            get => _currentPPS;
            set { _currentPPS = value; OnPropertyChanged(); }
        }

        private int _avgPPS;
        public int AvgPPS
        {
            get => _avgPPS;
            set { _avgPPS = value; OnPropertyChanged(); }
        }

        private int _maxPPS;
        public int MaxPPS
        {
            get => _maxPPS;
            set { _maxPPS = value; OnPropertyChanged(); }
        }

        private string _topProtocolName = "TLS";
        public string TopProtocolName
        {
            get => _topProtocolName;
            set { _topProtocolName = value; OnPropertyChanged(); }
        }

        private string _topProtocolPercent = "0%";
        public string TopProtocolPercent
        {
            get => _topProtocolPercent;
            set { _topProtocolPercent = value; OnPropertyChanged(); }
        }

        #endregion

        #region Collections

        public ObservableCollection<ProtocolInfo> Protocols { get; } = new();
        public ObservableCollection<MiniProtocolBar> MiniProtocolBars { get; } = new();
        public ObservableCollection<TopTalkerInfo> TopTalkers { get; } = new();

        #endregion

        #region Internal Storage

        private DateTime _captureStartTime = DateTime.Now;
        private long _totalPacketCount = 0;
        private long _totalBytes = 0;
        private int _packetsInLastSecond = 0;

        private readonly Dictionary<string, long> _protocolCounts = new()
        {
            { "TLS", 0 }, { "TCP", 0 }, { "UDP", 0 }, { "HTTP", 0 },
            { "DNS", 0 }, { "QUIC", 0 }, { "mDNS", 0 }, { "SSDP", 0 },
            { "ARP", 0 }, { "ICMP", 0 }, { "Other", 0 }
        };

        private readonly Dictionary<string, string> _protocolColors = new()
        {
            { "TLS", "#3B82F6" }, { "TCP", "#10B981" }, { "UDP", "#F59E0B" },
            { "HTTP", "#EF4444" }, { "DNS", "#8B5CF6" }, { "QUIC", "#EC4899" },
            { "mDNS", "#14B8A6" }, { "SSDP", "#F97316" }, { "ARP", "#06B6D4" },
            { "ICMP", "#84CC16" }, { "Other", "#6B7280" }
        };

        private readonly Dictionary<string, long> _ipCounts = new();

        #endregion

        public StatisticsStatusBarViewModel()
        {
            Array.Clear(_packetsData, 0, _packetsData.Length);

            _updateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _updateTimer.Tick += UpdateTimer_Tick;
        }

        #region Public Methods

        public void StartUpdating()
        {
            _captureStartTime = DateTime.Now;
            _updateTimer.Start();
        }

        public void StopUpdating()
        {
            _updateTimer.Stop();
        }

        public void AddPacket(int packetSize, string protocol, string sourceIp, string? destIp = null)
        {
            _totalPacketCount++;
            _totalBytes += packetSize;
            _packetsInLastSecond++;

            string normalizedProtocol = NormalizeProtocol(protocol);
            if (_protocolCounts.ContainsKey(normalizedProtocol))
                _protocolCounts[normalizedProtocol]++;
            else
                _protocolCounts["Other"]++;

            if (!string.IsNullOrEmpty(sourceIp) && sourceIp != "0.0.0.0")
            {
                if (_ipCounts.ContainsKey(sourceIp))
                    _ipCounts[sourceIp]++;
                else
                    _ipCounts[sourceIp] = 1;
            }
        }

        public void Reset()
        {
            _totalPacketCount = 0;
            _totalBytes = 0;
            _packetsInLastSecond = 0;
            _captureStartTime = DateTime.Now;

            Array.Clear(_packetsData, 0, _packetsData.Length);

            foreach (var key in _protocolCounts.Keys.ToList())
                _protocolCounts[key] = 0;

            _ipCounts.Clear();

            Protocols.Clear();
            MiniProtocolBars.Clear();
            TopTalkers.Clear();

            TotalPackets = "0";
            PacketsPerSecond = "0.0";
            TotalDataSize = "0 B";
            CaptureTime = "00:00:00";
            CurrentPPS = 0;
            AvgPPS = 0;
            MaxPPS = 0;
            TopProtocolName = "TLS";
            TopProtocolPercent = "0%";

            ChartUpdateRequested?.Invoke(this, _packetsData);
        }

        #endregion

        #region Private Methods

        private string NormalizeProtocol(string? protocol)
        {
            if (string.IsNullOrEmpty(protocol))
                return "Other";

            return protocol.ToUpperInvariant() switch
            {
                "TLS" or "SSL" or "HTTPS" => "TLS",
                "TCP" => "TCP",
                "UDP" => "UDP",
                "HTTP" => "HTTP",
                "DNS" => "DNS",
                "QUIC" => "QUIC",
                "MDNS" => "mDNS",
                "SSDP" or "SSCOPMCE" => "SSDP",
                "ARP" => "ARP",
                "ICMP" or "ICMPV6" => "ICMP",
                _ => "Other"
            };
        }

        private void UpdateTimer_Tick(object? sender, EventArgs e)
        {
            // Update chart data
            for (int i = 0; i < _packetsData.Length - 1; i++)
                _packetsData[i] = _packetsData[i + 1];

            _packetsData[^1] = _packetsInLastSecond;

            int currentPPS = _packetsInLastSecond;
            _packetsInLastSecond = 0;

            // Update properties
            CurrentPPS = currentPPS;
            TotalPackets = _totalPacketCount.ToString("N0");
            PacketsPerSecond = currentPPS.ToString("F1");
            TotalDataSize = FormatBytes(_totalBytes);
            CaptureTime = (DateTime.Now - _captureStartTime).ToString(@"hh\:mm\:ss");

            // Chart statistics
            var nonZeroData = _packetsData.Where(x => x > 0).ToArray();
            if (nonZeroData.Length > 0)
            {
                AvgPPS = (int)Math.Round(nonZeroData.Average());
                MaxPPS = (int)nonZeroData.Max();
            }
            else
            {
                AvgPPS = 0;
                MaxPPS = 0;
            }

            // Update protocols
            UpdateProtocolsDisplay();

            // Update top IPs
            UpdateTopTalkersDisplay();

            // Update chart
            ChartUpdateRequested?.Invoke(this, (double[])_packetsData.Clone());
        }

        private void UpdateProtocolsDisplay()
        {
            if (_totalPacketCount == 0) return;

            var sortedProtocols = _protocolCounts
                .Where(p => p.Value > 0)
                .OrderByDescending(p => p.Value)
                .Take(6)
                .ToList();

            // Update top protocol for Status Bar
            if (sortedProtocols.Count > 0)
            {
                var top = sortedProtocols.First();
                TopProtocolName = top.Key;
                TopProtocolPercent = $"{(double)top.Value / _totalPacketCount * 100:F1}%";
            }

            // Clear and fill collections
            Protocols.Clear();
            MiniProtocolBars.Clear();

            double miniBarTotalWidth = 120; // Mini bar width in Status Bar

            foreach (var proto in sortedProtocols)
            {
                double percent = (double)proto.Value / _totalPacketCount * 100;
                string colorHex = _protocolColors.TryGetValue(proto.Key, out var c) ? c : "#6B7280";
                var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colorHex));

                Protocols.Add(new ProtocolInfo
                {
                    Name = proto.Key,
                    Percent = percent,
                    PacketCount = proto.Value,
                    Color = brush
                });

                MiniProtocolBars.Add(new MiniProtocolBar
                {
                    Width = Math.Max((percent / 100.0) * miniBarTotalWidth, 1),
                    Color = brush
                });
            }
        }

        private void UpdateTopTalkersDisplay()
        {
            if (_ipCounts.Count == 0) return;

            var topIps = _ipCounts
                .OrderByDescending(ip => ip.Value)
                .Take(5)
                .ToList();

            if (topIps.Count == 0) return;

            var maxCount = topIps.First().Value;
            double barMaxWidth = 160;

            TopTalkers.Clear();

            foreach (var ip in topIps)
            {
                TopTalkers.Add(new TopTalkerInfo
                {
                    IpAddress = ip.Key,
                    PacketCount = (int)ip.Value,
                    Percent = (double)ip.Value / _totalPacketCount * 100,
                    BarWidth = (double)ip.Value / maxCount * barMaxWidth
                });
            }
        }

        private static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;

            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }

            return $"{size:F1} {sizes[order]}";
        }

        #endregion

        #region INotifyPropertyChanged

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }

    #region Data Models

    public class ProtocolInfo
    {
        public string Name { get; set; } = "";
        public double Percent { get; set; }
        public long PacketCount { get; set; }
        public SolidColorBrush Color { get; set; } = Brushes.Gray;
    }

    public class MiniProtocolBar
    {
        public double Width { get; set; }
        public SolidColorBrush Color { get; set; } = Brushes.Gray;
    }

    public class TopTalkerInfo
    {
        public string IpAddress { get; set; } = "";
        public int PacketCount { get; set; }
        public double Percent { get; set; }
        public double BarWidth { get; set; }
    }

    #endregion
}
