using System.ComponentModel;
using System.Runtime.InteropServices;
using WareHound.UI.Infrastructure.Events;

namespace WareHound.UI.Models;

public class PacketInfo : INotifyPropertyChanged
{
    private static TimeFormatType _currentTimeFormat = TimeFormatType.Relative;
    private static DateTime _captureStartTime = DateTime.Now;

    public event PropertyChangedEventHandler? PropertyChanged;

    public int Number { get; set; }
    public int Id { get; set; }
    public int SourcePort { get; set; }
    public int DestPort { get; set; }
    public string Protocol { get; set; } = "";
    public string SourceIp { get; set; } = "";
    public string DestIp { get; set; } = "";
    public string SourceMac { get; set; } = "";
    public string DestMac { get; set; } = "";
    public string HostName { get; set; } = "";
    public DateTime CaptureTime { get; set; }
    
    public byte[]? RawData { get; set; }
    public uint CaptureLen { get; set; }
    public uint OriginalLen { get; set; }

    string unknown = "Unknown";
    
    public string TimeDisplay => _currentTimeFormat switch
    {
        TimeFormatType.Absolute => CaptureTime.ToString("HH:mm:ss.fff"),
        TimeFormatType.Delta => $"+{(CaptureTime - _captureStartTime).TotalSeconds:F3}s",
        _ => CaptureTime.ToString("HH:mm:ss.fff") // Relative (default)
    };
    
    public string Info => $"{SourcePort} → {DestPort} | Host:{(string.IsNullOrEmpty(HostName) ? unknown : HostName)} | ID: {Id}";

    public static void SetTimeFormat(TimeFormatType format)
    {
        _currentTimeFormat = format;
    }

    public static void SetCaptureStartTime(DateTime startTime)
    {
        _captureStartTime = startTime;
    }

    public void NotifyTimeDisplayChanged()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(TimeDisplay)));
    }

    public static PacketInfo FromSnapshot(SnapshotStruct snapshot, int number)
    {
        DateTime captureTime;
        if (snapshot.TimestampSec > 0)
        {
            captureTime = DateTimeOffset.FromUnixTimeSeconds((long)snapshot.TimestampSec)
                .AddTicks(snapshot.TimestampUsec * 10) // Microseconds to ticks
                .LocalDateTime;
        }
        else
        {
            captureTime = DateTime.Now;
        }
        
        byte[]? rawData = null;
        if (snapshot.CaptureLen > 0 && snapshot.RawData != null)
        {
            rawData = new byte[snapshot.CaptureLen];
            Array.Copy(snapshot.RawData, rawData, (int)snapshot.CaptureLen);
        }
        
        return new PacketInfo
        {
            Number = number,
            Id = snapshot.Id,
            SourcePort = snapshot.SourcePort,
            DestPort = snapshot.DestPort,
            Protocol = snapshot.Protocol ?? "",
            SourceIp = snapshot.SourceIp ?? "",
            DestIp = snapshot.DestIp ?? "",
            SourceMac = snapshot.SourceMac ?? "",
            DestMac = snapshot.DestMac ?? "",
            HostName = snapshot.HostName ?? "",
            CaptureTime = captureTime,
            RawData = rawData,
            CaptureLen = snapshot.CaptureLen,
            OriginalLen = snapshot.OriginalLen
        };
    }
    
    public SnapshotStruct ToSnapshot()
    {
        var snapshot = new SnapshotStruct
        {
            Id = Id,
            SourcePort = SourcePort,
            DestPort = DestPort,
            Protocol = Protocol,
            SourceIp = SourceIp,
            DestIp = DestIp,
            SourceMac = SourceMac,
            DestMac = DestMac,
            HostName = HostName,
            CaptureLen = CaptureLen,
            OriginalLen = OriginalLen,
            TimestampSec = (ulong)new DateTimeOffset(CaptureTime).ToUnixTimeSeconds(),
            TimestampUsec = (uint)(CaptureTime.Ticks % TimeSpan.TicksPerSecond / 10),
            RawData = new byte[65536]
        };
        
        if (RawData != null && RawData.Length > 0)
        {
            Array.Copy(RawData, snapshot.RawData, Math.Min(RawData.Length, 65536));
        }
        
        return snapshot;
    }
}