namespace WareHound.UI.Models;

public class CaptureStatistics
{
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public DateTime CaptureStartTime { get; set; }
    public DateTime CaptureEndTime { get; set; }
    public TimeSpan Duration => CaptureEndTime - CaptureStartTime;
    public Dictionary<string, ProtocolStats> ProtocolBreakdown { get; set; } = new(); 
    public Dictionary<string, long> TopSourceIPs { get; set; } = new();
    public Dictionary<string, long> TopDestIPs { get; set; } = new();
    
    public Dictionary<int, long> TopSourcePorts { get; set; } = new();
    public Dictionary<int, long> TopDestPorts { get; set; } = new();
    
    public List<TimelinePoint> PacketsTimeline { get; set; } = new();
    
    public double PacketsPerSecond => Duration.TotalSeconds > 0 
        ? TotalPackets / Duration.TotalSeconds 
        : 0;
    
    public double BytesPerSecond => Duration.TotalSeconds > 0 
        ? TotalBytes / Duration.TotalSeconds 
        : 0;
}

public class ProtocolStats
{
    public string Protocol { get; set; } = "";
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public double Percentage { get; set; }
}

public class TimelinePoint
{
    public DateTime Time { get; set; }
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
}
