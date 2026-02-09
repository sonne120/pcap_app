using System.Collections.Generic;

namespace WareHound.UI.Models;

public sealed record StatisticsSnapshot
{
    public required long TotalPackets { get; init; }
    public required double PacketsPerSecond { get; init; }
    public required DateTime Timestamp { get; init; }
    public required IReadOnlyList<ProtocolStatItem> ProtocolStats { get; init; }
    public required long TotalBytes { get; init; }
    public required int UniqueProtocols { get; init; }
    public required int UniqueIps { get; init; }
    public TimeSpan CaptureElapsed { get; init; } = TimeSpan.Zero;
    
    public IReadOnlyList<TopTalkerItem> TopTalkers { get; init; } = Array.Empty<TopTalkerItem>();
    
    public double CurrentPps { get; init; }
    public double AveragePps { get; init; }
    public double MaxPps { get; init; }
}

public sealed record ProtocolStatItem(string Protocol, long PacketCount, double Percentage);
