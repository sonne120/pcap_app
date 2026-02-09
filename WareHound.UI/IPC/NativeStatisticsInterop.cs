using System.Runtime.InteropServices;

namespace WareHound.UI.IPC;

[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
public struct NativeProtocolStats
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string ProtocolName;
    public ulong PacketCount;
    public ulong ByteCount;
    public double Percentage;
}

[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
public struct NativeTalkerStats
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string IpAddress;
    public ulong PacketCount;
    public ulong ByteCount;
}

[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
public struct NativePortStats
{
    public ushort Port;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string ServiceName;
    public ulong PacketCount;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct NativeCaptureStatistics
{
    public ulong TotalPackets;
    public ulong TotalBytes;
    public ulong ActiveFlows;
    public double PacketsPerSecond;
    public double BytesPerSecond;
    public double CaptureDurationSeconds;
    public int UniqueProtocols;
    public int UniqueSourceIPs;
    public int UniqueDestIPs;
}

public interface INativeStatisticsInterop
{
    void EnableNativeStats(bool enable);
    bool IsNativeStatsEnabled();
    NativeCaptureStatistics? GetCaptureStatistics();
    NativeProtocolStats[] GetProtocolStats(int maxCount = 20);
    NativeTalkerStats[] GetTopSourceIPs(int maxCount = 10);
    NativeTalkerStats[] GetTopDestIPs(int maxCount = 10);
    NativePortStats[] GetTopPorts(int maxCount = 10);
    void ClearStatistics();
    ulong GetFlowCount();
}

public class NativeStatisticsInterop : INativeStatisticsInterop
{
    private const string DllName = "WareHound.Sniffer.dll";
    private readonly IntPtr _snifferHandle;

    public NativeStatisticsInterop(IntPtr snifferHandle)
    {
        _snifferHandle = snifferHandle;
    }


    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void Sniffer_EnableNativeStats(IntPtr sniffer, [MarshalAs(UnmanagedType.I1)] bool enable);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    private static extern bool Sniffer_IsNativeStatsEnabled(IntPtr sniffer);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    private static extern bool Sniffer_GetCaptureStatistics(IntPtr sniffer, out NativeCaptureStatistics stats);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int Sniffer_GetProtocolStats(IntPtr sniffer, [Out] NativeProtocolStats[] stats, int maxCount);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int Sniffer_GetTopSourceIPs(IntPtr sniffer, [Out] NativeTalkerStats[] stats, int maxCount);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int Sniffer_GetTopDestIPs(IntPtr sniffer, [Out] NativeTalkerStats[] stats, int maxCount);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int Sniffer_GetTopPorts(IntPtr sniffer, [Out] NativePortStats[] stats, int maxCount);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void Sniffer_ClearStatistics(IntPtr sniffer);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern ulong Sniffer_GetFlowCount(IntPtr sniffer);

    public void EnableNativeStats(bool enable)
    {
        Sniffer_EnableNativeStats(_snifferHandle, enable);
    }

    public bool IsNativeStatsEnabled()
    {
        return Sniffer_IsNativeStatsEnabled(_snifferHandle);
    }

    public NativeCaptureStatistics? GetCaptureStatistics()
    {
        if (Sniffer_GetCaptureStatistics(_snifferHandle, out var stats))
        {
            return stats;
        }
        return null;
    }

    public NativeProtocolStats[] GetProtocolStats(int maxCount = 20)
    {
        var buffer = new NativeProtocolStats[maxCount];
        int count = Sniffer_GetProtocolStats(_snifferHandle, buffer, maxCount);
        
        if (count <= 0) return Array.Empty<NativeProtocolStats>();
        
        var result = new NativeProtocolStats[count];
        Array.Copy(buffer, result, count);
        return result;
    }

    public NativeTalkerStats[] GetTopSourceIPs(int maxCount = 10)
    {
        var buffer = new NativeTalkerStats[maxCount];
        int count = Sniffer_GetTopSourceIPs(_snifferHandle, buffer, maxCount);
        
        if (count <= 0) return Array.Empty<NativeTalkerStats>();
        
        var result = new NativeTalkerStats[count];
        Array.Copy(buffer, result, count);
        return result;
    }

    public NativeTalkerStats[] GetTopDestIPs(int maxCount = 10)
    {
        var buffer = new NativeTalkerStats[maxCount];
        int count = Sniffer_GetTopDestIPs(_snifferHandle, buffer, maxCount);
        
        if (count <= 0) return Array.Empty<NativeTalkerStats>();
        
        var result = new NativeTalkerStats[count];
        Array.Copy(buffer, result, count);
        return result;
    }

    public NativePortStats[] GetTopPorts(int maxCount = 10)
    {
        var buffer = new NativePortStats[maxCount];
        int count = Sniffer_GetTopPorts(_snifferHandle, buffer, maxCount);
        
        if (count <= 0) return Array.Empty<NativePortStats>();
        
        var result = new NativePortStats[count];
        Array.Copy(buffer, result, count);
        return result;
    }

    public void ClearStatistics()
    {
        Sniffer_ClearStatistics(_snifferHandle);
    }

    public ulong GetFlowCount()
    {
        return Sniffer_GetFlowCount(_snifferHandle);
    }
}
