using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using WareHound.UI.Models;

namespace WareHound.UI.Services;

public class NativePcapFileService : IPcapFileService
{
    private const string DllName = "WareHound.Sniffer.dll";
    
    public string BackendName => "Native (C++ pcap)";

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    [return: MarshalAs(UnmanagedType.I1)]
    private static extern bool Sniffer_SavePcap(
        [MarshalAs(UnmanagedType.LPStr)] string filePath,
        IntPtr packets,
        int packetCount);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr Sniffer_LoadPcap(
        [MarshalAs(UnmanagedType.LPStr)] string filePath,
        out int packetCount);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void Sniffer_FreePcapData(IntPtr data);

    public bool CanHandle(string filePath)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        return ext == ".pcap" || ext == ".cap";
    }

    public async Task SaveAsync(string filePath, IEnumerable<PacketInfo> packets, 
        IProgress<int>? progress = null, CancellationToken cancellationToken = default)
    {
        var packetList = packets.Where(p => p.RawData != null && p.CaptureLen > 0).ToList();
        
        if (packetList.Count == 0)
        {
            throw new InvalidOperationException("No packets with raw data to save. Packets must have been captured (not just metadata).");
        }

        await Task.Run(() =>
        {
            int structSize = Marshal.SizeOf<SnapshotStruct>();
            IntPtr buffer = Marshal.AllocHGlobal(structSize * packetList.Count);

            try
            {
                for (int i = 0; i < packetList.Count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    var snapshot = packetList[i].ToSnapshot();
                    IntPtr ptr = IntPtr.Add(buffer, i * structSize);
                    Marshal.StructureToPtr(snapshot, ptr, false);
                    
                    progress?.Report((i + 1) * 100 / packetList.Count);
                }

                bool success = Sniffer_SavePcap(filePath, buffer, packetList.Count);
                
                if (!success)
                {
                    throw new IOException($"Failed to save PCAP file: {filePath}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }, cancellationToken);
    }

    public async Task<IList<PacketInfo>> LoadAsync(string filePath, 
        IProgress<int>? progress = null, CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            int packetCount;
            IntPtr dataPtr = Sniffer_LoadPcap(filePath, out packetCount);

            if (dataPtr == IntPtr.Zero || packetCount <= 0)
            {
                throw new IOException($"Failed to load PCAP file: {filePath}");
            }

            try
            {
                var packets = new List<PacketInfo>(packetCount);
                int structSize = Marshal.SizeOf<SnapshotStruct>();

                for (int i = 0; i < packetCount; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    IntPtr ptr = IntPtr.Add(dataPtr, i * structSize);
                    var snapshot = Marshal.PtrToStructure<SnapshotStruct>(ptr);
                    var packet = PacketInfo.FromSnapshot(snapshot, i + 1);
                    packets.Add(packet);
                    
                    progress?.Report((i + 1) * 100 / packetCount);
                }

                return packets;
            }
            finally
            {
                Sniffer_FreePcapData(dataPtr);
            }
        }, cancellationToken);
    }
}
