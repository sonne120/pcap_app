using System.Runtime.InteropServices;

namespace WareHound.UI.Models
{
    [StructLayout(LayoutKind.Sequential, Pack = 2, CharSet = CharSet.Ansi)]
    public struct SnapshotStruct
    {
        public int Id;
        public int SourcePort;
        public int DestPort;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string Protocol;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string SourceIp;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string DestIp;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string SourceMac;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string DestMac;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string HostName;
        public uint CaptureLen;
        public uint OriginalLen;
        public ulong TimestampSec;
        public uint TimestampUsec;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 65536)]
        public byte[] RawData;
    }
    
    [StructLayout(LayoutKind.Sequential, Pack = 2, CharSet = CharSet.Ansi)]
    public struct SnapshotHeader
    {
        public int Id;
        public int SourcePort;
        public int DestPort;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string Protocol;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string SourceIp;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string DestIp;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string SourceMac;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string DestMac;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 22)]
        public string HostName;      
        public uint CaptureLen;       
        public uint OriginalLen;     
        public ulong TimestampSec;   
        public uint TimestampUsec;  
   
        public SnapshotStruct ToSnapshot(byte[]? rawData)
        {
            return new SnapshotStruct
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
                TimestampSec = TimestampSec,
                TimestampUsec = TimestampUsec,
                RawData = rawData ?? Array.Empty<byte>()
            };
        }
        public int GetTotalIPCSize() => Marshal.SizeOf<SnapshotHeader>() + (int)CaptureLen;
    }
}
