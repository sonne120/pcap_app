using System.IO;
using System.Linq;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using WareHound.UI.Models;

namespace WareHound.UI.Services;

public class SharpPcapFileService : IPcapFileService
{
    public string BackendName => "SharpPcap (Managed)";

    public bool CanHandle(string filePath)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        return ext == ".pcap" || ext == ".pcapng" || ext == ".cap";
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
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
            
            using var writer = new CaptureFileWriterDevice(filePath);
            writer.Open(LinkLayers.Ethernet);

            for (int i = 0; i < packetList.Count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var pkt = packetList[i];
                if (pkt.RawData == null) continue;

                var timestamp = new PosixTimeval(pkt.CaptureTime);
                var rawCapture = new RawCapture(LinkLayers.Ethernet, timestamp, pkt.RawData);
                
                writer.Write(rawCapture);
                
                progress?.Report((i + 1) * 100 / packetList.Count);
            }

            writer.Close();
        }, cancellationToken);
    }

    public async Task<IList<PacketInfo>> LoadAsync(string filePath,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            var packets = new List<PacketInfo>();

            using var reader = new CaptureFileReaderDevice(filePath);
            reader.Open();

            int packetNumber = 0;
            GetPacketStatus status;
            PacketCapture e;

            while ((status = reader.GetNextPacket(out e)) == GetPacketStatus.PacketRead)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                packetNumber++;
                var rawCapture = e.GetPacket();
                var packet = ParsePacket(rawCapture, packetNumber);
                packets.Add(packet);
            
                if (packetNumber % 100 == 0)
                {
                    progress?.Report(packetNumber);
                }
            }

            reader.Close();
            return packets;
        }, cancellationToken);
    }

    private static PacketInfo ParsePacket(RawCapture rawCapture, int number)
    {
        var packetInfo = new PacketInfo
        {
            Number = number,
            CaptureTime = rawCapture.Timeval.Date,
            RawData = rawCapture.Data,
            CaptureLen = (uint)rawCapture.Data.Length,
            OriginalLen = (uint)rawCapture.Data.Length
        };

        try
        {
            var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

            // Parse Ethernet layer
            var ethernetPacket = packet.Extract<EthernetPacket>();
            if (ethernetPacket != null)
            {
                packetInfo.SourceMac = ethernetPacket.SourceHardwareAddress.ToString();
                packetInfo.DestMac = ethernetPacket.DestinationHardwareAddress.ToString();
            }

            // Parse IP layer
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket != null)
            {
                packetInfo.SourceIp = ipPacket.SourceAddress.ToString();
                packetInfo.DestIp = ipPacket.DestinationAddress.ToString();
                packetInfo.Id = ipPacket is IPv4Packet ipv4 ? ipv4.Id : 0;
                packetInfo.Protocol = ipPacket.Protocol.ToString().ToUpper();
            }

            // Parse TCP layer
            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket != null)
            {
                packetInfo.SourcePort = tcpPacket.SourcePort;
                packetInfo.DestPort = tcpPacket.DestinationPort;
                packetInfo.Protocol = "TCP";
            }

            // Parse UDP layer
            var udpPacket = packet.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                packetInfo.SourcePort = udpPacket.SourcePort;
                packetInfo.DestPort = udpPacket.DestinationPort;
                packetInfo.Protocol = "UDP";
            }

            // Parse ICMP layer
            var icmpPacket = packet.Extract<IcmpV4Packet>();
            if (icmpPacket != null)
            {
                packetInfo.Protocol = "ICMP";
            }
        }
        catch
        {
            packetInfo.Protocol = "UNKNOWN";
        }

        return packetInfo;
    }
}
