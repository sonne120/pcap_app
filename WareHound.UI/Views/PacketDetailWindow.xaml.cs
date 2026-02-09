using System.Text;
using System.Windows;
using WareHound.UI.Models;

namespace WareHound.UI.Views;

public partial class PacketDetailWindow : Window
{
    public PacketDetailWindow(PacketInfo packet)
    {
        InitializeComponent();
        LoadPacketData(packet);
    }

    private void LoadPacketData(PacketInfo packet)
    {
        // Header
        HeaderProtocol.Text = packet.Protocol;
        HeaderTime.Text = packet.TimeDisplay;
        HeaderPacketNo.Text = $"Packet #{packet.Number}";

        // Network Layer
        SourceIp.Text = packet.SourceIp;
        DestIp.Text = packet.DestIp;
        SourcePort.Text = packet.SourcePort.ToString();
        DestPort.Text = packet.DestPort.ToString();

        // Data Link Layer
        SourceMac.Text = packet.SourceMac;
        DestMac.Text = packet.DestMac;

        // Additional Info
        Protocol.Text = packet.Protocol;
        PacketId.Text = packet.Id.ToString();
        HostName.Text = string.IsNullOrEmpty(packet.HostName) ? "Unknown" : packet.HostName;
        CaptureTime.Text = packet.CaptureTime.ToString("yyyy-MM-dd HH:mm:ss.fff");

        // Generate Hex Dump
        HexDump.Text = GenerateHexDump(packet);
    }

    private string GenerateHexDump(PacketInfo packet)
    {
        var sb = new StringBuilder();
        
        var packetBytes = new List<byte>();
        
        // Ethernet header (14 bytes)
        packetBytes.AddRange(ParseMacAddress(packet.DestMac));
        packetBytes.AddRange(ParseMacAddress(packet.SourceMac));
        packetBytes.Add(0x08); packetBytes.Add(0x00); // EtherType: IPv4
        
        // IP header simulation (20 bytes)
        packetBytes.Add(0x45); // Version + IHL
        packetBytes.Add(0x00); // DSCP + ECN
        packetBytes.Add(0x00); packetBytes.Add(0x28); // Total length
        packetBytes.Add((byte)(packet.Id >> 8)); packetBytes.Add((byte)(packet.Id & 0xFF)); // Identification
        packetBytes.Add(0x40); packetBytes.Add(0x00); // Flags + Fragment offset
        packetBytes.Add(0x40); // TTL
        packetBytes.Add(GetProtocolNumber(packet.Protocol)); // Protocol
        packetBytes.Add(0x00); packetBytes.Add(0x00); // Header checksum
        packetBytes.AddRange(ParseIpAddress(packet.SourceIp));
        packetBytes.AddRange(ParseIpAddress(packet.DestIp));
        
        // Transport layer header (8 bytes for UDP, 20 for TCP)
        packetBytes.Add((byte)(packet.SourcePort >> 8)); packetBytes.Add((byte)(packet.SourcePort & 0xFF));
        packetBytes.Add((byte)(packet.DestPort >> 8)); packetBytes.Add((byte)(packet.DestPort & 0xFF));
        
        if (packet.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
        {
            // TCP specific fields
            packetBytes.Add(0x00); packetBytes.Add(0x00); packetBytes.Add(0x00); packetBytes.Add(0x01); // Seq
            packetBytes.Add(0x00); packetBytes.Add(0x00); packetBytes.Add(0x00); packetBytes.Add(0x00); // Ack
            packetBytes.Add(0x50); // Data offset
            packetBytes.Add(0x02); // Flags (SYN)
            packetBytes.Add(0xFF); packetBytes.Add(0xFF); // Window
            packetBytes.Add(0x00); packetBytes.Add(0x00); // Checksum
            packetBytes.Add(0x00); packetBytes.Add(0x00); // Urgent pointer
        }
        else
        {
            // UDP specific fields
            packetBytes.Add(0x00); packetBytes.Add(0x08); // Length
            packetBytes.Add(0x00); packetBytes.Add(0x00); // Checksum
        }

        // Format as hex dump
        var bytes = packetBytes.ToArray();
        for (int i = 0; i < bytes.Length; i += 16)
        {
            // Offset
            sb.Append($"{i:X8}  ");
            
            // Hex bytes
            for (int j = 0; j < 16; j++)
            {
                if (i + j < bytes.Length)
                    sb.Append($"{bytes[i + j]:X2} ");
                else
                    sb.Append("   ");
                
                if (j == 7) sb.Append(" ");
            }
            
            sb.Append(" ");
            
            // ASCII representation
            for (int j = 0; j < 16 && i + j < bytes.Length; j++)
            {
                byte b = bytes[i + j];
                sb.Append(b >= 32 && b < 127 ? (char)b : '.');
            }
            
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private byte[] ParseMacAddress(string mac)
    {
        var result = new byte[6];
        if (string.IsNullOrEmpty(mac)) return result;
        
        try
        {
            var parts = mac.Split(':');
            for (int i = 0; i < Math.Min(6, parts.Length); i++)
            {
                result[i] = Convert.ToByte(parts[i], 16);
            }
        }
        catch { }
        return result;
    }

    private byte[] ParseIpAddress(string ip)
    {
        var result = new byte[4];
        if (string.IsNullOrEmpty(ip)) return result;
        
        try
        {
            var parts = ip.Split('.');
            for (int i = 0; i < Math.Min(4, parts.Length); i++)
            {
                result[i] = byte.Parse(parts[i]);
            }
        }
        catch { }
        return result;
    }

    private byte GetProtocolNumber(string protocol)
    {
        return protocol?.ToUpperInvariant() switch
        {
            "TCP" => 0x06,
            "UDP" => 0x11,
            "ICMP" => 0x01,
            "IGMP" => 0x02,
            _ => 0x00
        };
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
