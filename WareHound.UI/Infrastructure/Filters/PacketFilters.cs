using System;
using WareHound.UI.Infrastructure.Events;
using WareHound.UI.Models;

namespace WareHound.UI.Infrastructure.Filters
{
    public interface IPacketFilter
    {
        bool IsMatch(PacketInfo packet);
    }

    public class NoOpFilter : IPacketFilter
    {
        public bool IsMatch(PacketInfo packet)
        {
            return true;
        }
    }

    public class ProtocolFilter : IPacketFilter
    {
        private readonly string _protocol;

        public ProtocolFilter(string protocol)
        {
            _protocol = protocol?.Trim().ToLowerInvariant() ?? string.Empty;
        }

        public bool IsMatch(PacketInfo packet)
        {
            return !string.IsNullOrEmpty(packet.Protocol) && 
                   packet.Protocol.ToLowerInvariant().Contains(_protocol);
        }
    }

    public class SourceIpFilter : IPacketFilter
    {
        private readonly string _ip;

        public SourceIpFilter(string ip)
        {
            _ip = ip?.Trim() ?? string.Empty;
        }

        public bool IsMatch(PacketInfo packet)
        {
            return !string.IsNullOrEmpty(packet.SourceIp) && 
                   packet.SourceIp.Contains(_ip);
        }
    }

    public class DestIpFilter : IPacketFilter
    {
        private readonly string _ip;

        public DestIpFilter(string ip)
        {
            _ip = ip?.Trim() ?? string.Empty;
        }

        public bool IsMatch(PacketInfo packet)
        {
            return !string.IsNullOrEmpty(packet.DestIp) && 
                   packet.DestIp.Contains(_ip);
        }
    }

    public class SourcePortFilter : IPacketFilter
    {
        private readonly int _port;
        private readonly bool _isValid;

        public SourcePortFilter(string port)
        {
            _isValid = int.TryParse(port, out _port);
        }

        public bool IsMatch(PacketInfo packet)
        {
            if (!_isValid) return true;
            return packet.SourcePort == _port;
        }
    }

    public class DestPortFilter : IPacketFilter
    {
        private readonly int _port;
        private readonly bool _isValid;

        public DestPortFilter(string port)
        {
            _isValid = int.TryParse(port, out _port);
        }

        public bool IsMatch(PacketInfo packet)
        {
            if (!_isValid) return true;
            return packet.DestPort == _port;
        }
    }

    public class AllFieldsFilter : IPacketFilter
    {
        private readonly string _value;

        public AllFieldsFilter(string value)
        {
            _value = value?.Trim().ToLowerInvariant() ?? string.Empty;
        }

        public bool IsMatch(PacketInfo packet)
        {
            if (string.IsNullOrEmpty(_value)) return true;
            
            return (packet.Protocol?.ToLowerInvariant().Contains(_value) ?? false) ||
                   (packet.SourceIp?.Contains(_value) ?? false) ||
                   (packet.DestIp?.Contains(_value) ?? false) ||
                   packet.SourcePort.ToString().Contains(_value) ||
                   packet.DestPort.ToString().Contains(_value);
        }
    }

    public static class FilterFactory
    {
        public static IPacketFilter Create(FilterCriteria criteria)
        {
            if (criteria == null || string.IsNullOrWhiteSpace(criteria.Value))
            {
                return new NoOpFilter();
            }

            return criteria.Type switch
            {
                FilterType.Protocol => new ProtocolFilter(criteria.Value),
                FilterType.SourceIP => new SourceIpFilter(criteria.Value),
                FilterType.DestIP => new DestIpFilter(criteria.Value),
                FilterType.SourcePort => new SourcePortFilter(criteria.Value),
                FilterType.DestPort => new DestPortFilter(criteria.Value),
                FilterType.All => new AllFieldsFilter(criteria.Value),
                _ => new NoOpFilter()
            };
        }
    }
}
