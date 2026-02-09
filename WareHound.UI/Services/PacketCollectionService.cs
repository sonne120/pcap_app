using System.Collections.ObjectModel;
using WareHound.UI.Models;

namespace WareHound.UI.Services
{
    public class SavedCollection
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public DateTime ModifiedAt { get; set; }
        public ObservableCollection<PacketInfo> Packets { get; set; } = new();
        public int PacketCount => Packets.Count;
        public string DisplayInfo => $"{Name} ({PacketCount} packets)";
    }

    public class PacketCollectionService : IPacketCollectionService
    {
        public ObservableCollection<SavedCollection> Collections { get; } = new();

        public SavedCollection CreateCollection(string name, IEnumerable<PacketInfo> packets)
        {
            var collection = new SavedCollection
            {
                Id = Guid.NewGuid().ToString(),
                Name = name,
                CreatedAt = DateTime.Now,
                ModifiedAt = DateTime.Now,
                Packets = new ObservableCollection<PacketInfo>(packets)
            };
            Collections.Add(collection);
            return collection;
        }

        public void AddToCollection(string collectionId, IEnumerable<PacketInfo> packets)
        {
            var collection = Collections.FirstOrDefault(c => c.Id == collectionId);
            if (collection == null) return;

            foreach (var packet in packets)
            {
                collection.Packets.Add(packet);
            }
            collection.ModifiedAt = DateTime.Now;
        }

        public void RemoveCollection(string collectionId)
        {
            var collection = Collections.FirstOrDefault(c => c.Id == collectionId);
            if (collection != null)
            {
                Collections.Remove(collection);
            }
        }

        public void ExportToCsv(string collectionId, string filePath)
        {
            var collection = Collections.FirstOrDefault(c => c.Id == collectionId);
            if (collection == null) return;

            var lines = new List<string>
            {
                "Number,Time,Protocol,SourceIP,DestIP,SourcePort,DestPort,SourceMAC,DestMAC,HostName"
            };

            foreach (var p in collection.Packets)
            {
                lines.Add(string.Join(",",
                    p.Number,
                    p.CaptureTime.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    p.Protocol,
                    p.SourceIp,
                    p.DestIp,
                    p.SourcePort,
                    p.DestPort,
                    p.SourceMac,
                    p.DestMac,
                    p.HostName));
            }

            System.IO.File.WriteAllLines(filePath, lines);
        }
    }
}
