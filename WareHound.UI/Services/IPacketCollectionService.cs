using System.Collections.ObjectModel;
using System.IO;
using WareHound.UI.Models;

namespace WareHound.UI.Services
{
    public interface IPacketCollectionService
    {
        ObservableCollection<SavedCollection> Collections { get; }
        SavedCollection CreateCollection(string name, IEnumerable<PacketInfo> packets);
        void AddToCollection(string collectionId, IEnumerable<PacketInfo> packets);
        void RemoveCollection(string collectionId);
        void ExportToCsv(string collectionId, string filePath);
    }
}
