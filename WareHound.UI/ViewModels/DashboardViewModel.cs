using System.Collections.ObjectModel;
using Microsoft.Win32;
using Prism.Commands;
using WareHound.UI.Infrastructure.ViewModels;
using WareHound.UI.Models;
using WareHound.UI.Services;

namespace WareHound.UI.ViewModels
{
    public class DashboardViewModel : BaseViewModel
    {
        private readonly IPacketCollectionService _collectionService;
        private SavedCollection? _selectedCollection;
        private PacketInfo? _selectedPacket;
        private ObservableCollection<TreeNode> _packetDetails = new();

        public ObservableCollection<SavedCollection> Collections => _collectionService.Collections;

        public SavedCollection? SelectedCollection
        {
            get => _selectedCollection;
            set
            {
                if (SetProperty(ref _selectedCollection, value))
                {
                    SelectedPacket = null;
                    DeleteCommand.RaiseCanExecuteChanged();
                    ExportCommand.RaiseCanExecuteChanged();
                }
            }
        }

        public PacketInfo? SelectedPacket
        {
            get => _selectedPacket;
            set
            {
                if (SetProperty(ref _selectedPacket, value))
                {
                    UpdatePacketDetails();
                }
            }
        }

        public ObservableCollection<TreeNode> PacketDetails
        {
            get => _packetDetails;
            set => SetProperty(ref _packetDetails, value);
        }

        public DelegateCommand DeleteCommand { get; }
        public DelegateCommand ExportCommand { get; }

        public DashboardViewModel(IPacketCollectionService collectionService)
        {
            _collectionService = collectionService ?? throw new ArgumentNullException(nameof(collectionService));

            DeleteCommand = new DelegateCommand(DeleteCollection, () => SelectedCollection != null)
                .ObservesProperty(() => SelectedCollection);
            ExportCommand = new DelegateCommand(ExportToCsv, () => SelectedCollection != null)
                .ObservesProperty(() => SelectedCollection);
        }


        private void DeleteCollection()
        {
            if (SelectedCollection == null) return;
            _collectionService.RemoveCollection(SelectedCollection.Id);
            SelectedCollection = null;
        }

        private void ExportToCsv()
        {
            if (SelectedCollection == null) return;

            var dialog = new SaveFileDialog
            {
                Filter = "CSV files (*.csv)|*.csv",
                FileName = $"{SelectedCollection.Name}.csv"
            };

            if (dialog.ShowDialog() == true)
            {
                _collectionService.ExportToCsv(SelectedCollection.Id, dialog.FileName);
            }
        }

        private void UpdatePacketDetails()
        {
            PacketDetails.Clear();
            if (SelectedPacket == null) return;

            var p = SelectedPacket;

            // Frame
            var frame = new TreeNode($"Packet #{p.Number}: {p.Protocol}");
            frame.AddChild($"Capture Time: {p.CaptureTime:yyyy-MM-dd HH:mm:ss.fff}");
            frame.AddChild($"Packet ID: {p.Id}");
            PacketDetails.Add(frame);

            // Ethernet
            var eth = new TreeNode($"Ethernet II, Src: {p.SourceMac}, Dst: {p.DestMac}");
            eth.AddChild($"Source MAC: {p.SourceMac}");
            eth.AddChild($"Destination MAC: {p.DestMac}");
            PacketDetails.Add(eth);

            // IP
            var ip = new TreeNode($"Internet Protocol, Src: {p.SourceIp}, Dst: {p.DestIp}");
            ip.AddChild($"Source IP: {p.SourceIp}");
            ip.AddChild($"Destination IP: {p.DestIp}");
            PacketDetails.Add(ip);

            // Protocol
            var proto = new TreeNode($"{p.Protocol}, Src Port: {p.SourcePort}, Dst Port: {p.DestPort}");
            proto.AddChild($"Source Port: {p.SourcePort}");
            proto.AddChild($"Destination Port: {p.DestPort}");
            PacketDetails.Add(proto);
        }
    }
}
