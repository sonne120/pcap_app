using Prism.Events;
using WareHound.UI.Infrastructure.Events;

namespace WareHound.UI.Services;

public class PcapFileServiceFactory
{
    private readonly NativePcapFileService _nativeService;
    private readonly SharpPcapFileService _sharpPcapService;
    private PcapBackend _currentBackend = PcapBackend.SharpPcap; 

    public PcapFileServiceFactory(
        NativePcapFileService nativeService,
        SharpPcapFileService sharpPcapService,
        IEventAggregator eventAggregator)
    {
        _nativeService = nativeService;
        _sharpPcapService = sharpPcapService;
        
        eventAggregator.GetEvent<PcapBackendChangedEvent>().Subscribe(OnBackendChanged);
    }

    private void OnBackendChanged(PcapBackend backend)
    {
        _currentBackend = backend;
    }
    public IPcapFileService GetService()
    {
        return _currentBackend switch
        {
            PcapBackend.Native => _nativeService,
            PcapBackend.SharpPcap => _sharpPcapService,
            _ => _sharpPcapService
        };
    }

    public IPcapFileService GetService(PcapBackend backend)
    {
        return backend switch
        {
            PcapBackend.Native => _nativeService,
            PcapBackend.SharpPcap => _sharpPcapService,
            _ => _sharpPcapService
        };
    }

    public PcapBackend CurrentBackend => _currentBackend;
}
