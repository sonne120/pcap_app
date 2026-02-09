using Prism.Events;
using WareHound.UI.Services;

namespace WareHound.UI.Infrastructure.Events;

public class PcapBackendChangedEvent : PubSubEvent<PcapBackend> { }
