using Prism.Events;
using WareHound.UI.Models;

namespace WareHound.UI.Infrastructure.Events;

public class PcapLoadedEvent : PubSubEvent<IList<PacketInfo>> { }

public class PcapSaveRequestEvent : PubSubEvent { }

public class PcapSaveResponseEvent : PubSubEvent<IList<PacketInfo>> { }
