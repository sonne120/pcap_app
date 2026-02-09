using Prism.Events;
using WareHound.UI.Models;

namespace WareHound.UI.Infrastructure.Events;

public class PacketCapturedEvent : PubSubEvent<PacketInfo> { }
