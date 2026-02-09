using Prism.Events;

namespace WareHound.UI.Infrastructure.Events
{

    public class DevicesLoadingEvent : PubSubEvent<bool> { }

    public class DevicesLoadedEvent : PubSubEvent { }

    public class DevicesLoadFailedEvent : PubSubEvent<string> { }
}
