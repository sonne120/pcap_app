using Prism.Events;

namespace WareHound.UI.Infrastructure.Events
{
    public enum TimeFormatType
    {
        Relative,
        Absolute,
        Delta
    }
    public class TimeFormatChangedEvent : PubSubEvent<TimeFormatType> { }
}
