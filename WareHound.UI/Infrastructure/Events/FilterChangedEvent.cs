using Prism.Events;

namespace WareHound.UI.Infrastructure.Events
{
    public enum FilterType
    {
        All,
        Protocol,
        SourceIP,
        DestIP,
        SourcePort,
        DestPort
    }

    public class FilterCriteria
    {
        public FilterType Type { get; set; } = FilterType.All;
        public string Value { get; set; } = "";

        public static FilterCriteria Empty => new() { Type = FilterType.All, Value = "" };
    }

    public class FilterChangedEvent : PubSubEvent<FilterCriteria> { }
}
