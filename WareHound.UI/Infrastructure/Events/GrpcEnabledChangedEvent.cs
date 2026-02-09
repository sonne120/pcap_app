using Prism.Events;

namespace WareHound.UI.Infrastructure.Events
{
    public class GrpcSettings
    {
        public bool Enabled { get; set; }
        public string ServerAddress { get; set; } = "https://localhost:5001";
    }

    public class GrpcEnabledChangedEvent : PubSubEvent<GrpcSettings> { }
}
