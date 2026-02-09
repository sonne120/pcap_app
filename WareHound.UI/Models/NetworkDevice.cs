namespace WareHound.UI.Models
{
    public class NetworkDevice
    {
        public int Index { get; set; }
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";

        public string DisplayName => string.IsNullOrEmpty(Description) ? Name : Description;
        public override string ToString() => DisplayName;
    }
}
