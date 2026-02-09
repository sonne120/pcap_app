using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace WareHound.UI.ViewModels;

public class ProtocolBarItem : INotifyPropertyChanged
{
    private string _protocol = string.Empty;
    private double _percentage;
    private string _color = "#3B82F6";
    private long _packetCount;
    
    public string Protocol
    {
        get => _protocol;
        set { _protocol = value; OnPropertyChanged(); }
    }
    
    public double Percentage
    {
        get => _percentage;
        set { _percentage = value; OnPropertyChanged(); OnPropertyChanged(nameof(PercentageText)); }
    }
    
    public string Color
    {
        get => _color;
        set { _color = value; OnPropertyChanged(); }
    }
    
    public long PacketCount
    {
        get => _packetCount;
        set { _packetCount = value; OnPropertyChanged(); }
    }
    
    public string PercentageText => $"{Percentage:F1}%";
    
    public event PropertyChangedEventHandler? PropertyChanged;
    
    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

/// <summary>
/// Display model for top talker IP addresses in the stats panel.
/// </summary>
public class TopTalkerDisplayItem : INotifyPropertyChanged
{
    private string _ipAddress = string.Empty;
    private long _packetCount;
    private double _percentage;
    
    public string IpAddress
    {
        get => _ipAddress;
        set { _ipAddress = value; OnPropertyChanged(); }
    }
    
    public long PacketCount
    {
        get => _packetCount;
        set { _packetCount = value; OnPropertyChanged(); OnPropertyChanged(nameof(PacketCountText)); }
    }
    
    public double Percentage
    {
        get => _percentage;
        set { _percentage = value; OnPropertyChanged(); }
    }
    
    public string PacketCountText => PacketCount.ToString("N0") + " packets";
    
    public event PropertyChangedEventHandler? PropertyChanged;
    
    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
