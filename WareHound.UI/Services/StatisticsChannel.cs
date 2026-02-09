using System.Threading.Channels;
using WareHound.UI.Models;

namespace WareHound.UI.Services;

public interface IStatisticsChannel
{
    ChannelWriter<StatisticsSnapshot> Writer { get; }
    ChannelReader<StatisticsSnapshot> Reader { get; }
}

public sealed class StatisticsChannel : IStatisticsChannel
{
    private readonly Channel<StatisticsSnapshot> _channel;

    public StatisticsChannel()
    {
        var options = new BoundedChannelOptions(10)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = false,
            SingleWriter = true
        };
        _channel = Channel.CreateBounded<StatisticsSnapshot>(options);
    }

    public ChannelWriter<StatisticsSnapshot> Writer => _channel.Writer;
    public ChannelReader<StatisticsSnapshot> Reader => _channel.Reader;
}
