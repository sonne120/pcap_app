using System.Collections.Concurrent;
using WareHound.UI.Models;
using WareHound.UI.Services.BackgroundJobs.AsyncCollection;

namespace WareHound.UI.Services.BackgroundJobs
{
    public class BackgroundJobs : IBackgroundJobs<SnapshotStruct>
    {
        public ConcurrentQueue<SnapshotStruct> BackgroundTasks { get; set; } = new();
        public AsyncConcurrencyQueue<SnapshotStruct> BackgroundTaskGrpc { get; set; } = new();
    }
}
