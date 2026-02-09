using System.Collections.Concurrent;
using WareHound.UI.Services.BackgroundJobs.AsyncCollection;

namespace WareHound.UI.Services.BackgroundJobs
{
    public interface IBackgroundJobs<T>
    {
        ConcurrentQueue<T> BackgroundTasks { get; set; }
        AsyncConcurrencyQueue<T> BackgroundTaskGrpc { get; set; }

        void CleanBackgroundTask()
        {
            BackgroundTasks.Clear();
            BackgroundTaskGrpc.Clear();
        }
    }
}
