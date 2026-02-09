using System.Collections.ObjectModel;
using System.Diagnostics;
using WareHound.UI.Models;

namespace WareHound.UI.Infrastructure.Services
{
    public interface ILoggerService
    {
        void Log(string message);
        void LogError(string message, Exception? exception = null);
        void LogDebug(string message);
        void LogWarning(string message);
        ObservableCollection<LogEntry> LogEntries { get; }
        void ClearLogs();
    }

    public class DebugLoggerService : ILoggerService
    {
        private const int MaxLogEntries = 5000;
        
        public ObservableCollection<LogEntry> LogEntries { get; } = new();

        public void Log(string message)
        {
            Debug.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] INFO: {message}");
            AddLogEntry(LogLevel.Info, message);
        }

        public void LogError(string message, Exception? exception = null)
        {
            Debug.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] ERROR: {message}");
            if (exception != null)
            {
                Debug.WriteLine($"    Exception: {exception.Message}");
                Debug.WriteLine($"    StackTrace: {exception.StackTrace}");
            }
            AddLogEntry(LogLevel.Error, message, exception?.ToString());
        }

        public void LogWarning(string message)
        {
            Debug.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] WARN: {message}");
            AddLogEntry(LogLevel.Warning, message);
        }

        public void LogDebug(string message)
        {
#if DEBUG
            Debug.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] DEBUG: {message}");
            AddLogEntry(LogLevel.Debug, message);
#endif
        }

        public void ClearLogs()
        {
            System.Windows.Application.Current?.Dispatcher?.Invoke(() =>
            {
                LogEntries.Clear();
            });
        }

        private void AddLogEntry(LogLevel level, string message, string? exception = null)
        {
            var entry = new LogEntry
            {
                Timestamp = DateTime.Now,
                Level = level,
                Message = message,
                Exception = exception
            };

            System.Windows.Application.Current?.Dispatcher?.Invoke(() =>
            {
                LogEntries.Add(entry);
                while (LogEntries.Count > MaxLogEntries)
                {
                    LogEntries.RemoveAt(0);
                }
            });
        }
    }
}
