using System.Collections.ObjectModel;
using Prism.Commands;
using Prism.Mvvm;
using Prism.Regions;
using WareHound.UI.Infrastructure.Services;
using WareHound.UI.Models;

namespace WareHound.UI.ViewModels
{
    public class LogViewModel : BindableBase, INavigationAware
    {
        private readonly ILoggerService _loggerService;
        private string _filterText = "";
        private LogLevel? _selectedLevelFilter;
        private LogEntry? _selectedLogEntry;
        public ObservableCollection<LogEntry> LogEntries => _loggerService.LogEntries;
        public string[] LogLevels { get; } = { "All", "Debug", "Info", "Warning", "Error" };

        public string FilterText
        {
            get => _filterText;
            set => SetProperty(ref _filterText, value);
        }

        public LogEntry? SelectedLogEntry
        {
            get => _selectedLogEntry;
            set => SetProperty(ref _selectedLogEntry, value);
        }

        public int SelectedLevelIndex
        {
            get => _selectedLevelFilter.HasValue ? (int)_selectedLevelFilter.Value + 1 : 0;
            set
            {
                _selectedLevelFilter = value == 0 ? null : (LogLevel)(value - 1);
                RaisePropertyChanged();
            }
        }

        public int LogCount => LogEntries.Count;
        public int ErrorCount => LogEntries.Count(e => e.Level == LogLevel.Error);
        public int WarningCount => LogEntries.Count(e => e.Level == LogLevel.Warning);

        public DelegateCommand ClearLogsCommand { get; }
        public DelegateCommand CopySelectedCommand { get; }
        public DelegateCommand ExportLogsCommand { get; }

        public LogViewModel(ILoggerService loggerService)
        {
            _loggerService = loggerService;
            
            ClearLogsCommand = new DelegateCommand(ClearLogs);
            CopySelectedCommand = new DelegateCommand(CopySelected, () => SelectedLogEntry != null)
                .ObservesProperty(() => SelectedLogEntry);
            ExportLogsCommand = new DelegateCommand(ExportLogs);

            LogEntries.CollectionChanged += (s, e) =>
            {
                RaisePropertyChanged(nameof(LogCount));
                RaisePropertyChanged(nameof(ErrorCount));
                RaisePropertyChanged(nameof(WarningCount));
            };

            _loggerService.Log("Log viewer opened");
        }

        private void ClearLogs()
        {
            _loggerService.ClearLogs();
        }

        private void CopySelected()
        {
            if (SelectedLogEntry != null)
            {
                var text = $"[{SelectedLogEntry.TimestampDisplay}] [{SelectedLogEntry.LevelDisplay}] {SelectedLogEntry.Message}";
                if (!string.IsNullOrEmpty(SelectedLogEntry.Exception))
                {
                    text += $"\n{SelectedLogEntry.Exception}";
                }
                System.Windows.Clipboard.SetText(text);
            }
        }

        private void ExportLogs()
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|Log files (*.log)|*.log|All files (*.*)|*.*",
                DefaultExt = ".txt",
                FileName = $"WareHound_Logs_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                var lines = LogEntries.Select(e => 
                    $"[{e.TimestampDisplay}] [{e.LevelDisplay}] {e.Message}" + 
                    (string.IsNullOrEmpty(e.Exception) ? "" : $"\n  {e.Exception}"));
                
                System.IO.File.WriteAllLines(dialog.FileName, lines);
                _loggerService.Log($"Logs exported to {dialog.FileName}");
            }
        }

        public void OnNavigatedTo(NavigationContext navigationContext)
        {
            _loggerService.LogDebug("Navigated to Log view");
        }

        public bool IsNavigationTarget(NavigationContext navigationContext) => true;
        public void OnNavigatedFrom(NavigationContext navigationContext) { }
    }
}
