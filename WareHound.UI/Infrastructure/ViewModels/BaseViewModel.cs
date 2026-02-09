using Prism.Events;
using Prism.Mvvm;
using Prism.Regions;
using Prism.Services.Dialogs;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using WareHound.UI.Infrastructure.Services;

namespace WareHound.UI.Infrastructure.ViewModels
{
    public abstract class BaseViewModel : BindableBase, INavigationAware, IDisposable
    {
        private readonly List<SubscriptionToken> _subscriptionTokens = new();
        private CancellationTokenSource? _cts;
        private bool _disposed;
        private bool _isBusy;
        private string _errorMessage = string.Empty;

        protected IEventAggregator? EventAggregator { get; }
        protected ILoggerService? _loggerService;

        protected bool IsDisposed => _disposed;

        protected CancellationToken CancellationToken =>
            (_cts ??= new CancellationTokenSource()).Token;

        public bool IsBusy
        {
            get => _isBusy;
            set => SetProperty(ref _isBusy, value);
        }

        public string ErrorMessage
        {
            get => _errorMessage;
            set
            {
                if (SetProperty(ref _errorMessage, value))
                {
                    RaisePropertyChanged(nameof(HasError));
                }
            }
        }

        public bool HasError => !string.IsNullOrEmpty(ErrorMessage);

        protected BaseViewModel()
        {
        }

        protected BaseViewModel(IEventAggregator eventAggregator, ILoggerService logger)
        {
            EventAggregator = eventAggregator ?? throw new ArgumentNullException(nameof(eventAggregator));
            _loggerService = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        protected void Subscribe<TEvent, TPayload>(Action<TPayload> handler)
            where TEvent : PubSubEvent<TPayload>, new()
        {
            if (EventAggregator == null)
                throw new InvalidOperationException("EventAggregator is not available. Use the constructor that accepts IEventAggregator.");

            var token = EventAggregator.GetEvent<TEvent>().Subscribe(handler);
            if (token != null)
                _subscriptionTokens.Add(token);
        }

        protected void SubscribeOnUIThread<TEvent, TPayload>(Action<TPayload> handler)
            where TEvent : PubSubEvent<TPayload>, new()
        {
            if (EventAggregator == null)
                throw new InvalidOperationException("EventAggregator is not available. Use the constructor that accepts IEventAggregator.");

            var token = EventAggregator.GetEvent<TEvent>().Subscribe(handler, ThreadOption.UIThread);
            if (token != null)
                _subscriptionTokens.Add(token);
        }

        protected void Subscribe<TEvent>(Action handler)
            where TEvent : PubSubEvent, new()
        {
            if (EventAggregator == null)
                throw new InvalidOperationException("EventAggregator is not available. Use the constructor that accepts IEventAggregator.");

            var token = EventAggregator.GetEvent<TEvent>().Subscribe(handler);
            if (token != null)
                _subscriptionTokens.Add(token);
        }
        protected void Publish<TEvent, TPayload>(TPayload payload)
            where TEvent : PubSubEvent<TPayload>, new()
        {
            EventAggregator?.GetEvent<TEvent>().Publish(payload);
        }

        protected void Publish<TEvent>()
            where TEvent : PubSubEvent, new()
        {
            EventAggregator?.GetEvent<TEvent>().Publish();
        }

        protected void CancelOperations()
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
        }

        #region Logging Helpers

        protected void Log(string message)
        {
            _loggerService?.Log(message);
        }

        protected void LogDebug(string message)
        {
            _loggerService?.LogDebug(message);
        }

        protected void LogWarning(string message)
        {
            _loggerService?.LogWarning(message);
        }

        protected void LogError(string message, Exception? ex = null)
        {
            _loggerService?.LogError(message, ex);
        }

        #endregion


        protected static void RunOnUI(Action action)
        {
            if (Application.Current?.Dispatcher == null)
            {
                action();
                return;
            }

            if (Application.Current.Dispatcher.CheckAccess())
            {
                action();
            }
            else
            {
                Application.Current.Dispatcher.Invoke(action);
            }
        }

        protected static void BeginOnUI(Action action)
        {
            if (Application.Current?.Dispatcher == null)
            {
                action();
                return;
            }

            if (Application.Current.Dispatcher.CheckAccess())
            {
                action();
            }
            else
            {
                Application.Current.Dispatcher.BeginInvoke(action);
            }
        }


        protected static async Task RunOnUIAsync(Action action)
        {
            if (Application.Current?.Dispatcher == null)
            {
                action();
                return;
            }

            if (Application.Current.Dispatcher.CheckAccess())
            {
                action();
            }
            else
            {
                await Application.Current.Dispatcher.InvokeAsync(action);
            }
        }

        protected void ClearError() => ErrorMessage = string.Empty;

        protected void SetError(string message) => ErrorMessage = message;

        protected void HandleException(Exception ex, string? context = null)
        {
            var message = context != null
                ? $"{context}: {ex.Message}"
                : ex.Message;
            SetError(message);
        }

        protected async Task ExecuteAsync(
            Func<Task> operation,
            string? errorContext = null,
            bool showBusy = true)
        {
            if (showBusy) IsBusy = true;
            ClearError();

            try
            {
                await operation();
            }
            catch (OperationCanceledException ex )
            {
                _loggerService.Log($"Logs exported to {ex.InnerException}");
            }
            catch (Exception ex)
            {
                HandleException(ex, errorContext);
            }
            finally
            {
                if (showBusy) IsBusy = false;
            }
        }
        protected async Task<T?> ExecuteAsync<T>(
            Func<Task<T>> operation,
            string? errorContext = null,
            bool showBusy = true)
        {
            if (showBusy) IsBusy = true;
            ClearError();

            try
            {
                return await operation();
            }
            catch (OperationCanceledException)
            {
                return default;
            }
            catch (Exception ex)
            {
                HandleException(ex, errorContext);
                return default;
            }
            finally
            {
                if (showBusy) IsBusy = false;
            }
        }

        public virtual void OnNavigatedTo(NavigationContext navigationContext)
        {
        }
        public virtual bool IsNavigationTarget(NavigationContext navigationContext) => true;

        public virtual void OnNavigatedFrom(NavigationContext navigationContext)
        {
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                OnDispose();
                CancelOperations();

                foreach (var token in _subscriptionTokens)
                {
                    token?.Dispose();
                }
                _subscriptionTokens.Clear();
            }

            _disposed = true;
        }
        protected virtual void OnDispose()
        {
        }
    }
}
