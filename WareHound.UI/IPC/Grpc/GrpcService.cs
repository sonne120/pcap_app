using System.Net.Http;
using AutoMapper;
using Grpc.Core;
using Grpc.Net.Client;
using GrpcClient;
using Microsoft.Extensions.Hosting;
using Prism.Events;
using WareHound.UI.Infrastructure.Events;
using WareHound.UI.Infrastructure.Services;
using WareHound.UI.Models;
using WareHound.UI.Services.BackgroundJobs;
using WareHound.UI.Services.BackgroundJobs.AsyncCollection;

namespace WareHound.UI.IPC.Grpc
{
    public class GrpcService : BackgroundService, IHostedGrpcService
    {
        private readonly IMapper _mapper;
        private readonly ILoggerService _logger;
        private readonly AsyncConcurrencyQueue<SnapshotStruct> _snapshotsQueue;
        private readonly IEventAggregator _eventAggregator;
        
        private GrpcChannel? _channel;
        private StreamingDates.StreamingDatesClient? _streamDataClient;
        private AsyncClientStreamingCall<streamingRequest, streamingReply>? _clientStreamingCall;
        
        private volatile bool _isEnabled = false;
        private string _serverAddress = "https://localhost:5001";
        private readonly object _connectionLock = new();

        public GrpcService(
            IBackgroundJobs<SnapshotStruct> backgroundJobs, 
            IMapper mapper,
            IEventAggregator eventAggregator,
            ILoggerService logger)
        {
            _snapshotsQueue = backgroundJobs.BackgroundTaskGrpc;
            _mapper = mapper;
            _eventAggregator = eventAggregator;
            _logger = logger;

            // Subscribe to settings changes
            _eventAggregator.GetEvent<GrpcEnabledChangedEvent>().Subscribe(OnGrpcSettingsChanged);
        }

        private void OnGrpcSettingsChanged(GrpcSettings settings)
        {
            lock (_connectionLock)
            {
                _serverAddress = settings.ServerAddress;

                if (settings.Enabled && !_isEnabled)
                {
                    _isEnabled = true;
                    _ = ConnectAsync();
                }
                else if (!settings.Enabled && _isEnabled)
                {
                    _isEnabled = false;
                    _ = DisconnectAsync();
                }
            }
        }

        private async Task ConnectAsync()
        {
            try
            {
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = 
                        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                };

                _channel = GrpcChannel.ForAddress(_serverAddress, new GrpcChannelOptions
                {
                    HttpHandler = handler
                });

                _streamDataClient = new StreamingDates.StreamingDatesClient(_channel);
                _clientStreamingCall = _streamDataClient.GetStreamingData();
                
                _logger.Log($"[GrpcService] Connected to {_serverAddress}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"[GrpcService] Connection failed: {ex.Message}", ex);
                _isEnabled = false;
            }
        }

        private async Task DisconnectAsync()
        {
            try
            {
                if (_clientStreamingCall != null)
                {
                    await _clientStreamingCall.RequestStream.CompleteAsync();
                    _clientStreamingCall.Dispose();
                    _clientStreamingCall = null;
                }

                if (_channel != null)
                {
                    await _channel.ShutdownAsync();
                    _channel.Dispose();
                    _channel = null;
                }

                _streamDataClient = null;
                _logger.Log("[GrpcService] Disconnected");
            }
            catch (Exception ex)
            {
                _logger.LogError($"[GrpcService] Disconnect error: {ex.Message}", ex);
            }
        }

        public override void Dispose()
        {
            _eventAggregator.GetEvent<GrpcEnabledChangedEvent>().Unsubscribe(OnGrpcSettingsChanged);
            _ = DisconnectAsync();
            base.Dispose();
        }

        public override Task StartAsync(CancellationToken cancellationToken)
        {
            // Don't connect on start - wait for settings toggle
            return base.StartAsync(cancellationToken);
        }

        async Task IHostedGrpcService.StartAsync(CancellationToken cancellationToken)
        {
            await StartAsync(cancellationToken);
        }

        protected override async Task ExecuteAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await foreach (var data in _snapshotsQueue.WithCancellation(cancellationToken))
                    {
                        // Only send if enabled and connected
                        if (_isEnabled && _clientStreamingCall != null)
                        {
                            try
                            {
                                var streamData = _mapper.Map<streamingRequest>(data);
                                await _clientStreamingCall.RequestStream.WriteAsync(streamData, cancellationToken);
                            }
                            catch (RpcException ex)
                            {
                                _logger.LogError($"[GrpcService] Send error: {ex.Status}", ex);
                                // Could attempt reconnection here
                            }
                        }

                        await Task.Delay(50, cancellationToken);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"[GrpcService] Error: {ex.Message}", ex);
                    await Task.Delay(1000, cancellationToken);
                }
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            await DisconnectAsync();
            await base.StopAsync(cancellationToken);
        }

        async Task IHostedGrpcService.StopAsync(CancellationToken cancellationToken)
        {
            await StopAsync(cancellationToken);
        }
    }
}
