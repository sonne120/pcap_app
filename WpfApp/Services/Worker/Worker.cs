using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.IO;
using System.IO.Pipes;
using wpfapp.models;
using wpfapp.Services.BackgroundJob;

namespace wpfapp.Services.Worker
{
    public class Worker : BackgroundService
    {
        private readonly int timeout = 10000;
        private readonly ILogger<Worker> _logger;
        private readonly IBackgroundJobs<Snapshot> _backgroundJobs;
        private readonly IServiceScopeFactory _scopeFactory;

        public Worker(ILogger<Worker> logger,
                      IStreamData streamData,
                      IBackgroundJobs<Snapshot> backgroundJobs,
                      IServiceScopeFactory scopeFactory)
        {
            _logger = logger;
            _backgroundJobs = backgroundJobs;
            _scopeFactory = scopeFactory;
            //streamData.GetStream(3);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            Func<BinaryReader, Task<Snapshot>> result; Snapshot res;
            int totalPacketsReceived = 0;

            _logger.LogInformation("Worker ExecuteAsync started");

            while (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("Worker running at: {time}", DateTimeOffset.Now);

                try
                {
                    _logger.LogInformation("Worker Creating named pipe client...");
                    await using var pipe = new NamedPipeClientStream(".", "testpipe", PipeDirection.InOut);
                    using (BinaryReader stream = new BinaryReader(pipe))
                    {
                        if (!pipe.IsConnected)
                        {
                          
                            using var cts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                            cts.CancelAfter(TimeSpan.FromSeconds(5));
                            
                            try
                            {
                                await pipe.ConnectAsync(cts.Token).ConfigureAwait(false);
                                pipe.ReadMode = PipeTransmissionMode.Byte;
                            }
                            catch (OperationCanceledException)
                            {
                                _logger.LogInformation("Pipe connection cancelled or timed out");
                                //break; 
                            }
                        }

                        Func<BinaryReader, Task<Snapshot>> func = (value) => Task.Run(() => ReadClass.ReadMessage(value));

                        var pool = new ObjectPool<BinaryReader, Task<Snapshot>>(() =>
                        {
                            return func;
                        });

                        pool.Return(func);// first Task in poll
                        pool.Return(func);// second Task in poll 
                        pool.Return(func); //third Task in poll for any case ... improving scalability
                        
                        _logger.LogInformation("Worker Starting to read from pipe...");
                        
                        while (pipe.IsConnected && !stoppingToken.IsCancellationRequested)
                        {
                            result = pool.Get();
                            try
                            {
                                res = await result(stream);
                                totalPacketsReceived++;
                                
                                if (totalPacketsReceived == 1)
                                {
                                    _logger.LogInformation($"Worker  ID: {res.id}, Source: {res.source_ip} ? Dest: {res.dest_ip}");
                                }
                                
                                _backgroundJobs.BackgroundTasks.Enqueue(res);
                                _backgroundJobs.BackgroundTaskGrpc.Enqueue(res);
                                
                                if (totalPacketsReceived % 100 == 0)
                                {
                                    _logger.LogInformation($"Worker Received {totalPacketsReceived} packets from pipe");
                                }
                            }
                            catch (IOException ex)
                            {
                                _logger.LogWarning("Pipe read error: {error}", ex.Message);
                                break; // Exit inner loop on pipe error
                            }
                            finally
                            {
                                pool.Return(result);
                            }
                        }
                        
                        _logger.LogInformation($"[Worker] Exited pipe read loop. Total packets: {totalPacketsReceived}");
                    }
                    
                    if (stoppingToken.IsCancellationRequested)
                    {
                        _logger.LogInformation("Worker stopping - cancellation requested");
                        break; // Exit main loop
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError("Worker error: {error}", ex.Message);
                }
                
                if (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(timeout, stoppingToken);
                }
            }
            
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {        
            try
            {
                using (var scope = _scopeFactory.CreateScope())
                {
                    var service_j = scope.ServiceProvider.GetRequiredService<IBackgroundJobs<Snapshot>>();
                    service_j.CleanBackgroundTask();
                }
                _logger.LogInformation("Worker cleanup completed");
            }
            catch (Exception ex)
            {
                _logger.LogError("Worker cleanup error: {error}", ex.Message);
            }
            
            await base.StopAsync(cancellationToken);
            _logger.LogInformation("Worker stopped");
        }
    }
}
