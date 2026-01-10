using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using wpfapp.IPC.Ptr;

namespace wpfapp.Services.Worker
{
    public class StartService : IHostedService
    {
        readonly private int timeout = 100;
        private static EventWaitHandle _eventWaitHandle;
        private static int _currentDevice = -1;
        private static bool _isRunning = false;
        private static bool _captureThreadStarted = false;
        private static ILogger<StartService> _logger;

        static StartService()
        {
            _eventWaitHandle = new EventWaitHandle(false, EventResetMode.ManualReset, @"Global\sniffer");
        }

        public StartService(ILogger<StartService> logger)
        {
            _logger = logger;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            if (_isRunning)
            {
                _eventWaitHandle.Set();
                //StartCapturePtr.Start();
                await Task.Delay(timeout, cancellationToken);
                return;
            }

            _eventWaitHandle.Set();
            
            if (!_captureThreadStarted)
            {
                if (_currentDevice < 0)
                {
                    await Task.Delay(timeout, cancellationToken);
                    return;
                }
                GetStreamPtr.StartStream(_currentDevice);
                _captureThreadStarted = true;
                
                await Task.Delay(500, cancellationToken);
               
                PutdevPtr.PutDev(_currentDevice);
            }
            else
            {
                //PutdevPtr.PutDev(_currentDevice);
            }
            
            _isRunning = true;
            
            await Task.Delay(timeout, cancellationToken);
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            try
            {
                StopCapturePtr.Stop();
                await Task.Delay(200, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "StartService Error stopping capture");
            }
            finally
            {
                _isRunning = false;
            }
        }

        public static void SetDevice(int device)
        {
            _currentDevice = device;
            
            if (_captureThreadStarted && _isRunning)
            {
                _ = Task.Run(() =>
                {
                    try
                    {
                        PutdevPtr.PutDev(device);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "StartService Error switching device");
                    }
                });
            }
        }

        public async Task SetUpDevice(int device, CancellationToken cancellationToken)
        {
            SetDevice(device);
            await Task.Delay(timeout, cancellationToken);
        }
    }
}
