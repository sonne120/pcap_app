using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace wpfapp.IPC.Ptr
{
    public static class StopPtr
    {
        [DllImport("sniffer_packages.dll", EntryPoint = "fnStop", CallingConvention = CallingConvention.StdCall)]
        private static extern void fnStop();

        public static void Stop()
        {
            System.Diagnostics.Debug.WriteLine("[StopPtr] Stop called, invoking fnStop with timeout...");
            
            // Wrap the blocking P/Invoke in a Task with timeout
            var stopTask = Task.Run(() =>
            {
                try
                {
                    fnStop();
                    System.Diagnostics.Debug.WriteLine("[StopPtr] fnStop completed");
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[StopPtr] fnStop error: {ex.Message}");
                }
            });

            // Wait up to 5 seconds for stop to complete
            if (!stopTask.Wait(TimeSpan.FromSeconds(5)))
            {
                System.Diagnostics.Debug.WriteLine("[StopPtr] WARNING: fnStop timed out after 5 seconds");
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("[StopPtr] fnStop completed successfully");
            }
        }
    }
}
