using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WareHound.UI.IPC.Grpc;
using WareHound.UI.Models;
using WareHound.UI.Services.BackgroundJobs;

namespace WareHound.UI.Infrastructure.Extensions
{
    public static class GrpcServiceExtensions
    {
        public static IServiceCollection AddGrpcStreamingServices(this IServiceCollection services)
        {
            services.AddSingleton<IBackgroundJobs<SnapshotStruct>, BackgroundJobs>();
            services.AddSingleton<IHostedGrpcService, GrpcService>();
            services.AddSingleton<GrpcService>();
            services.AddHostedService(sp => sp.GetRequiredService<GrpcService>());

            return services;
        }
    }
}
