using AutoMapper;
using GrpcClient;
using WareHound.UI.Models;

namespace WareHound.UI.Infrastructure.Mapping
{
    public class SnapshotMappingProfile : Profile
    {
        public SnapshotMappingProfile()
        {
            // Map from SnapshotStruct to gRPC streamingRequest
            CreateMap<SnapshotStruct, streamingRequest>()
                .ForMember(dest => dest.SourcePort, opt => opt.MapFrom(src => src.SourcePort))
                .ForMember(dest => dest.DestPort, opt => opt.MapFrom(src => src.DestPort))
                .ForMember(dest => dest.SourceIp, opt => opt.MapFrom(src => src.SourceIp ?? string.Empty))
                .ForMember(dest => dest.DestIp, opt => opt.MapFrom(src => src.DestIp ?? string.Empty))
                .ForMember(dest => dest.SourceMac, opt => opt.MapFrom(src => src.SourceMac ?? string.Empty))
                .ForMember(dest => dest.DestMac, opt => opt.MapFrom(src => src.DestMac ?? string.Empty))
                .ForMember(dest => dest.Proto, opt => opt.MapFrom(src => src.Protocol ?? string.Empty));

            // Map from gRPC streamingRequest to SnapshotStruct (reverse mapping)
            CreateMap<streamingRequest, SnapshotStruct>()
                .ForMember(dest => dest.SourcePort, opt => opt.MapFrom(src => src.SourcePort))
                .ForMember(dest => dest.DestPort, opt => opt.MapFrom(src => src.DestPort))
                .ForMember(dest => dest.SourceIp, opt => opt.MapFrom(src => src.SourceIp))
                .ForMember(dest => dest.DestIp, opt => opt.MapFrom(src => src.DestIp))
                .ForMember(dest => dest.SourceMac, opt => opt.MapFrom(src => src.SourceMac))
                .ForMember(dest => dest.DestMac, opt => opt.MapFrom(src => src.DestMac))
                .ForMember(dest => dest.Protocol, opt => opt.MapFrom(src => src.Proto))
                .ForMember(dest => dest.Id, opt => opt.Ignore())
                .ForMember(dest => dest.HostName, opt => opt.Ignore())
                .ForMember(dest => dest.CaptureLen, opt => opt.Ignore())
                .ForMember(dest => dest.OriginalLen, opt => opt.Ignore())
                .ForMember(dest => dest.TimestampSec, opt => opt.Ignore())
                .ForMember(dest => dest.TimestampUsec, opt => opt.Ignore())
                .ForMember(dest => dest.RawData, opt => opt.Ignore());
        }
    }
}
