using System.Runtime.InteropServices;

namespace WpfApp.Model
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PcapStruct
    {
        public int id;
        public int source_port;
        public int dest_port;
        public string proto;
        public string source_ip;
        public string dest_ip;
        public string source_mac;
        public string dest_mac;
        public string host_name;
    }
}
