#pragma pack(push, 2)
typedef struct Snapshot {
    int id;
    int source_port;
    int dest_port;
    char proto[22];
    char source_ip[22];
    char dest_ip[22];
    char source_mac[22];
    char dest_mac[22];
    char host_name[22];
} Snapshot;
#pragma pack(pop)
