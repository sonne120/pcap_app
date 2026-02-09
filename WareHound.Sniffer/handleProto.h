#pragma once
#ifndef HANDLE_PROTO_H
#define HANDLE_PROTO_H
#include <iostream>
#include <map>
#include <functional>
#include <cstring>

#pragma warning(disable:4996) 

class handleProto
{
public:
	~handleProto();
	handleProto();
	handleProto(handleProto* proto);

public:
	void* initialize();
	void handlePROTO_IP();
	void handlePROTO_TCP();
	void handlePROTO_UDP();
	void handlePROTO_PUP();
	void handlePROTO_ICMP();
	void handlePROTO_IGMP();
	void handlePROTO_GGP();
	void handlePROTO_IDP();
	void handlePROTO_ST();
	void handlePROTO_RDP();
	void handlePROTO_ND();
	void handlePROTO_L2TP();
	void handlePROTO_PIM();
	void handlePROTO_PGM();
	void handlePROTO_SCTP();
	void handlePROTO_CBT();
	void handlePROTO_EGP();
	void handlePROTO_IGP();
	void handlePROTO_IPV4();
	void handlePROTO_IPV6();
	void handlePROTO_ROUTING();
	void handlePROTO_FRAGMENT();
	void handlePROTO_ESP();
	void handlePROTO_AH();
	void handlePROTO_ICMPV6();
	void handlePROTO_NONE();
	void handlePROTO_DSTOPTS();
	void handlePROTO_RAW();
	void handlePROTO_MAX();
	void handlePROTO_RESERVED_IPSEC();
	void handlePROTO_SSCOPMCE();
	void handlePROTO_GRE();
	void handlePROTO_OSPF();
	void handlePROTO_VRRP();
	void handlePROTO_STP();
	void handlePROTO_SMP();
	void handlePROTO_UDPLITE();
	void handlePROTO_MPLS();
	void handlePROTO_HOPOPT();
	// Additional protocols
	void handlePROTO_ENCAP();
	void handlePROTO_IPIP();
	void handlePROTO_TP();
	void handlePROTO_DCCP();
	void handlePROTO_RSVP();
	void handlePROTO_MOBILE();
	void handlePROTO_HIP();
	void handlePROTO_SHIM6();
	void handlePROTO_WESP();
	void handlePROTO_ROHC();
	void handlePROTO_ETHERNET();
	void handlePROTO_EIGRP();
	void handlePROTO_ISIS();
	void handlePROTO_MH();
	void handlePROTO_MANET();
	void handlePROTO_FC();
	void handlePROTO_IPCOMP();
	void handlePROTO_SNP();
	void handlePROTO_COMPAQ();
	void handlePROTO_IPX();
	void handlePROTO_SKIP();
	void handlePROTO_TLSP();
	void handlePROTO_IL();
	void handlePROTO_MUX();
	void handlePROTO_CHAOS();
	void handlePROTO_EMCON();
	void handlePROTO_IRTP();
	void handlePROTO_ISO_TP4();
	void handlePROTO_NETBLT();
	void handlePROTO_MFE_NSP();
	void handlePROTO_MERIT_INP();
	void handlePROTO_3PC();
	void handlePROTO_IDPR();
	void handlePROTO_XTP();
	void handlePROTO_DDP();
	void handlePROTO_IDPR_CMTP();
	void handlePROTO_IDRP();
	void handlePROTO_SDRP();
	void handlePROTO_HMP();
	void handlePROTO_PRM();
	void handlePROTO_TRUNK1();
	void handlePROTO_TRUNK2();
	void handlePROTO_LEAF1();
	void handlePROTO_UNASSIGNED();
	void handlePROTO_EXPERIMENTAL();
	void* handleDefault();

public:
	std::map<int, std::function<void()>> caseMap;
	int* _src_port;
	int* _dst_port;
	char* protoStr;
private:
	handleProto* p;
};

inline handleProto::~handleProto()
{
	// Don't delete - these are external pointers we don't own
	_src_port = nullptr;
	_dst_port = nullptr;
	protoStr = nullptr;
	p = nullptr;
}

inline handleProto::handleProto() : protoStr(nullptr), _src_port(nullptr), _dst_port(nullptr), p(nullptr) {
}

inline handleProto::handleProto(handleProto* proto) {
	// Copy the pointers from the source object
	if (proto) {
		protoStr = proto->protoStr;
		_src_port = proto->_src_port;
		_dst_port = proto->_dst_port;
	} else {
		protoStr = nullptr;
		_src_port = nullptr;
		_dst_port = nullptr;
	}
	p = this;
	initialize();
}

 inline void* handleProto::initialize()
{
	// IANA IP Protocol Numbers - https://www.iana.org/assignments/protocol-numbers
	caseMap[0] = std::bind(&handleProto::handlePROTO_HOPOPT, p);      // HOPOPT - IPv6 Hop-by-Hop Option
	caseMap[1] = std::bind(&handleProto::handlePROTO_ICMP, p);        // ICMP
	caseMap[2] = std::bind(&handleProto::handlePROTO_IGMP, p);        // IGMP
	caseMap[3] = std::bind(&handleProto::handlePROTO_GGP, p);         // GGP
	caseMap[4] = std::bind(&handleProto::handlePROTO_IPV4, p);        // IPv4 encapsulation
	caseMap[5] = std::bind(&handleProto::handlePROTO_ST, p);          // ST - Stream
	caseMap[6] = std::bind(&handleProto::handlePROTO_TCP, p);         // TCP
	caseMap[7] = std::bind(&handleProto::handlePROTO_CBT, p);         // CBT
	caseMap[8] = std::bind(&handleProto::handlePROTO_EGP, p);         // EGP
	caseMap[9] = std::bind(&handleProto::handlePROTO_IGP, p);         // IGP (any private interior gateway)
	caseMap[12] = std::bind(&handleProto::handlePROTO_PUP, p);        // PUP
	caseMap[14] = std::bind(&handleProto::handlePROTO_EMCON, p);      // EMCON
	caseMap[16] = std::bind(&handleProto::handlePROTO_CHAOS, p);      // Chaos
	caseMap[17] = std::bind(&handleProto::handlePROTO_UDP, p);        // UDP
	caseMap[18] = std::bind(&handleProto::handlePROTO_MUX, p);        // MUX - Multiplexing
	caseMap[20] = std::bind(&handleProto::handlePROTO_HMP, p);        // HMP - Host Monitoring Protocol
	caseMap[21] = std::bind(&handleProto::handlePROTO_PRM, p);        // PRM - Packet Radio Measurement
	caseMap[22] = std::bind(&handleProto::handlePROTO_IDP, p);        // XNS-IDP
	caseMap[24] = std::bind(&handleProto::handlePROTO_TRUNK1, p);     // TRUNK-1
	caseMap[25] = std::bind(&handleProto::handlePROTO_TRUNK2, p);     // TRUNK-2
	caseMap[26] = std::bind(&handleProto::handlePROTO_LEAF1, p);      // LEAF-1
	caseMap[27] = std::bind(&handleProto::handlePROTO_RDP, p);        // RDP - Reliable Data Protocol
	caseMap[28] = std::bind(&handleProto::handlePROTO_IRTP, p);       // IRTP - Internet Reliable Transaction
	caseMap[29] = std::bind(&handleProto::handlePROTO_ISO_TP4, p);    // ISO-TP4
	caseMap[30] = std::bind(&handleProto::handlePROTO_NETBLT, p);     // NETBLT - Bulk Data Transfer
	caseMap[31] = std::bind(&handleProto::handlePROTO_MFE_NSP, p);    // MFE-NSP
	caseMap[32] = std::bind(&handleProto::handlePROTO_MERIT_INP, p); // MERIT-INP
	caseMap[33] = std::bind(&handleProto::handlePROTO_DCCP, p);       // DCCP - Datagram Congestion Control
	caseMap[34] = std::bind(&handleProto::handlePROTO_3PC, p);        // 3PC - Third Party Connect
	caseMap[35] = std::bind(&handleProto::handlePROTO_IDPR, p);       // IDPR
	caseMap[36] = std::bind(&handleProto::handlePROTO_XTP, p);        // XTP
	caseMap[37] = std::bind(&handleProto::handlePROTO_DDP, p);        // DDP - Datagram Delivery Protocol
	caseMap[38] = std::bind(&handleProto::handlePROTO_IDPR_CMTP, p);  // IDPR-CMTP
	caseMap[39] = std::bind(&handleProto::handlePROTO_TP, p);         // TP++ Transport Protocol
	caseMap[40] = std::bind(&handleProto::handlePROTO_IL, p);         // IL Transport Protocol
	caseMap[41] = std::bind(&handleProto::handlePROTO_IPV6, p);       // IPv6 encapsulation
	caseMap[42] = std::bind(&handleProto::handlePROTO_SDRP, p);       // SDRP - Source Demand Routing
	caseMap[45] = std::bind(&handleProto::handlePROTO_IDRP, p);       // IDRP
	caseMap[43] = std::bind(&handleProto::handlePROTO_ROUTING, p);    // Routing Header for IPv6
	caseMap[44] = std::bind(&handleProto::handlePROTO_FRAGMENT, p);   // Fragment Header for IPv6
	caseMap[46] = std::bind(&handleProto::handlePROTO_RSVP, p);       // RSVP
	caseMap[47] = std::bind(&handleProto::handlePROTO_GRE, p);        // GRE
	caseMap[50] = std::bind(&handleProto::handlePROTO_ESP, p);        // ESP - Encapsulating Security Payload
	caseMap[51] = std::bind(&handleProto::handlePROTO_AH, p);         // AH - Authentication Header
	caseMap[55] = std::bind(&handleProto::handlePROTO_MOBILE, p);     // Mobile Host Routing
	caseMap[56] = std::bind(&handleProto::handlePROTO_TLSP, p);       // TLSP
	caseMap[57] = std::bind(&handleProto::handlePROTO_SKIP, p);       // SKIP
	caseMap[58] = std::bind(&handleProto::handlePROTO_ICMPV6, p);     // ICMPv6
	caseMap[59] = std::bind(&handleProto::handlePROTO_NONE, p);       // No Next Header for IPv6
	caseMap[60] = std::bind(&handleProto::handlePROTO_DSTOPTS, p);    // Destination Options for IPv6
	caseMap[77] = std::bind(&handleProto::handlePROTO_ND, p);         // ND - Sun Network Disk
	caseMap[88] = std::bind(&handleProto::handlePROTO_EIGRP, p);      // EIGRP
	caseMap[89] = std::bind(&handleProto::handlePROTO_OSPF, p);       // OSPF
	caseMap[94] = std::bind(&handleProto::handlePROTO_IPIP, p);       // IPIP - IP-within-IP
	caseMap[97] = std::bind(&handleProto::handlePROTO_ENCAP, p);      // Encapsulation Header
	caseMap[98] = std::bind(&handleProto::handlePROTO_ENCAP, p);      // Any private encryption scheme
	caseMap[103] = std::bind(&handleProto::handlePROTO_PIM, p);       // PIM
	caseMap[108] = std::bind(&handleProto::handlePROTO_IPCOMP, p);    // IP Payload Compression
	caseMap[112] = std::bind(&handleProto::handlePROTO_VRRP, p);      // VRRP
	caseMap[113] = std::bind(&handleProto::handlePROTO_PGM, p);       // PGM - Reliable Multicast
	caseMap[115] = std::bind(&handleProto::handlePROTO_L2TP, p);      // L2TP
	caseMap[118] = std::bind(&handleProto::handlePROTO_STP, p);       // STP - Schedule Transfer Protocol
	caseMap[121] = std::bind(&handleProto::handlePROTO_SMP, p);       // SMP
	caseMap[124] = std::bind(&handleProto::handlePROTO_ISIS, p);      // IS-IS over IPv4
	caseMap[128] = std::bind(&handleProto::handlePROTO_SSCOPMCE, p);  // SSCOPMCE
	caseMap[132] = std::bind(&handleProto::handlePROTO_SCTP, p);      // SCTP
	caseMap[133] = std::bind(&handleProto::handlePROTO_FC, p);        // FC - Fibre Channel
	caseMap[135] = std::bind(&handleProto::handlePROTO_MH, p);        // MH - Mobility Header
	caseMap[136] = std::bind(&handleProto::handlePROTO_UDPLITE, p);   // UDPLite
	caseMap[137] = std::bind(&handleProto::handlePROTO_MPLS, p);      // MPLS-in-IP
	caseMap[138] = std::bind(&handleProto::handlePROTO_MANET, p);     // MANET Protocols
	caseMap[139] = std::bind(&handleProto::handlePROTO_HIP, p);       // HIP - Host Identity Protocol
	caseMap[140] = std::bind(&handleProto::handlePROTO_SHIM6, p);     // Shim6 Protocol
	caseMap[141] = std::bind(&handleProto::handlePROTO_WESP, p);      // WESP - Wrapped ESP
	caseMap[142] = std::bind(&handleProto::handlePROTO_ROHC, p);      // ROHC - Robust Header Compression
	caseMap[143] = std::bind(&handleProto::handlePROTO_ETHERNET, p);  // Ethernet encapsulation
	// Unassigned protocols (143-252) - mark as suspicious/unknown
	caseMap[233] = std::bind(&handleProto::handlePROTO_UNASSIGNED, p); // Unassigned - potentially suspicious
	// Experimental/Testing (253-254)
	caseMap[253] = std::bind(&handleProto::handlePROTO_EXPERIMENTAL, p); // Experimentation
	caseMap[254] = std::bind(&handleProto::handlePROTO_EXPERIMENTAL, p); // Experimentation
	return 0;
}

 inline void handleProto::handlePROTO_IP()
{
	strcpy(protoStr, "IP");
}

inline void handleProto::handlePROTO_TCP()
{
	int sp = *_src_port;
	int dp = *_dst_port;
	// TLS/SSL
	if (sp == 443 || dp == 443)
		strcpy(protoStr, "TLS");
	// HTTP
	else if (sp == 80 || dp == 80 || sp == 8080 || dp == 8080)
		strcpy(protoStr, "HTTP");
	// DNS over TCP
	else if (sp == 53 || dp == 53)
		strcpy(protoStr, "DNS");
	// FTP
	else if (sp == 21 || dp == 21)
		strcpy(protoStr, "FTP");
	else if (sp == 20 || dp == 20)
		strcpy(protoStr, "FTP-DATA");
	// SSH
	else if (sp == 22 || dp == 22)
		strcpy(protoStr, "SSH");
	// Telnet
	else if (sp == 23 || dp == 23)
		strcpy(protoStr, "TELNET");
	// SMTP
	else if (sp == 25 || dp == 25 || sp == 587 || dp == 587 || sp == 465 || dp == 465)
		strcpy(protoStr, "SMTP");
	// POP3
	else if (sp == 110 || dp == 110 || sp == 995 || dp == 995)
		strcpy(protoStr, "POP3");
	// IMAP
	else if (sp == 143 || dp == 143 || sp == 993 || dp == 993)
		strcpy(protoStr, "IMAP");
	// LDAP
	else if (sp == 389 || dp == 389 || sp == 636 || dp == 636)
		strcpy(protoStr, "LDAP");
	// MySQL
	else if (sp == 3306 || dp == 3306)
		strcpy(protoStr, "MySQL");
	// PostgreSQL
	else if (sp == 5432 || dp == 5432)
		strcpy(protoStr, "PostgreSQL");
	// MongoDB
	else if (sp == 27017 || dp == 27017)
		strcpy(protoStr, "MongoDB");
	// Redis
	else if (sp == 6379 || dp == 6379)
		strcpy(protoStr, "Redis");
	// RDP (Remote Desktop)
	else if (sp == 3389 || dp == 3389)
		strcpy(protoStr, "RDP");
	// SMB/CIFS
	else if (sp == 445 || dp == 445 || sp == 139 || dp == 139)
		strcpy(protoStr, "SMB");
	// Kerberos
	else if (sp == 88 || dp == 88)
		strcpy(protoStr, "Kerberos");
	// HTTPS alternate
	else if (sp == 8443 || dp == 8443)
		strcpy(protoStr, "HTTPS");
	// BGP
	else if (sp == 179 || dp == 179)
		strcpy(protoStr, "BGP");
	// MQTT
	else if (sp == 1883 || dp == 1883 || sp == 8883 || dp == 8883)
		strcpy(protoStr, "MQTT");
	// Docker
	else if (sp == 2375 || dp == 2375 || sp == 2376 || dp == 2376)
		strcpy(protoStr, "Docker");
	// Kubernetes API
	else if (sp == 6443 || dp == 6443)
		strcpy(protoStr, "K8s-API");
	// Git
	else if (sp == 9418 || dp == 9418)
		strcpy(protoStr, "Git");
	// XMPP
	else if (sp == 5222 || dp == 5222 || sp == 5223 || dp == 5223)
		strcpy(protoStr, "XMPP");
	// IRC
	else if (sp == 6667 || dp == 6667 || sp == 6697 || dp == 6697)
		strcpy(protoStr, "IRC");
	else
		strcpy(protoStr, "TCP");
}

inline void handleProto::handlePROTO_UDP()
{
	int sp = *_src_port;
	int dp = *_dst_port;
	// DNS
	if (sp == 53 || dp == 53)
		strcpy(protoStr, "DNS");
	// DHCP
	else if (sp == 67 || dp == 67 || sp == 68 || dp == 68)
		strcpy(protoStr, "DHCP");
	// NTP
	else if (sp == 123 || dp == 123)
		strcpy(protoStr, "NTP");
	// SNMP
	else if (sp == 161 || dp == 161 || sp == 162 || dp == 162)
		strcpy(protoStr, "SNMP");
	// TFTP
	else if (sp == 69 || dp == 69)
		strcpy(protoStr, "TFTP");
	// Syslog
	else if (sp == 514 || dp == 514)
		strcpy(protoStr, "SYSLOG");
	// NetBIOS
	else if (sp == 137 || dp == 137 || sp == 138 || dp == 138)
		strcpy(protoStr, "NetBIOS");
	// QUIC (HTTP/3)
	else if (sp == 443 || dp == 443 || sp == 8443 || dp == 8443)
		strcpy(protoStr, "QUIC");
	// RIP
	else if (sp == 520 || dp == 520)
		strcpy(protoStr, "RIP");
	// RADIUS
	else if (sp == 1812 || dp == 1812 || sp == 1813 || dp == 1813)
		strcpy(protoStr, "RADIUS");
	// mDNS (Multicast DNS)
	else if (sp == 5353 || dp == 5353)
		strcpy(protoStr, "mDNS");
	// LLMNR
	else if (sp == 5355 || dp == 5355)
		strcpy(protoStr, "LLMNR");
	// SIP
	else if (sp == 5060 || dp == 5060 || sp == 5061 || dp == 5061)
		strcpy(protoStr, "SIP");
	// RTP (common range)
	else if ((sp >= 16384 && sp <= 32767) || (dp >= 16384 && dp <= 32767))
		strcpy(protoStr, "RTP");
	// STUN
	else if (sp == 3478 || dp == 3478)
		strcpy(protoStr, "STUN");
	// WireGuard
	else if (sp == 51820 || dp == 51820)
		strcpy(protoStr, "WireGuard");
	// OpenVPN
	else if (sp == 1194 || dp == 1194)
		strcpy(protoStr, "OpenVPN");
	// IPsec NAT-T
	else if (sp == 4500 || dp == 4500)
		strcpy(protoStr, "IPsec-NAT");
	// L2TP
	else if (sp == 1701 || dp == 1701)
		strcpy(protoStr, "L2TP");
	// VXLAN
	else if (sp == 4789 || dp == 4789)
		strcpy(protoStr, "VXLAN");
	// CoAP
	else if (sp == 5683 || dp == 5683 || sp == 5684 || dp == 5684)
		strcpy(protoStr, "CoAP");
	else
		strcpy(protoStr, "UDP");
}

inline void handleProto::handlePROTO_PUP()
{
	strcpy(protoStr, "PUP");
}

inline void handleProto::handlePROTO_ICMP()
{
	strcpy(protoStr, "ICMP");
}

inline void handleProto::handlePROTO_IGMP()
{
	strcpy(protoStr, "IGMP");
}

inline void handleProto::handlePROTO_GGP()
{
	strcpy(protoStr, "GGP");
}

inline void handleProto::handlePROTO_IDP()
{
	strcpy(protoStr, "IDP");
}

inline void handleProto::handlePROTO_ST()
{
	strcpy(protoStr, "ST");
}

inline void handleProto::handlePROTO_RDP()
{
	strcpy(protoStr, "RDP");
}

inline void handleProto::handlePROTO_ND()
{
	strcpy(protoStr, "ND");
}

inline void handleProto::handlePROTO_L2TP()
{
	strcpy(protoStr, "L2TP");
}

inline void handleProto::handlePROTO_PIM()
{
	strcpy(protoStr, "PIM");
}

inline void handleProto::handlePROTO_PGM()
{
	strcpy(protoStr, "PGM");
}

inline void handleProto::handlePROTO_SCTP()
{
	strcpy(protoStr, "SCTP");
}

inline void handleProto::handlePROTO_CBT()
{
	strcpy(protoStr, "CBT");
}

inline void handleProto::handlePROTO_EGP()
{
	strcpy(protoStr, "EGP");
}

inline void handleProto::handlePROTO_IGP()
{
	strcpy(protoStr, "IGP");
}

inline void handleProto::handlePROTO_IPV4()
{
	strcpy(protoStr, "IPV4");
}

inline void handleProto::handlePROTO_IPV6()
{
	strcpy(protoStr, "IPV6");
}

inline void handleProto::handlePROTO_ROUTING()
{
	strcpy(protoStr, "ROUTING");
}

inline void handleProto::handlePROTO_FRAGMENT()
{
	strcpy(protoStr, "FRAGMENT");
}

inline void handleProto::handlePROTO_ESP()
{
	strcpy(protoStr, "ESP");
}

inline void handleProto::handlePROTO_AH()
{
	strcpy(protoStr, "AH");
}

inline void handleProto::handlePROTO_RESERVED_IPSEC()
{
	strcpy(protoStr, "RESERVED_IPSEC");
}

inline void handleProto::handlePROTO_ICMPV6()
{
	strcpy(protoStr, "ICMPV6");
}

inline void handleProto::handlePROTO_NONE()
{
	strcpy(protoStr, "NONE");
}

inline void handleProto::handlePROTO_DSTOPTS()
{
	strcpy(protoStr, "PROTO_DSTOPTS");
}

inline void handleProto::handlePROTO_RAW()
{
	strcpy(protoStr, "PROTO_RAW");
}

inline void handleProto::handlePROTO_MAX()
{
	strcpy(protoStr, "PROTO_MAX");
}

inline void handleProto::handlePROTO_SSCOPMCE()
{
	strcpy(protoStr, "SSCOPMCE");
}

inline void handleProto::handlePROTO_GRE()
{
	strcpy(protoStr, "GRE");
}

inline void handleProto::handlePROTO_OSPF()
{
	strcpy(protoStr, "OSPF");
}

inline void handleProto::handlePROTO_VRRP()
{
	strcpy(protoStr, "VRRP");
}

inline void handleProto::handlePROTO_STP()
{
	strcpy(protoStr, "STP");
}

inline void handleProto::handlePROTO_SMP()
{
	strcpy(protoStr, "SMP");
}

inline void handleProto::handlePROTO_UDPLITE()
{
	strcpy(protoStr, "UDPLite");
}

inline void handleProto::handlePROTO_MPLS()
{
	strcpy(protoStr, "MPLS");
}

inline void handleProto::handlePROTO_HOPOPT()
{
	strcpy(protoStr, "HOPOPT");
}

inline void handleProto::handlePROTO_ENCAP()
{
	strcpy(protoStr, "ENCAP");
}

inline void handleProto::handlePROTO_IPIP()
{
	strcpy(protoStr, "IPIP");
}

inline void handleProto::handlePROTO_TP()
{
	strcpy(protoStr, "TP++");
}

inline void handleProto::handlePROTO_DCCP()
{
	strcpy(protoStr, "DCCP");
}

inline void handleProto::handlePROTO_RSVP()
{
	strcpy(protoStr, "RSVP");
}

inline void handleProto::handlePROTO_MOBILE()
{
	strcpy(protoStr, "MOBILE");
}

inline void handleProto::handlePROTO_HIP()
{
	strcpy(protoStr, "HIP");
}

inline void handleProto::handlePROTO_SHIM6()
{
	strcpy(protoStr, "SHIM6");
}

inline void handleProto::handlePROTO_WESP()
{
	strcpy(protoStr, "WESP");
}

inline void handleProto::handlePROTO_ROHC()
{
	strcpy(protoStr, "ROHC");
}

inline void handleProto::handlePROTO_ETHERNET()
{
	strcpy(protoStr, "ETHERNET");
}

inline void handleProto::handlePROTO_EIGRP()
{
	strcpy(protoStr, "EIGRP");
}

inline void handleProto::handlePROTO_ISIS()
{
	strcpy(protoStr, "IS-IS");
}

inline void handleProto::handlePROTO_MH()
{
	strcpy(protoStr, "MH");
}

inline void handleProto::handlePROTO_MANET()
{
	strcpy(protoStr, "MANET");
}

inline void handleProto::handlePROTO_FC()
{
	strcpy(protoStr, "FC");
}

inline void handleProto::handlePROTO_IPCOMP()
{
	strcpy(protoStr, "IPCOMP");
}

inline void handleProto::handlePROTO_SNP()
{
	strcpy(protoStr, "SNP");
}

inline void handleProto::handlePROTO_COMPAQ()
{
	strcpy(protoStr, "COMPAQ");
}

inline void handleProto::handlePROTO_IPX()
{
	strcpy(protoStr, "IPX");
}

inline void handleProto::handlePROTO_SKIP()
{
	strcpy(protoStr, "SKIP");
}

inline void handleProto::handlePROTO_TLSP()
{
	strcpy(protoStr, "TLSP");
}

inline void handleProto::handlePROTO_IL()
{
	strcpy(protoStr, "IL");
}

inline void handleProto::handlePROTO_MUX()
{
	strcpy(protoStr, "MUX");
}

inline void handleProto::handlePROTO_CHAOS()
{
	strcpy(protoStr, "CHAOS");
}

inline void handleProto::handlePROTO_EMCON()
{
	strcpy(protoStr, "EMCON");
}

inline void handleProto::handlePROTO_IRTP()
{
	strcpy(protoStr, "IRTP");
}

inline void handleProto::handlePROTO_ISO_TP4()
{
	strcpy(protoStr, "ISO-TP4");
}

inline void handleProto::handlePROTO_NETBLT()
{
	strcpy(protoStr, "NETBLT");
}

inline void handleProto::handlePROTO_MFE_NSP()
{
	strcpy(protoStr, "MFE-NSP");
}

inline void handleProto::handlePROTO_MERIT_INP()
{
	strcpy(protoStr, "MERIT-INP");
}

inline void handleProto::handlePROTO_3PC()
{
	strcpy(protoStr, "3PC");
}

inline void handleProto::handlePROTO_IDPR()
{
	strcpy(protoStr, "IDPR");
}

inline void handleProto::handlePROTO_XTP()
{
	strcpy(protoStr, "XTP");
}

inline void handleProto::handlePROTO_DDP()
{
	strcpy(protoStr, "DDP");
}

inline void handleProto::handlePROTO_IDPR_CMTP()
{
	strcpy(protoStr, "IDPR-CMTP");
}

inline void handleProto::handlePROTO_IDRP()
{
	strcpy(protoStr, "IDRP");
}

inline void handleProto::handlePROTO_SDRP()
{
	strcpy(protoStr, "SDRP");
}

inline void handleProto::handlePROTO_HMP()
{
	strcpy(protoStr, "HMP");
}

inline void handleProto::handlePROTO_PRM()
{
	strcpy(protoStr, "PRM");
}

inline void handleProto::handlePROTO_TRUNK1()
{
	strcpy(protoStr, "TRUNK-1");
}

inline void handleProto::handlePROTO_TRUNK2()
{
	strcpy(protoStr, "TRUNK-2");
}

inline void handleProto::handlePROTO_LEAF1()
{
	strcpy(protoStr, "LEAF-1");
}

inline void handleProto::handlePROTO_UNASSIGNED()
{
	strcpy(protoStr, "UNASSIGN-233");
}

inline void handleProto::handlePROTO_EXPERIMENTAL()
{
	strcpy(protoStr, "EXP-RFC3692");
}

inline void* handleProto::handleDefault()
{
	return 0;
}
#endif
