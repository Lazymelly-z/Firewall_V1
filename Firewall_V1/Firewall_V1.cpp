#include <iostream>
#include <vector>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windivert.h>

#pragma	comment(lib, "Ws2_32.lib")
#pragma	comment(lib, "WinDivert.lib")

using namespace std;
//---------------------------------------------//

UINT8 Packet[65535];
UINT PacketLen = 0;
PWINDIVERT_IPHDR IpHeader = NULL;
PWINDIVERT_TCPHDR TcpHeader = NULL;
PWINDIVERT_UDPHDR UdpHeader = NULL;
PVOID Payload = NULL;
UINT PayloadLen = 0;
WINDIVERT_ADDRESS Addr;

enum class Action {
	PASS, BLOCK
};

struct FirewallRules {
	UINT16 DstPort;
	UINT8 Protocol; 
	Action Action;
	string Description;
};

vector<FirewallRules> Rules = {
	{80, 6, Action::BLOCK, "HTTP traffic"},
	{443, 6, Action::BLOCK, "HTTPS traffic"},
	{53, 17, Action::BLOCK, "DNS traffic"},
	{0, 17, Action::BLOCK, "DNS" },
	{0, 53, Action:: BLOCK, "TCP"}, 
	{0, 0, Action::BLOCK, "BLOCKS EVERYTHING"}
};

Action RuleChecker(UINT16 DstPort, UINT8 Protocol) {
	for (const FirewallRules& r : Rules) {
		bool PortMatch = (r.DstPort == 0 || r.DstPort == DstPort);
		bool ProtocolMatch = (r.Protocol == 0 || r.Protocol == Protocol);

		if (PortMatch && ProtocolMatch) {
			cout << "[" << r.Description << "]Port : " << DstPort << endl;
			return r.Action;
		}
	}
	return Action::PASS;
}



void PacketLogger(PWINDIVERT_IPHDR IpHeader, PWINDIVERT_TCPHDR TcpHeader, PWINDIVERT_UDPHDR UdpHeader){

	if (IpHeader == NULL) return;

	if (IpHeader != NULL) {
		char SrcStr[46], DstStr[46];
		UINT32 SrcIp = IpHeader->SrcAddr;
		UINT32 DstIp = IpHeader->DstAddr;
		inet_ntop(AF_INET, &SrcIp, SrcStr, sizeof(SrcStr));
		inet_ntop(AF_INET, &DstIp, DstStr, sizeof(DstStr));
		cout << "From: " << SrcStr << "To: " << DstStr << endl;
	}

	if (TcpHeader != NULL) {
		cout << "TCP Packet:" << ntohs(TcpHeader->SrcPort) << ", DstPort=" << ntohs(TcpHeader->DstPort) << endl;
	}
	else if (UdpHeader != NULL) {
		cout << "UDP Packet: SrcPort=" << ntohs(UdpHeader->SrcPort) << ", DstPort=" << ntohs(UdpHeader->DstPort) << endl;
	}

}

void HandlePacket(HANDLE WdHandle, UINT8* pkt, UINT pkt_len, WINDIVERT_ADDRESS addr) {

	PWINDIVERT_IPHDR IpHeader = NULL;
	PWINDIVERT_TCPHDR TcpHeader = NULL;
	PWINDIVERT_UDPHDR UdpHeader = NULL;
	PVOID Payload = NULL;
	UINT PayloadLen = 0;
	
	WinDivertHelperParsePacket(Packet, PacketLen, &IpHeader, NULL, NULL, NULL, NULL, &TcpHeader, &UdpHeader, &Payload, &PayloadLen, NULL, NULL);


	PacketLogger(IpHeader, TcpHeader, UdpHeader);

	UINT16 DstPort = 0;
	UINT8 Protocol = IpHeader ? IpHeader->Protocol : 0;

	if (TcpHeader) {
		DstPort = ntohs(TcpHeader->DstPort);
	}
	else if (UdpHeader) {
		DstPort = ntohs(UdpHeader->DstPort);
	}

	if (RuleChecker(DstPort, Protocol) == Action :: PASS)
		WinDivertSend(WdHandle, Packet, PacketLen,NULL, &Addr);
}

int main() {
	HANDLE Handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);

	if (Handle == INVALID_HANDLE_VALUE) {
		cerr << "Failed to open WinDivert handle: " << GetLastError() << endl;
		return 1;
	}
	cout << "Firewall is running..." << endl << "Press ctrl + c to exit" << endl;

	while (true) {
		if (!WinDivertRecv(Handle, Packet, sizeof(Packet), &PacketLen, &Addr)) break;

		HandlePacket(Handle, Packet, PacketLen, Addr);
	}
	WinDivertClose(Handle);
	return 0;
}