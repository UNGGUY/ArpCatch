#include "arp.h"
#include <memory.h>
#include <WinSock2.h>
#include <conio.h>
#include <packet32.h>
#include <ntddndis.h>


//封装ARP请求包
unsigned char* BuildArpRequestPacket(unsigned char* source_mac,
	unsigned long srcIP,
	unsigned long destIP
)
{
	static struct arp_packet packet;
	//目的MAC地址为广播地址，FF-FF-FF-FF-FF-FF
	memset(packet.eth.dest_mac, 0xFF, 6);
	//源MAC地址
	memcpy(packet.eth.source_mac, source_mac, 6);
	//上层协议为ARP协议，0x0806
	packet.eth.eh_type = htons(0x0806);
	//硬件类型，Ethernet是0x0001
	packet.arp.hardware_type = htons(0x0001);
	//上层协议类型，IP为0x0800
	packet.arp.protocol_type = htons(0x0800);
	//硬件地址长度：MAC地址长度为0x06
	packet.arp.add_len = 6;
	//协议地址长度：IP地址长度为0x04
	packet.arp.pro_len = 4;
	//操作：ARP请求为1
	packet.arp.option = htons(0x0001);
	//源MAC地址
	memcpy(packet.arp.sour_addr, source_mac, 6);
	//源IP地址
	packet.arp.sour_ip = srcIP;
	//目的MAC地址
	memset(packet.arp.dest_addr, 0, 6);
	//目的IP地址
	packet.arp.dest_ip = destIP;
	//填充数据，18B
	memset(packet.arp.padding, 0, 18);
	return (unsigned char*)&packet;
}

unsigned char* GetSelfMac(char* pDevName) {

	static u_char mac[6];

	memset(mac, 0, sizeof(mac));

	LPADAPTER lpAdapter = PacketOpenAdapter(pDevName);

	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		return NULL;
	}

	PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL)
	{
		PacketCloseAdapter(lpAdapter);
		return NULL;
	}
	// 
	// Retrieve the adapter MAC querying the NIC driver
	//
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;

	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);

	BOOLEAN	Status = PacketRequest(lpAdapter, FALSE, OidData);
	if (Status)
	{
		memcpy(mac, (u_char*)(OidData->Data), 6);
	}
	free(OidData);
	PacketCloseAdapter(lpAdapter);

	return mac;

}

