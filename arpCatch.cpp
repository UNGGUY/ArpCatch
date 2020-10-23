#include <iostream>
#include <WinSock2.h>
#include <stdio.h>
#include <time.h>
#include <stdio.h>
#include "pcap.h"
#include "arp.h"
#include <map>
#include <string>
#include <map>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")

using namespace std;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

FILE* fp;
map<string, string> ArpTable; //IP->Mac
DWORD WINAPI CaptureThreadProc(LPVOID lpParameter);

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	cout << "Name: " << d->name << endl;
	cout << "Desc: " << d->description << endl;
	char devName[100];
	strcpy(devName, &d->name[8]);
	cout << "DevName: " << devName << endl;
	unsigned char* mac = GetSelfMac(devName);
	cout << "Mac: ";
	for (int i = 0; i < 6; i++) {
		if (i > 0) printf("-");
		printf("%02X", mac[i]);
	}
	printf("\n");
	unsigned long netmask = 0;
	unsigned long myip = 0;
	pcap_addr_t* a;
	for (a = d->addresses; a; a = a->next) {
		if (AF_INET == a->addr->sa_family) {
			myip = ((sockaddr_in*)(a->addr))->sin_addr.S_un.S_addr;
			netmask = ((struct sockaddr_in*)(a->netmask))->sin_addr.S_un.S_addr;
			break; //只取第一个IPV4地址
		}
	}
	if (0 == myip) {
		pcap_freealldevs(alldevs);
		cout << "没有找到有效的IP地址\n";
		return -1;
	}
	cout << "IP: " << inet_ntoa(*(in_addr*)&myip) << endl;
	cout << "Netmask: " << inet_ntoa(*(in_addr*)&netmask) << endl;

	

	//compile the filter
	struct bpf_program fcode;
	if (pcap_compile(adhandle, &fcode, "arp", 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	DWORD ThreadID;
	//CreateThread(0, 0, CaptureThreadProc, adhandle, 0, &ThreadID);


	


	unsigned netsize = ntohl(~netmask);
	//子网地址，网络字节顺序
	unsigned long net = myip & netmask;

	unsigned char* arpPacket;
	for (int i = 1; i < netsize; i++) {
		//网络中第i台主机的子网内地址，网络字节顺序
		unsigned long n = htonl(i);
		//第i台主机的IP地址，网络字节顺序
		unsigned long ip = net | n;
		cout << inet_ntoa(*(in_addr*)&ip) << endl;

		arpPacket = BuildArpRequestPacket(mac, myip, ip);

		if (pcap_sendpacket(adhandle,arpPacket ,sizeof(arp_packet)) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
			return;
		}
	}


	return 0;
}

DWORD WINAPI CaptureThreadProc(LPVOID lpParameter) {
	pcap_t* adhandle = (pcap_t*)lpParameter;
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	//struct tm ltime;
	//char timestr[16];
	//time_t local_tv_sec;

	string ip, mac;

	/*
	* unused variables
	*/
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	//local_tv_sec = header->ts.tv_sec;
	//localtime_s(&ltime, &local_tv_sec);
	//strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	//fprintf(fp, "%s,%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	const arp_packet* arpPacket = (arp_packet*)pkt_data;

	ip = inet_ntoa(*(in_addr*)&arpPacket->arp.sour_ip);
	for (int i = 0; i < 6; i++) {
		if (i > 0) printf("-");
		mac += arpPacket->arp.sour_addr[i];
		printf("%02X", arpPacket->arp.sour_addr[i]);
	}
	if (0==ArpTable.count(ip))
	{
		ArpTable.insert(map<string, string>::value_type(ip, mac));
		cout << "ip:" << ip << "    mac:" << mac << endl;
	}



}
