#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <net/if_arp.h>

#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <signal.h>
#endif

#define MAC_ADDRSTRLEN 2 * 6 + 5 + 1
#define STR_BUF 16
#define netmask 0xffffff
#define MAX_SIZE 500

typedef struct eth_h
{
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
} eth_h;

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

typedef struct ip_header
{
    u_char ver_ihl;         // Version (4 bits) + Internet header length (4 bits)
    u_char tos;             // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;             // Time to live
    u_char proto;           // Protocol
    u_short crc;            // Header checksum
    ip_address saddr;       // Source address
    ip_address daddr;       // Destination address
    u_int op_pad;           // Option + Padding
} ip_header;

typedef struct udp_header
{
    u_short sport; // Source port
    u_short dport; // Destination port
    u_short len;   // Datagram length
    u_short crc;   // Checksum
} udp_header;

typedef struct tcp_header
{
    u_short source_port;
    u_short destination_port;
    u_long seq_number;
    u_long ack_number;
    u_short info_ctrl;
    u_short window;
    u_short checksum;
    u_short urgent_pointer;
} tcp_header;

typedef struct A
{
    char from[MAX_SIZE];
    char to[MAX_SIZE];
    int num;
} count;
count ans_count[MAX_SIZE];

static const char *mac_ntoa(u_int8_t *d);
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
static void dump_ethernet(u_int32_t len, const u_char *pkt_data);
u_short n_data = 0;
u_short n_ip = 0;
int main(int argc, char **argv)
{
    pcap_t *fp;
    char filename[20], errbuf[PCAP_ERRBUF_SIZE], source[PCAP_ERRBUF_SIZE];
    char packet_filter[] = "";
    struct bpf_program fcode;
    char *device = NULL;
    int i;

    if (argc < 2 || argc > 3 || strcmp(argv[1], "-r") != 0)
    {
        printf("請輸入:%s -r 檔案名稱\n", argv[0]);
        return -1;
    }

    device = pcap_lookupdev(errbuf);
    if (device == NULL)
    {
        fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
        exit(1);
    }

    strcpy(filename, argv[2]);
    //open file
    if ((fp = pcap_open_offline(filename, errbuf)) == NULL)
    {
        fprintf(stderr, "無法開啟%s!\n", filename);
        return -1;
    }

    memset(ans_count, 0, sizeof(ans_count));
    pcap_freecode(&fcode);
    pcap_loop(fp, 0, dispatcher_handler, NULL);

    printf("----------我是分隔線----------\n");
    printf("所有封包的傳遞次數:\n");
    for (i = 0; i < n_ip; i++)
        printf("%2d data從來源IP:%s to 目的IP:%s.\n", ans_count[i].num + 1, ans_count[i].from, ans_count[i].to);

    return 0;
}
void dispatcher_handler(u_char *tmp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    n_data++;
    printf("\n第%d筆資料\n", n_data);
    ip_header *ih;
    tcp_header *th;
    udp_header *uh;
    u_short sport, dport;
    u_int ip_len;
    int i = 0, flag = 0;

    struct tm *timeinfo;
    char buffer[30], source_ip[MAX_SIZE], des_ip[MAX_SIZE];

    memset(source_ip, 0, MAX_SIZE);
    memset(des_ip, 0, MAX_SIZE);

    //print ip time
    timeinfo = localtime(&header->ts.tv_sec);
    strftime(buffer, 30, "%Y/%m/%d %H:%M:%S", timeinfo);
    printf("擷取時間:%s", buffer);

    //print MAC address
    dump_ethernet(header->caplen, pkt_data);
    struct eth_h *ethernet = (struct eth_h *)pkt_data;
    printf("ether_type = %d\n\n", ethernet->ether_type);

    if (ntohs(ethernet->ether_type) == ETHERTYPE_IP)
    {
        ih = (ip_header *)(pkt_data + 14);
        ip_len = (ih->ver_ihl & 0xf) * 4;
        snprintf(source_ip, sizeof(source_ip), "%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
        snprintf(des_ip, sizeof(des_ip), "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
        printf("來源IP = %s\n目的IP = %s\n\n", source_ip, des_ip);

        for (i = 0; i < MAX_SIZE; i++)
            if (strcmp(ans_count[i].from, source_ip) == 0 && strcmp(ans_count[i].to, des_ip) == 0)
            {
                ans_count[i].num++;
                flag = 1;
            }

        if (flag == 0)
        {
            strcpy(ans_count[n_ip].from, source_ip);
            strcpy(ans_count[n_ip].to, des_ip);
            n_ip++;
        }
        //UDP
        if (ih->proto == 17)
        {
            uh = (udp_header *)((u_char *)ih + ip_len);
            sport = ntohs(uh->sport);
            dport = ntohs(uh->dport);
            printf("這是UDP封包\n");
            printf("來源port號碼 = %d\n目的port號碼 = %d\n\n", sport, dport);
        }
        //TCP
        else if (ih->proto == 6)
        {
            th = (tcp_header *)((u_char *)ih + ip_len);
            sport = ntohs(th->source_port);
            dport = ntohs(th->destination_port);
            printf("這是TCP封包\n");
            printf("來源port號碼 = %d\n目的port號碼 = %d\n\n", sport, dport);
        }
    }
    else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
    {
        printf("這是ARP封包\n");
    }
    else if (ntohs(ethernet->ether_type) == ETHERTYPE_REVARP)
    {
        printf("這是Reverse ARP封包\n");
    }
    else if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV6)
    {
        printf("這是IPV6封包\n");
    }
    else
    {
        printf("I don't know.\n");
    }
}

//顯示來源MAC位址與目的MAC位址
static void dump_ethernet(u_int32_t length, const u_char *pkt_data)
{
    char source_MAC[MAC_ADDRSTRLEN];
    char des_MAC[MAC_ADDRSTRLEN];

    memset(source_MAC, 0, sizeof(source_MAC));
    memset(des_MAC, 0, sizeof(des_MAC));

    struct eth_h *ethernet = (struct eth_h *)pkt_data;
    sprintf(source_MAC, "%s", mac_ntoa(ethernet->ether_shost));
    sprintf(des_MAC, "%s", mac_ntoa(ethernet->ether_dhost));
    printf("\n\n來源MAC位址:%17s", source_MAC);
    printf("\n目的MAC位址:%17s\n", des_MAC);
}
static const char *mac_ntoa(u_int8_t *d)
{
    static char mac[STR_BUF][MAC_ADDRSTRLEN];
    static int which = -1;
    which = (which + 1 == STR_BUF ? 0 : which + 1);
    memset(mac[which], 0, MAC_ADDRSTRLEN);
    snprintf(mac[which], sizeof(mac[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
    return mac[which];
}

