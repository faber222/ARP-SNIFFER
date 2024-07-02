#define _WIN32_WINNT 0x0600

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// Definindo o cabeçalho Ethernet
struct ether_header {
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
};

// Definindo o cabeçalho ARP
struct ether_arp {
    uint16_t arp_hrd;        /* Format of hardware address.  */
    uint16_t arp_pro;        /* Format of protocol address.  */
    uint8_t arp_hln;         /* Length of hardware address.  */
    uint8_t arp_pln;         /* Length of protocol address.  */
    uint16_t arp_op;         /* ARP opcode (command).  */
    uint8_t arp_sha[6];      /* Sender hardware address.  */
    uint8_t arp_spa[4];      /* Sender IP address.  */
    uint8_t arp_tha[6];      /* Target hardware address.  */
    uint8_t arp_tpa[4];      /* Target IP address.  */
};

// Definindo o tipo ARP
#define ETHERTYPE_ARP 0x0806

// Implementação de inet_ntop para Windows
const char* inet_ntop(int af, const void* src, char* dst, size_t size) {
    struct sockaddr_in srcaddr;

    memset(&srcaddr, 0, sizeof(struct sockaddr_in));
    srcaddr.sin_family = af;
    memcpy(&srcaddr.sin_addr, src, sizeof(struct in_addr));

    // Função WSAAddressToString para converter endereços binários para strings
    DWORD len = size;
    if (WSAAddressToString(( struct sockaddr* ) &srcaddr, sizeof(struct sockaddr_in), NULL, dst, &len) != 0) {
        return NULL;
    }

    return dst;
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header* eth_header = ( struct ether_header* ) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp* arp_header = ( struct ether_arp* ) (packet + sizeof(struct ether_header));
        char sender_ip[INET_ADDRSTRLEN];
        char target_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);

        printf("ARP packet captured:\n");
        printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
               arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
        printf("Sender IP: %s\n", sender_ip);
        printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
               arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);
        printf("Target IP: %s\n", target_ip);
        printf("\n");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    struct bpf_program fp;
    char filter_exp[] = "arp";
    bpf_u_int32 net;

    // Inicializando Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }

    // Open the device for capturing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Capture packets and log them
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the handle
    pcap_close(handle);

    // Finalizando Winsock
    WSACleanup();

    return 0;
}
