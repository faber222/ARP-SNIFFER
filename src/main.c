#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
        char sender_ip[INET_ADDRSTRLEN];
        char target_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);

        printf("PACOTE ARP CAPTURADO:\n");
        printf("MAC ORIGEM: %02x:%02x:%02x:%02x:%02x:%02x\n", 
               arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
               arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
        printf("IP ORIGEM: %s\n", sender_ip);
        printf("MAC DESTINO: %02x:%02x:%02x:%02x:%02x:%02x\n", 
               arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
               arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);
        printf("IP DESTINO: %s\n", target_ip);
        printf("\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "USE: %s <interface>\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "arp";
    bpf_u_int32 net;

    // Open the device for capturing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "NAO FOI POSSIVEL ENCONTRAR O DISPOSITIVO %s: %s\n", dev, errbuf);
        return 2;
    }

    // Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "FILTRO NAO ENCONTRADO %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "NAO FOI POSSIVEL APLICAR O FILTRO %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Capture packets and log them
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the handle
    pcap_close(handle);

    return 0;
}
