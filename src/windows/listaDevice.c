#include <pcap.h>
#include <stdio.h>

int main() {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the device list from the local machine
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    // Print the list
    for(d=alldevs; d; d=d->next) {
        printf("%s - %s\n", d->name, (d->description) ? d->description : "No description available");
    }

    // Free the device list
    pcap_freealldevs(alldevs);

    return 0;
}
