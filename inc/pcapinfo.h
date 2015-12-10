//
// Created by Julien Fortin on 12/8/15.
//

#ifndef __PCAPINFO_H__
#define __PCAPINFO_H__

#include <pcap/pcap.h>

typedef struct packet_s
{
    struct pcap_pkthdr  header;
    const u_char        *data;
} packet_t;

#define THREADPOOL_QUEUE_SIZE 4242

#endif
