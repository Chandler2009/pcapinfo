//
// Created by Julien Fortin on 12/8/15.
//

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#ifdef __linux__
    #include <netinet/ether.h>
#elif __APPLE__
    #include <net/ethernet.h>
#endif

#include "pcapinfo.h"
#include "threadpool.h"

static threadpool_t*   pool             = NULL;

static pthread_mutex_t _display_lock    = PTHREAD_MUTEX_INITIALIZER;

static inline void printerr(const char* err, size_t len)
{
    write(2, err, len);
}

static inline int usage()
{
    printerr("Usage: ./pcapinfo NB_THREADS(>=1) FILE\n", 39);
    return EXIT_FAILURE;
}

static pcap_t* open_pcap_file(const char* filename)
{
    char errorbuff[PCAP_ERRBUF_SIZE];

    pcap_t *file = pcap_open_offline(filename, errorbuff);

    if (!file)
        printerr(errorbuff, strlen(errorbuff));

    return file;
}

static inline void  _free_packet(packet_t* packet)
{
    if (packet)
    {
        free((void*)packet->data);
        free(packet);
    }
}

static void* _analyze_packet_error_truncated_ip(packet_t* packet, int len)
{
    if (_pthread_mutex_lock(&_display_lock))
    {
        fprintf(stderr, "Error: ip packet truncated. %d instead of %lu\n", len, sizeof(struct ip));
        _pthread_mutex_unlock(&_display_lock);
    }
    _free_packet(packet);
    return NULL;
}

static void* _analyze_packet_error_version(packet_t* packet, int version)
{
    if (_pthread_mutex_lock(&_display_lock))
    {
        fprintf(stderr,"Error: Unknown version %d\n", version);
        _pthread_mutex_unlock(&_display_lock);
    }
    _free_packet(packet);
    return NULL;
}

static void*    _analyze_packet(void* data)
{
    if (!data)
        return NULL;

    packet_t*   packet = (packet_t*)data;

    char    time_buffer[9];
    char*   protocol;

    strftime(time_buffer, sizeof(time_buffer), "%H:%M:%S", localtime(&packet->header.ts.tv_sec));

    struct ether_header*    ethernet_header = (struct ether_header *)packet->data;

    char    *src_mac = ether_ntoa((const struct ether_addr *)&ethernet_header->ether_shost);
    char    *dest_mac = ether_ntoa((const struct ether_addr *)&ethernet_header->ether_dhost);

    const struct ip*     ip = (struct ip*)(packet->data + sizeof(struct ether_header));

    struct tcphdr*  tcp;
    struct udphdr*  udp;

    int src_port;
    int dest_port;

    switch (ip->ip_p)
    {
        case IPPROTO_TCP:
            tcp = (struct tcphdr*)(packet->data + sizeof(struct ether_header) + sizeof(struct ip));
            src_port = ntohs(tcp->th_sport);
            dest_port = ntohs(tcp->th_dport);
            protocol = "TCP";
            break;

        case IPPROTO_UDP:
            udp = (struct udphdr*)(packet->data + sizeof(struct ether_header) + sizeof(struct ip));
            src_port = ntohs(udp->uh_sport);
            dest_port = ntohs(udp->uh_dport);
            protocol = "UDP";
            break;

        default:
            protocol = "";
            src_port = -42;
            dest_port = -42;
            break;
    }

    u_int length = packet->header.len - sizeof(struct ether_header);

    if (length < sizeof(struct ip))
        return _analyze_packet_error_truncated_ip(packet, length);

    u_int hlen      = ip->ip_hl;
    u_int version   = ip->ip_v;

    if (version != 4)
        return _analyze_packet_error_version(packet, version);
    if (hlen < 5)
        fprintf(stderr,"bad-hlen %d \n", hlen);

    u_int off = ntohs(ip->ip_off);
    if ((off & 0x1fff) == 0)
    {
        const char* src_ip = inet_ntoa(ip->ip_src);
        const char* dest_ip = inet_ntoa(ip->ip_dst);

        if (_pthread_mutex_lock(&_display_lock))
        {
            printf("[%s][%s](%s)%s:%d -> (%s)%s:%d\n",
                   time_buffer,
                   protocol,
                   src_mac,
                   src_ip,
                   src_port,
                   dest_mac,
                   dest_ip,
                   dest_port);
            fflush(NULL);
            _pthread_mutex_unlock(&_display_lock);
        }
    }
    _free_packet(packet);
    return NULL;
}

static void*    _read_packet(void *data)
{
    if (!data)
        return NULL;

    pcap_t *file = (pcap_t *) data;

    packet_t* packet = NULL;

    struct pcap_pkthdr* header;
    const u_char*       pkt_data;

    while ((pcap_next_ex(file, &header, &pkt_data)) > 0)
    {
        packet = calloc(1, sizeof(packet_t));
        if (!packet)
            perror("copy packet: malloc");
        else
        {
            memcpy(&packet->header, header, sizeof(struct pcap_pkthdr));

            if ((packet->data = calloc(header->len, sizeof(*pkt_data))))
            {
                memcpy((void*)packet->data, pkt_data, header->len);
                threadpool_add_task(pool, &_analyze_packet, packet);
            }
            else
                perror("copy packet: calloc");
        }
    }
    pcap_close(file);
    return NULL;
}

int main(int ac, const char *av[])
{
    if (ac < 3)
        return usage();

    pcap_t* file;

    for (int i = 2; i < ac; ++i)
        if ((file = open_pcap_file(av[i])))
        {
            if (!pool && !(pool = threadpool_new(atoi(av[1]), THREADPOOL_QUEUE_SIZE)))
            {
                printerr("Invalid threadpool.\n", 20);
                pthread_mutex_destroy(&_display_lock);
                pcap_close(file);
                return EXIT_FAILURE;
            }
            threadpool_add_task(pool, &_read_packet, file);
        }
    threadpool_delete(pool);
    pthread_mutex_destroy(&_display_lock);
    return EXIT_SUCCESS;
}
