#ifndef _NETFILTER_H
#define _NETFILTER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define MAX_PKT_BUF_LEN 4096

typedef struct pkt_data_t {
    unsigned char data[MAX_PKT_BUF_LEN];
    uint32_t len;
} pkt_data_t;

extern uint go_callback(uint32_t id, uint16_t proto, unsigned char* data, int len, void* user_data, pkt_data_t *pkt_data);

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *user_data){
    uint32_t id = -1;
    uint16_t proto;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    unsigned char *buffer = NULL;
    int len = 0;
    int verdict = 0;
    pkt_data_t pkt_data;

    memset(&pkt_data, 0, sizeof(pkt_data_t));
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);
    proto = ntohs(ph->hw_protocol);

    len = nfq_get_payload(nfa, &buffer);
    verdict = go_callback(id, proto, buffer, len, user_data, &pkt_data);

    return nfq_set_verdict(qh, id, verdict, pkt_data.len, pkt_data.data);
}

static inline struct nfq_q_handle* CreateQueue(struct nfq_handle *h, u_int16_t queue, void* user_data)
{
    return nfq_create_queue(h, queue, &nf_callback, user_data);
}

static inline void Run(struct nfq_handle *h, int fd)
{
    char buf[MAX_PKT_BUF_LEN] __attribute__ ((aligned));
    int rv;

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }
}

#endif
