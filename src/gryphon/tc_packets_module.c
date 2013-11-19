
#include <xcopy.h>
#include <gryphon.h>

static time_t         read_pcap_over_time;
static uint64_t       adj_v_pack_diff = 0;
static uint64_t       session_created = 0;
static uint64_t       packets_considered_cnt = 0;
static uint64_t       packets_cnt = 0;
static struct timeval first_pack_time, last_v_pack_time,
                      last_pack_time;

static int dispose_packet(unsigned char *frame, int frame_len, int ip_recv_len);

static void tc_process_packets(tc_event_timer_t *evt);
static uint64_t timeval_diff(struct timeval *start, struct timeval *cur);


static unsigned char *alloc_pool_mem(int length)
{
    unsigned char *p;

    p = clt_settings.mem_pool + clt_settings.mem_pool_index;
    clt_settings.mem_pool_index += length;

    if (clt_settings.mem_pool_index >= clt_settings.mem_pool_size) {
        tc_log_info(LOG_ERR, 0, "pool full, calloc error for frame data");
        return NULL;
    }
    return p;
}

static void append_by_order(session_data_t *s, frame_t *added_frame)
{
    bool     last_changed = true;
    frame_t *next, *node;

    node = s->last_frame;
    next = node->next;

    while (node != NULL && after(node->seq, added_frame->seq)) {
        next = node;
        node = node->prev;
        last_changed = false;
    }

    if (node != NULL) {
        node->next        = added_frame;
        added_frame->prev = node;
    }
    if (next != NULL) {
        next->prev        = added_frame;
        added_frame->next = next;
    }

    s->frames++;

    if (last_changed) {
        s->last_frame = added_frame;
    }

}


static void 
record_packet(uint64_t key, unsigned char *frame, int frame_len, uint32_t seq, 
        uint32_t ack_seq, uint16_t src_port, bool saved, 
        uint16_t cont_len, int status)
{
    frame_t        *fr = NULL;
    session_data_t *session = NULL;
    p_session_entry entry   = NULL;

    entry = tc_retrieve_session(key);

    if (status == SYN_SENT) {
        tc_log_debug1(LOG_DEBUG, 0, "reuse port:%llu", ntohs(src_port));
        entry = NULL;
    }
    if (entry == NULL) {
        if (status != SYN_SENT) {
            return;
        }

        fr = (frame_t *) alloc_pool_mem(sizeof(frame_t));
        if (fr == NULL) {
            tc_log_info(LOG_WARN, 0, "calloc error for frame_t");
            return;
        }
        fr->frame_data = alloc_pool_mem(frame_len);
        if (fr->frame_data == NULL) {
            tc_log_info(LOG_WARN, 0, "calloc error for frame data");
            return;
        }
        memcpy(fr->frame_data, frame, frame_len);
        fr->frame_len = frame_len;

        fr->seq = seq;
        entry = (p_session_entry) alloc_pool_mem(sizeof(session_entry_t));
        if (entry == NULL) {
            tc_log_info(LOG_WARN, 0, "calloc error for session_entry_t");
            return;
        }
        session_created++;
        entry->key = key;
        session = &(entry->data);

        session->first_frame = fr;
        session->frames = 1;
        session->last_frame = fr;
        session->last_ack_seq = ack_seq;
        session->orig_src_port = src_port;
        session->status = SYN_SENT;
        tc_add_session(entry);

    } else {

        session = &(entry->data);
        session->status |= status;
        if (cont_len > 0) {
            session->has_req = 1;
        } else if ((session->status & SEND_REQ) && 
                (!(session->status & CLIENT_FIN))) 
        {
            tc_log_debug1(LOG_DEBUG, 0, "dropped:%u", ntohs(src_port));
            return;
        }

        if (!saved) {
            session->end = 1;
        }

        if (!session->end) {
        
            fr = (frame_t *) alloc_pool_mem(sizeof(frame_t));
            if (fr == NULL) {
                tc_log_info(LOG_WARN, 0, "calloc error for frame_t");
                return;
            }
            fr->frame_data = alloc_pool_mem(frame_len);
            if (fr->frame_data == NULL) {
                tc_log_info(LOG_WARN, 0, "calloc error for frame data");
                return;
            }
            memcpy(fr->frame_data, frame, frame_len);
            fr->frame_len = frame_len;
            fr->seq = seq;

            append_by_order(session, fr);
            if (session->last_ack_seq == ack_seq) {
                fr->belong_to_the_same_req = 1;
                tc_log_debug1(LOG_DEBUG, 0, "belong to the same req:%u", ntohs(src_port));
            } else {
                tc_log_debug1(LOG_DEBUG, 0, "a new req:%u", ntohs(src_port)); 
            }
            session->last_ack_seq = ack_seq;
        }
    }

}


static int
dispose_packet(unsigned char *frame, int frame_len, int ip_recv_len)
{
    int              i, last, packet_num, max_payload,
                     index, payload_len, status = 0;
    bool             saved = true;
    char             *p, buf[ETHERNET_HDR_LEN + IP_RECV_BUF_SIZE];
    uint16_t         id, size_ip, size_tcp, tot_len, cont_len, 
                     pack_len = 0, head_len;
    uint32_t         seq, tmp_seq, ack_seq;
    uint64_t         key;
    unsigned char   *packet;
    tc_ip_header_t  *ip_header;
    tc_tcp_header_t *tcp_header;

    packet = frame + ETHERNET_HDR_LEN;


    ip_header   = (tc_ip_header_t *) packet;

    packets_cnt++;
    if (ip_header->protocol != IPPROTO_TCP) {
        return TC_ERROR;
    }    

    size_ip     = ip_header->ihl << 2;
    if (size_ip < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid IP header length: %d", size_ip);
        return TC_ERROR;
    }
    tcp_header  = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    size_tcp    = tcp_header->doff << 2;

    if (size_tcp < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid TCP header len: %d bytes", size_tcp);
        return TC_ERROR;
    }

    if (LOCAL == check_pack_src(&(clt_settings.transfer), 
                ip_header->daddr, tcp_header->dest, CHECK_DEST)) {
        if (clt_settings.target_localhost) {
            if (ip_header->saddr != LOCALHOST) {
                tc_log_info(LOG_WARN, 0, "not localhost source ip address");
                return TC_ERROR;
            }
        }
        tot_len     = ntohs(ip_header -> tot_len);
        head_len = size_tcp + size_ip;
        if (tot_len < head_len) {
            tc_log_info(LOG_WARN, 0, "bad tot_len:%d bytes, header len:%d",
                    tot_len, head_len);
            return TC_ERROR;
        }
    } else {
        return TC_ERROR;
    }

#if (GRYPHON_DEBUG)
    tc_log_trace(LOG_NOTICE, 0, CLIENT_FLAG, ip_header, tcp_header);
#endif
    if (tcp_header->syn) {
        status = SYN_SENT;
    } else if (tcp_header->fin || tcp_header->rst) {
        status = CLIENT_FIN;
#if (GRYPHON_COMET)
        saved = false;
#endif
    } 
    packets_considered_cnt++;

    key = tc_get_key(ip_header->saddr, tcp_header->source);
    ack_seq = ntohl(tcp_header->ack_seq);
    ack_seq = ntohl(tcp_header->ack_seq);
    seq = ntohl(tcp_header->seq);

    cont_len    = tot_len - size_tcp - size_ip;
    if (cont_len > 0) {
        status |= SEND_REQ;
    }

    /* 
     * If the packet length is larger than MTU, we split it. 
     */
    if (ip_recv_len > clt_settings.mtu) {

        /* calculate number of packets */
        if (tot_len != ip_recv_len) {
            tc_log_info(LOG_WARN, 0, "packet len:%u, recv len:%u",
                    tot_len, ip_recv_len);
            return TC_ERROR;
        }

        head_len    = size_ip + size_tcp;
        max_payload = clt_settings.mtu - head_len;
        packet_num  = (cont_len + max_payload - 1)/max_payload;
        last        = packet_num - 1;
        id          = ip_header->id;


        tc_log_debug1(LOG_DEBUG, 0, "recv:%d, more than MTU", ip_recv_len);
        index = head_len;

        for (i = 0 ; i < packet_num; i++) {
            tcp_header->seq = htonl(seq + i * max_payload);
            if (i != last) {
                pack_len  = clt_settings.mtu;
            } else {
                pack_len += (cont_len - packet_num * max_payload);
            }
            payload_len = pack_len - head_len;
            ip_header->tot_len = htons(pack_len);
            ip_header->id = id++;
            p = buf + ETHERNET_HDR_LEN;
            /* copy header here */
            memcpy(p, (char *) packet, head_len);
            p +=  head_len;
            /* copy payload here */
            memcpy(p, (char *) (packet + index), payload_len);
            index = index + payload_len;

            tmp_seq = ntohl(tcp_header->seq);
            record_packet(key, (unsigned char *) buf,
                    ETHERNET_HDR_LEN + pack_len, tmp_seq, ack_seq, 
                    tcp_header->source, saved, cont_len, status);
        }
    } else {
        record_packet(key, frame, frame_len, seq, ack_seq, 
                tcp_header->source, saved, cont_len, status);
    }

    return TC_OK;
}

int
tc_send_init(tc_event_loop_t *event_loop)
{
#if (!GRYPHON_PCAP_SEND)
    int  fd;
#endif

#if (!GRYPHON_PCAP_SEND)
    /* init the raw socket to send */
    if ((fd = tc_raw_socket_out_init()) == TC_INVALID_SOCKET) {
        return TC_ERROR;
    } else {
        tc_raw_socket_out = fd;
    }
#else
    tc_pcap_send_init(clt_settings.output_if_name, clt_settings.mtu);
#endif

    /* register a timer for activating sending packets */
    tc_event_timer_add(event_loop, 0, tc_process_packets);

    return TC_OK;
}

static void
tc_process_packets(tc_event_timer_t *evt)
{
    int i = 0;
    evt->msec = tc_current_time_msec;

    for (; i < clt_settings.throughput_factor; i++) {
        process_ingress();
    }
}

static uint64_t
timeval_diff(struct timeval *start, struct timeval *cur)
{
    uint64_t usec;

    usec  = (cur->tv_sec - start->tv_sec) * 1000000;
    usec += cur->tv_usec - start->tv_usec;

    return usec;
}

void 
read_packets_from_pcap(char *pcap_file, char *filter)
{
    int                 first = 1, l2_len, ip_pack_len;
    char                ebuf[PCAP_ERRBUF_SIZE];
    bool                stop = false;
    pcap_t             *pcap;
    unsigned char      *pkt_data, *frame, *ip_data;
    struct bpf_program  fp;
    struct pcap_pkthdr  pkt_hdr;  


    if ((pcap = pcap_open_offline(pcap_file, ebuf)) == NULL) {
        tc_log_info(LOG_ERR, 0, "open %s" , ebuf);
        return;
    }

    if (filter != NULL) {
        if (pcap_compile(pcap, &fp, filter, 0, 0) == -1) {
            tc_log_info(LOG_ERR, 0, "couldn't parse filter %s: %s", 
                    filter, pcap_geterr(pcap));
            return;
        }   
        if (pcap_setfilter(pcap, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n",
                    filter, pcap_geterr(pcap));
            return;
        }
    }

    while (!stop) {

        pkt_data = (u_char *) pcap_next(pcap, &pkt_hdr);
        if (pkt_data != NULL) {

            if (pkt_hdr.caplen < pkt_hdr.len) {

                tc_log_info(LOG_WARN, 0, "truncated packets,drop");
            } else {

                ip_data = get_ip_data(pcap, pkt_data, pkt_hdr.len, &l2_len);
                if (l2_len < ETHERNET_HDR_LEN) {
                    tc_log_info(LOG_WARN, 0, "l2 len is %d", l2_len);
                    continue;
                }

                last_pack_time = pkt_hdr.ts;
                if (ip_data != NULL) {
                    clt_settings.pcap_time = last_pack_time.tv_sec * 1000 + 
                        last_pack_time.tv_usec / 1000; 

                    ip_pack_len = pkt_hdr.len - l2_len;
                    tc_log_debug2(LOG_DEBUG, 0, "frame len:%d, ip len:%d",
                            pkt_hdr.len, ip_pack_len);
                    frame = ip_data - ETHERNET_HDR_LEN;
                    dispose_packet(frame, ip_pack_len + ETHERNET_HDR_LEN,
                            ip_pack_len);

                    if (first) {
                        first_pack_time = pkt_hdr.ts;
                        first = 0;
                    } else {
                        adj_v_pack_diff = timeval_diff(&last_v_pack_time,
                                &last_pack_time);
                    }

                    /* set last valid packet time in pcap file */
                    last_v_pack_time = last_pack_time;

                }
            }
        } else {

            stop = true;
            tc_log_info(LOG_NOTICE, 0, "stop, null from pcap_next");
            read_pcap_over_time = tc_time();
        }
    }

    pcap_close(pcap);
    tc_log_info(LOG_INFO, 0, "total packets: %llu, needed packets:%llu", 
            packets_cnt, packets_considered_cnt);
    
}

void 
calculate_mem_pool_size(char *pcap_file, char *filter)
{
    int                 l2_len;
    char                ebuf[PCAP_ERRBUF_SIZE];
    bool                stop = false;
    pcap_t             *pcap;
    uint16_t            size_ip, size_tcp;
    unsigned char      *pkt_data,*ip_data;
    tc_ip_header_t     *ip_header;
    tc_tcp_header_t    *tcp_header;
    struct bpf_program  fp;
    struct pcap_pkthdr  pkt_hdr;  



    if ((pcap = pcap_open_offline(pcap_file, ebuf)) == NULL) {
        tc_log_info(LOG_ERR, 0, "open %s" , ebuf);
        return;
    }

    if (filter != NULL) {
        if (pcap_compile(pcap, &fp, filter, 0, 0) == -1) {
            tc_log_info(LOG_ERR, 0, "couldn't parse filter %s: %s", 
                    filter, pcap_geterr(pcap));
            return;
        }   
        if (pcap_setfilter(pcap, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n",
                    filter, pcap_geterr(pcap));
            return;
        }
    }

    while (!stop) {

        pkt_data = (u_char *) pcap_next(pcap, &pkt_hdr);
        if (pkt_data != NULL) {

            if (pkt_hdr.caplen >= pkt_hdr.len) {
                ip_data = get_ip_data(pcap, pkt_data, pkt_hdr.len, &l2_len);
                if (l2_len < ETHERNET_HDR_LEN) {
                    continue;
                }

                if (ip_data != NULL) {
                    ip_header   = (tc_ip_header_t *) ip_data;
                    if (ip_header->protocol != IPPROTO_TCP) {
                        continue;
                    }    
                    size_ip = ip_header->ihl << 2;
                    if (size_ip < 20) {
                        continue;
                    }
                    tcp_header = (tc_tcp_header_t *) (ip_data + size_ip);
                    size_tcp   = tcp_header->doff << 2;
                    if (size_tcp < 20) {
                        continue;
                    }
                    if (LOCAL != check_pack_src(&(clt_settings.transfer), 
                                ip_header->daddr, tcp_header->dest, CHECK_DEST)) 
                    {
                        continue;
                    }

                    if (tcp_header->syn) {
                        clt_settings.mem_pool_size += sizeof(session_entry_t);
                    } 
                    clt_settings.mem_pool_size += pkt_hdr.len + sizeof(frame_t);
                }
            }
        } else {

            stop = true;
            tc_log_info(LOG_NOTICE, 0, "read over from file:%s", pcap_file);
            read_pcap_over_time = tc_time();
        }
    }

    pcap_close(pcap);
}


