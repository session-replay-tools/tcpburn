
#include <xcopy.h>
#include <tc_user.h>

static bool    init_phase  = true;
static time_t  record_time = 0;
static int handshake_cnt   = 0;
static int size_of_user_index = 0;
static int size_of_users      = 0;
static int base_user_seq      = 0;
static int relative_user_seq  = 0;

static uint64_t fin_sent_cnt  = 0;
static uint64_t rst_sent_cnt  = 0;
static uint64_t conn_cnt      = 0;
static uint64_t rst_recv_cnt  = 0;
static uint64_t fin_recv_cnt  = 0;
static uint64_t resp_cnt      = 0; 
static uint64_t resp_cont_cnt = 0;
static uint64_t active_conn_cnt    = 0;
static uint64_t syn_sent_cnt       = 0;
static uint64_t packs_sent_cnt     = 0; 
static uint64_t cont_sent_cnt      = 0; 
static uint64_t orig_clt_packs_cnt = 0; 

static tc_user_index_t  *user_index_array = NULL;
static tc_user_t        *user_array       = NULL;
static session_table_t  *s_table          = NULL;

static uint32_t 
supplemental_hash(uint32_t value)                                                                 
{
    uint32_t h = 0;
    uint32_t tmp1 = value >> 20;
    uint32_t tmp2 = value >> 12;
    uint32_t tmp3 = tmp1 ^ tmp2;

    h = value ^ tmp3;
    tmp1 = h >> 7;
    tmp2 = h >> 4;
    tmp3 = tmp1 ^ tmp2;
    h= h ^ tmp3;

    return h;
}

static uint32_t table_index(uint32_t h, uint32_t len)
{
    return h & (len - 1);
}

int 
tc_build_session_table(int size)
{
    s_table = (session_table_t *) calloc(1, sizeof(session_table_t));
    if (s_table == NULL) {
        tc_log_info(LOG_WARN, 0, "calloc error for session table");
        return TC_ERROR;
    }

    s_table->size = size;
    s_table->entries = (p_session_entry *) calloc(size, sizeof(p_session_entry));

    if (s_table->entries == NULL) {
        tc_log_info(LOG_WARN, 0, "calloc error for session entries");
        free(s_table);
        s_table = NULL;
        return TC_ERROR;
    }

    return TC_OK;
}

uint64_t 
tc_get_key(uint32_t ip, uint16_t port)
{
    uint64_t ip_l   = (uint64_t) ip;
    uint64_t port_l = (uint64_t) port;
    uint64_t key = (ip_l << 16) + (ip_l << 8) + port_l; 
    return key;
}

void 
tc_add_session(p_session_entry entry)
{
    uint32_t h = supplemental_hash((uint32_t) entry->key);
    uint32_t index = table_index(h, s_table->size);
    p_session_entry e = NULL, last = NULL;

    for(e = s_table->entries[index]; e != NULL; e = e->next) { 
        if (e->key == entry->key) {   
            return;
        }   
        last = e;
    } 

    if (last == NULL) {
        s_table->entries[index] = entry;
    } else {
        last->next = entry;
    }

    s_table->num_of_sessions++;
    tc_log_info(LOG_NOTICE, 0, "index:%d,sessions in table:%d", 
            index, s_table->num_of_sessions);
}

static void
tc_init_session_for_users()
{
    bool            is_find = false;
    int             i, index = 0;
    tc_user_t      *u;
    p_session_entry e = NULL;
    session_data_t *sess;

    if (s_table->num_of_sessions == 0) {
        tc_log_info(LOG_WARN, 0, "no sessions for replay");
        return;
    }

    e = s_table->entries[index];

    for (i = 0; i < size_of_users; i++) {
        u = user_array + i;

        if (e == NULL) {
            is_find = false;
            do {
                index = (index + 1) % (s_table->size);
                e = s_table->entries[index];
                while (e != NULL) {
                    sess = &(e->data);
                    if (!sess->has_req) {
                        e = e->next;
                    } else {
                        is_find = true;
                        break;
                    }
                }

                if (is_find) {
                    break;
                }
            } while (e == NULL);
        } 

        u->orig_session = &(e->data);
        u->orig_frame = u->orig_session->first_frame;
        u->orig_unack_frame = u->orig_session->first_frame;
        orig_clt_packs_cnt += u->orig_session->frames;
        tc_log_debug3(LOG_DEBUG, 0, "index:%d,frames:%u, orig src port:%u", 
                index, u->orig_session->frames, 
                ntohs(u->orig_session->orig_src_port));

        e = e->next;
        while (e != NULL) {
            sess = &(e->data);
            if (!sess->has_req) {
                e = e->next;
            } else {
                is_find = true;
                break;
            }
        }
    }

    tc_log_info(LOG_NOTICE, 0, 
            "users:%d, sessions:%d, total packets needed sent:%llu",
            size_of_users, s_table->num_of_sessions, orig_clt_packs_cnt);
}

p_session_entry 
tc_retrieve_session(uint64_t key)
{
    uint32_t h = supplemental_hash((uint32_t) key);
    uint32_t index = table_index(h, s_table->size);
    p_session_entry e = NULL;

    for(e = s_table->entries[index]; e != NULL; e = e->next) { 
        if (e->key == key) {   
            return e;
        }   
    } 

    return NULL;
}

static tc_user_t *
tc_retrieve_active_user()
{
    int        total;
    time_t     cur;
    tc_user_t *u; 

    cur = tc_time();

    if (record_time == 0) {
        record_time = cur;
    }

    if (init_phase) {
        total = base_user_seq + relative_user_seq;
        if (total >= size_of_users) {
           tc_log_info(LOG_NOTICE, 0, "total is larger than size of users");
           init_phase = false;
           u = user_array + 0;
           base_user_seq = 1;
        } else {
            u = user_array + total;
            relative_user_seq = (relative_user_seq + 1) % 1024;

            if (relative_user_seq == 0) {
                if (record_time != cur) {
                    base_user_seq += 1024;
                    record_time = cur;
                    tc_log_info(LOG_NOTICE, 0, "change record time");
                    total = total + 1;
                    if (total == size_of_users) {
                        init_phase = false;
                        tc_log_info(LOG_NOTICE, 0, "set init phase false");
                    }
                }
            }
        }
      
    } else {
        u = user_array + base_user_seq;
        base_user_seq = (base_user_seq + 1) % size_of_users;
    }

    return u;
}

tc_user_t *
tc_retrieve_user(uint64_t key)
{
    int      index, i, min, max;

    index = key % size_of_user_index;

    min = user_index_array[index].index;

    if (index == (size_of_user_index -1)) {
        max = size_of_users;
    } else {
        max = user_index_array[index + 1].index;
    }

    tc_log_debug3(LOG_DEBUG, 0, "retrieve user,usr key :%llu,min=%d,max=%d", 
            key, min, max);
    for (i = min; i < max; i++) {
        if (user_array[i].key == key) {
            return user_array + i;
        }
    }

    return NULL;

}

bool 
tc_build_users(int port_prioritized, int num_users, uint32_t *ips, int num_ip)
{
    int       i, j, k, count, sub_key, slot_avg,
             *stat, *accum, *slot_cnt, *sub_keys;
    uint16_t *buf_ports, port;
    uint32_t  ip, *buf_ips;
    uint64_t  key, *keys;
    
    tc_log_info(LOG_INFO, 0, "enter tc_build_users");

    size_of_users = num_users;

    slot_avg = SLOT_AVG;
    if (size_of_users < slot_avg) {
        slot_avg = size_of_users;
    }

    size_of_user_index = size_of_users / slot_avg;

    user_array = (tc_user_t *) calloc (size_of_users, sizeof (tc_user_t));
    user_index_array = (tc_user_index_t *) calloc (size_of_user_index, 
            sizeof(tc_user_index_t));
    if (user_index_array == NULL || user_array == NULL) {
        tc_log_info(LOG_WARN, 0, "calloc error for users");
        return false;
    }

    count     = 0;
    keys      = (uint64_t *) malloc (sizeof(uint64_t) * size_of_users);
    sub_keys  = (int *) malloc (sizeof(int) * size_of_users);
    buf_ips   = (uint32_t *) malloc (sizeof(uint32_t) * size_of_users);
    buf_ports = (uint16_t *) malloc (sizeof(uint16_t) * size_of_users);
    accum     = (int *) malloc (sizeof(int) * size_of_users);
    stat      = (int *) malloc (sizeof(int) * size_of_user_index);
    slot_cnt  = (int *) malloc (sizeof(int) * size_of_user_index);

    if (keys == NULL || sub_keys == NULL || buf_ips == NULL || 
            buf_ports == NULL || accum == NULL || stat == NULL 
            || slot_cnt == NULL) 
    {
        free(keys);
        free(sub_keys);
        free(buf_ips);
        free(buf_ports);
        free(accum);
        free(stat);
        free(slot_cnt);
        tc_log_info(LOG_WARN, 0, "calloc error for building users");
        return false;
    }

    memset(stat, 0 ,sizeof(int) * size_of_user_index);
    memset(slot_cnt, 0 ,sizeof(int) * size_of_user_index);
    memset(sub_keys, 0, sizeof(int) * size_of_users);

    if (port_prioritized) {
        for ( i = 0; i < num_ip; i++) {
            ip = ips[i];

            for (j = 1024; j < 65536; j++) {
                port = htons(j);
                key = tc_get_key(ip, port);
                if (count >= size_of_users) {
                    break;
                }

                sub_key = key % size_of_user_index;
                if (stat[sub_key] >= SLOT_MAX) {
                    continue;
                }
                buf_ips[count] = ip;
                buf_ports[count] = port;
                sub_keys[count] = sub_key;
                keys[count++] = key;
                stat[sub_key]++;
            }
        }
    } else {
        for (j = 1024; j < 65536; j++) {
            port = htons(j);
            for ( i = 0; i < num_ip; i++) {
                ip = ips[i];

                key = tc_get_key(ip, port);
                if (count >= size_of_users) {
                    break;
                }

                sub_key = key % size_of_user_index;
                if (stat[sub_key] >= SLOT_MAX) {
                    continue;
                }
                buf_ips[count] = ip;
                buf_ports[count] = port;
                sub_keys[count] = sub_key;
                keys[count++] = key;
                stat[sub_key]++;
            }
        }
    }

    if (count < size_of_users) {
        tc_log_info(LOG_WARN, 0, "insuffient ips:%d for creating users:%d", 
                num_ip, size_of_users);
        tc_log_info(LOG_NOTICE, 0, "change users from %d to %d", 
                size_of_users, count); 
        size_of_users = count;
        size_of_user_index = size_of_users / slot_avg;
    }

    user_index_array[0].index = 0;
    for ( i = 1; i < size_of_user_index; i++) {
        user_index_array[i].index = stat[i - 1] + user_index_array[i - 1].index;
    }

    for ( i = 0; i < size_of_users; i++) {
        sub_key = sub_keys[i];
        if (sub_key > 0) {
            accum[i] = user_index_array[sub_key].index  + slot_cnt[sub_key];
        } else {
            accum[i] = slot_cnt[sub_key];

        }

        k = accum[i];
        user_array[k].src_addr = buf_ips[i];
        user_array[k].src_port = buf_ports[i];
        user_array[k].key = keys[i];
        tc_log_debug2(LOG_DEBUG, 0, "usr key :%llu,pos=%d", keys[i], k);

        slot_cnt[sub_key]++;
    }

    free(sub_keys);
    free(buf_ports);
    free(buf_ips);
    free(accum);
    free(stat);
    free(keys);
    free(slot_cnt);

    tc_init_session_for_users();

    tc_log_info(LOG_INFO, 0, "leave tc_build_users");

    return true;
}

static bool send_stop(tc_user_t *u) 
{
    int       time_diff;
    uint32_t  srv_sk_buf_s;

    if (u->orig_frame == NULL) {
        tc_log_debug1(LOG_DEBUG, 0, "orig frame is null :%d", 
                ntohs(u->src_port));
        return true;
    }

    if (u->state.status & SYN_SENT) {
        if (!(u->state.status & SYN_CONFIRM)) {
            tc_log_debug1(LOG_DEBUG, 0, "client wait server handshake:%d", 
                    ntohs(u->src_port));
            return true;
        }
    }

    if (u->state.status & CLIENT_FIN) {
        if (!(u->state.status & SERVER_FIN)) {
            tc_log_debug1(LOG_DEBUG, 0, "client wait server fin:%d", 
                ntohs(u->src_port));
            return true;
        }
    }

    time_diff = tc_time() - u->last_sent_time;
    if (time_diff >= 3) {
        u->state.resp_waiting = 0; 
        return false;
    }

    if (u->state.resp_waiting) {
            tc_log_debug1(LOG_DEBUG, 0, "client wait server resp:%d", 
                ntohs(u->src_port));
        return true;
    }

    if (u->state.status & SEND_REQ) {
        if (u->orig_frame->next != NULL) {
            srv_sk_buf_s = u->orig_frame->next->seq - u->orig_frame->seq;
            srv_sk_buf_s = srv_sk_buf_s + u->orig_frame->seq - u->last_ack_seq;
            if (srv_sk_buf_s > u->srv_window) {
                tc_log_debug3(LOG_DEBUG, 0, "wait,srv_sk_buf_s:%u,win:%u,p:%u",
                        srv_sk_buf_s, u->srv_window, ntohs(u->src_port));
                return true;
            }
        }

    }

    return false;
}

#if (GRYPHON_SINGLE)
static bool
send_router_info(tc_user_t *u, uint16_t type)
{
    int                      i, fd;
    bool                     result = false;
    msg_client_t             msg;
    connections_t           *connections;


    memset(&msg, 0, sizeof(msg_client_t));
    msg.client_ip = u->src_addr;
    msg.client_port = u->src_port;
    msg.type = htons(type);
    msg.target_ip = u->dst_addr;
    msg.target_port = u->dst_port;

    for (i = 0; i < clt_settings.real_servers.num; i++) {

        if (!clt_settings.real_servers.active[i]) {
            continue;
        }

        connections = &(clt_settings.real_servers.connections[i]);
        fd = connections->fds[connections->index];
        connections->index = (connections->index + 1) % connections->num;

        if (fd == -1) {
            tc_log_info(LOG_WARN, 0, "sock invalid");
            continue;
        }

        if (tc_socket_send(fd, (char *) &msg, MSG_CLIENT_SIZE) == TC_ERROR) {
            tc_log_info(LOG_ERR, 0, "fd:%d, msg client send error", fd); 
            if (clt_settings.real_servers.active[i] != 0) {
                clt_settings.real_servers.active[i] = 0;
                clt_settings.real_servers.active_num--;
            }

            continue;
        }
        result = true;
    }                                                                                                             
    return result;
}
#endif

static void
fill_timestamp(tc_user_t *u, tc_tcp_header_t *tcp_header)
{
    uint32_t         timestamp;
    unsigned char   *opt, *p; 

    p   = (unsigned char *) tcp_header;
    opt = p + sizeof(tc_tcp_header_t);
    opt[0] = 1;
    opt[1] = 1;
    opt[2] = 8;
    opt[3] = 10;
    timestamp = htonl(u->ts_value);
    bcopy((void *) &timestamp, (void *) (opt + 4), sizeof(timestamp));
    timestamp = htonl(u->ts_ec_r);
    bcopy((void *) &timestamp, (void *) (opt + 8), sizeof(timestamp));
    tc_log_debug3(LOG_DEBUG, 0, "fill ts:%u,%u,p:%u", 
            u->ts_value, u->ts_ec_r, ntohs(u->src_port));
}

static void 
update_timestamp(tc_user_t *u, tc_tcp_header_t *tcp_header)
{
    uint32_t       ts;
    unsigned int   opt, opt_len;
    unsigned char *p, *end;

    p = ((unsigned char *) tcp_header) + TCP_HEADER_MIN_LEN;
    end =  ((unsigned char *) tcp_header) + (tcp_header->doff << 2);  
    while (p < end) {
        opt = p[0];
        switch (opt) {
            case TCPOPT_TIMESTAMP:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if ((p + opt_len) <= end) {
                    ts = htonl(u->ts_ec_r);
                    tc_log_debug2(LOG_DEBUG, 0, "set ts reply:%u,p:%u", 
                            u->ts_ec_r, ntohs(u->src_port));
                    bcopy((void *) &ts, (void *) (p + 6), sizeof(ts));
                    ts = EXTRACT_32BITS(p + 2);
                    if (ts < u->ts_value) {
                        tc_log_debug1(LOG_DEBUG, 0, "ts < history,p:%u",
                                ntohs(u->src_port));
                        ts = htonl(u->ts_value);
                        bcopy((void *) &ts, (void *) (p + 2), sizeof(ts));
                    } else {
                        u->ts_value = ts;
                    }
                }
                return;
            case TCPOPT_NOP:
                p = p + 1; 
                break;
            case TCPOPT_EOL:
                return;
            default:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if (opt_len < 2) {
                    tc_log_info(LOG_WARN, 0, "opt len:%d", opt_len);
                    return;
                }
                p += opt_len;
                break;
        }    
    }
    return;
}

static bool process_packet(tc_user_t *u, unsigned char *frame) 
{
    bool                    result;
    uint16_t                size_ip, size_tcp, tot_len, cont_len;
    uint32_t                h_ack, h_last_ack;
    tc_ip_header_t         *ip_header;
    tc_tcp_header_t        *tcp_header;
    ip_port_pair_mapping_t *test;

    ip_header  = (tc_ip_header_t *) (frame + ETHERNET_HDR_LEN);
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    size_tcp = tcp_header->doff << 2;
    tot_len  = ntohs(ip_header->tot_len);
    cont_len = tot_len - size_tcp - size_ip;

    if (u->dst_port == 0) {
        test = get_test_pair(&(clt_settings.transfer), 
                ip_header->daddr, tcp_header->dest);
        if (test == NULL) {
            tc_log_info(LOG_NOTICE, 0, " test null:%u", 
                    ntohs(tcp_header->dest));
            tc_log_trace(LOG_WARN, 0, TO_BAKEND_FLAG, ip_header, tcp_header);
            return false;
        }
        u->dst_addr = test->target_ip;
        u->dst_port = test->target_port;
#if (GRYPHON_PCAP_SEND)
        u->src_mac       = test->src_mac;
        u->dst_mac       = test->dst_mac;
#endif
    }

    if (u->state.last_ack_recorded) {
        if (u->state.status < SEND_REQ && (u->state.status & SYN_CONFIRM)) {
            h_ack = ntohl(tcp_header->ack_seq);
            h_last_ack = ntohl(u->history_last_ack_seq);
            if (after(h_ack, h_last_ack)) {
                tc_log_debug1(LOG_DEBUG, 0, "server resp first, wait, p:%u", 
                        ntohs(u->src_port));
                u->state.resp_waiting = 1;
                return false;
            }
        }

    }

    ip_header->saddr = u->src_addr;
    tcp_header->source = u->src_port;
    u->history_last_ack_seq = tcp_header->ack_seq;
    u->state.last_ack_recorded = 1;
    tcp_header->ack_seq = u->exp_ack_seq;
    ip_header->daddr = u->dst_addr;
    tcp_header->dest = u->dst_port;

    tc_log_debug2(LOG_DEBUG, 0, "set ack seq:%u, p:%u",
            ntohl(u->exp_ack_seq), ntohs(u->src_port));

    packs_sent_cnt++;
    if (tcp_header->syn) {
        syn_sent_cnt++;
#if (GRYPHON_SINGLE)
        if (!send_router_info(u, CLIENT_ADD)) {
            return false;
        }
#endif
        u->state.last_ack_recorded = 0;
        u->state.status  |= SYN_SENT;
    } else if (tcp_header->fin) {
        fin_sent_cnt++;
        u->state.status  |= CLIENT_FIN;
    } else if (tcp_header->rst) {
        rst_sent_cnt++;
        u->state.status  |= CLIENT_FIN;
    }

    if (cont_len > 0) {
        cont_sent_cnt++;
        u->state.status |= SEND_REQ;
    }
    if (u->state.timestamped) {
        update_timestamp(u, tcp_header);
    }

    tcp_header->check = 0;
    tcp_header->check = tcpcsum((unsigned char *) ip_header,
            (unsigned short *) tcp_header, (int) (tot_len - size_ip));
#if (GRYPHON_PCAP_SEND)
    ip_header->check = 0;
    ip_header->check = csum((unsigned short *) ip_header,size_ip);
#endif
    tc_log_debug_trace(LOG_DEBUG, 0, TO_BAKEND_FLAG, ip_header, tcp_header);

#if (!GRYPHON_PCAP_SEND)
    result = tc_raw_socket_send(tc_raw_socket_out, ip_header, tot_len,
            ip_header->daddr);
#else
    fill_frame((struct ethernet_hdr *) frame, u->src_mac, u->dst_mac);
    result = tc_pcap_send(frame, tot_len + ETHERNET_HDR_LEN);
#endif

    if (result == TC_OK) {
        u->last_sent_time = tc_time();
        return true;
    } else {
        tc_log_info(LOG_ERR, 0, "send to back error,tot_len is:%d,cont_len:%d",
                tot_len,cont_len);
#if (!TCPCOPY_PCAP_SEND)
        tc_raw_socket_out = TC_INVALID_SOCKET;
#endif
        tc_over = SIGRTMAX;
        return false;
    }
}

static
void process_user_packet(tc_user_t *u)
{
    unsigned char   frame[DEFAULT_MTU + ETHERNET_HDR_LEN];

    if (send_stop(u)) {
        return;
    }

    while (true) {
        memcpy(frame, u->orig_frame->frame, DEFAULT_MTU + ETHERNET_HDR_LEN);
        process_packet(u, frame);
        u->total_packets_sent++;
        u->orig_frame = u->orig_frame->next;


        if (send_stop(u)) {
            break;
        }
        if (!u->orig_frame->belong_to_the_same_req) {
            if (u->state.status & SYN_ACK) {
                tc_log_debug1(LOG_DEBUG, 0, "set resp waiting:%u",
                        ntohs(u->src_port));
                u->state.resp_waiting = 1;
            }
            break;
        }
    }
}

static void 
send_faked_rst(tc_user_t *u)
{
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;
    unsigned char    *p, frame[FAKE_FRAME_LEN];

    memset(frame, 0, FAKE_FRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;
    ip_header  = (tc_ip_header_t *) p;
    tcp_header = (tc_tcp_header_t *) (p + IP_HEADER_LEN);

    ip_header->version  = 4;
    ip_header->ihl      = IP_HEADER_LEN/4;
    ip_header->frag_off = htons(IP_DF); 
    ip_header->ttl      = 64; 
    ip_header->protocol = IPPROTO_TCP;
    ip_header->tot_len  = htons(FAKE_MIN_IP_DATAGRAM_LEN);
    ip_header->saddr    = u->src_addr;
    ip_header->daddr    = u->dst_addr;
    tcp_header->source  = u->src_port;
    tcp_header->dest    = u->dst_port;
    tcp_header->seq     = u->exp_seq;
    tcp_header->ack_seq = u->exp_ack_seq;
    tcp_header->window  = htons(65535); 
    tcp_header->ack     = 1;
    tcp_header->rst     = 1;
    tcp_header->doff    = TCP_HEADER_DOFF_MIN_VALUE;

    process_packet(u, frame);
}


static void 
send_faked_ack(tc_user_t *u)
{
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;
    unsigned char    *p, frame[FAKE_FRAME_LEN];

    memset(frame, 0, FAKE_FRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;
    ip_header  = (tc_ip_header_t *) p;
    tcp_header = (tc_tcp_header_t *) (p + IP_HEADER_LEN);

    ip_header->version  = 4;
    ip_header->ihl      = IP_HEADER_LEN/4;
    ip_header->frag_off = htons(IP_DF); 
    ip_header->ttl      = 64; 
    ip_header->protocol = IPPROTO_TCP;
    ip_header->saddr    = u->src_addr;
    ip_header->daddr    = u->dst_addr;
    tcp_header->source  = u->src_port;
    tcp_header->dest    = u->dst_port;
    tcp_header->seq     = u->exp_seq;
    tcp_header->ack_seq = u->exp_ack_seq;
    tcp_header->window  = htons(65535); 
    tcp_header->ack     = 1;
    if (u->state.timestamped) {
        ip_header->tot_len  = htons(FAKE_IP_TS_DATAGRAM_LEN);
        tcp_header->doff    = TCP_HEADER_DOFF_TS_VALUE;
        fill_timestamp(u, tcp_header);
    } else {
        ip_header->tot_len  = htons(FAKE_MIN_IP_DATAGRAM_LEN);
        tcp_header->doff    = TCP_HEADER_DOFF_MIN_VALUE;
    }

    process_packet(u, frame);
}

static void
fast_retransmit(tc_user_t *u, uint32_t cur_ack_seq)
{
    frame_t          *unack_frame, *next;

    unack_frame = u->orig_unack_frame;
    if (unack_frame == NULL) {
        return;
    }

    next = unack_frame->next;
    while (true) {
        if (unack_frame == u->orig_frame) {
            break;
        }
        if (unack_frame->seq == cur_ack_seq) {
            tc_log_debug1(LOG_DEBUG, 0, "packets retransmitted:%u", 
                    ntohs(u->src_port));
            process_packet(u, unack_frame->frame);
            break;
        } else if (before(unack_frame->seq, cur_ack_seq) && next != NULL &&
                before(cur_ack_seq, next->seq)) 
        {
            process_packet(u, unack_frame->frame);
            break;
        } else if (before(unack_frame->seq, cur_ack_seq)) {
            unack_frame = next;
            if (unack_frame == NULL) {
                break;
            }
            next = unack_frame->next;
        } else {
            tc_log_debug1(LOG_DEBUG, 0, "packets retransmitted not match:%u", 
                    ntohs(u->src_port));
            break;
        }
    }
}

static void
update_ack_packets(tc_user_t *u, uint32_t cur_ack_seq)
{
    frame_t          *unack_frame, *next;

    unack_frame = u->orig_unack_frame;
    if (unack_frame == NULL) {
        return;
    }

    next = unack_frame->next;
    while (true) {
        if (unack_frame == u->orig_frame) {
            break;
        }
        if (next != NULL) {
            if (next->seq == cur_ack_seq) {
                u->orig_unack_frame = unack_frame->next;
                break;
            } else if (before(cur_ack_seq, next->seq) && 
                    before(unack_frame->seq, cur_ack_seq)) 
            {
                tc_log_debug1(LOG_DEBUG, 0, "partially acked:%u", 
                        ntohs(u->src_port));
                break;
            } else {    
                tc_log_debug1(LOG_DEBUG, 0, "skipped:%u", 
                        ntohs(u->src_port));
                unack_frame = next;
                next = unack_frame->next;
                if (unack_frame == u->orig_session->last_frame) {
                    break;
                }
            }
        } else {
            if (before(unack_frame->seq, cur_ack_seq)) {
                unack_frame = unack_frame->next;
            }
            u->orig_unack_frame = unack_frame;
            break;
        }
    }

}

static void         
retrieve_options(tc_user_t *u, int direction, tc_tcp_header_t *tcp_header)
{                   
    uint32_t       ts_value; 
    unsigned int   opt, opt_len;
    unsigned char *p, *end;

    p = ((unsigned char *) tcp_header) + TCP_HEADER_MIN_LEN;
    end =  ((unsigned char *) tcp_header) + (tcp_header->doff << 2);  
    while (p < end) {
        opt = p[0];
        switch (opt) {
            case TCPOPT_WSCALE:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if ((p + opt_len) > end) {
                    return;
                }
                u->wscale = (uint16_t) p[2];
                p += opt_len;
            case TCPOPT_TIMESTAMP:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if ((p + opt_len) > end) {
                    return;
                }
                if (direction == LOCAL) {
                    ts_value = EXTRACT_32BITS(p + 2);
                } else {
                    u->ts_ec_r  = EXTRACT_32BITS(p + 2);
                    ts_value = EXTRACT_32BITS(p + 6);
                    if (tcp_header->syn) {
                        u->state.timestamped = 1;
                        tc_log_debug1(LOG_DEBUG, 0, "timestamped,p=%u", 
                                ntohs(u->src_port));
                    }
                    tc_log_debug3(LOG_DEBUG, 0, 
                            "get ts(client viewpoint):%u,%u,p:%u", 
                            u->ts_value, u->ts_ec_r, ntohs(u->src_port));
                }
                if (ts_value > u->ts_value) {
                    tc_log_debug1(LOG_DEBUG, 0, "ts > history,p:%u",
                            ntohs(u->src_port));
                    u->ts_value = ts_value;
                }
                p += opt_len;
            case TCPOPT_NOP:
                p = p + 1; 
                break;                      
            case TCPOPT_EOL:
                return;
            default:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                p += opt_len;
                break;
        }    
    }

    return;
}

void process_outgress(unsigned char *packet)
{
    uint16_t           size_ip, size_tcp, tot_len, cont_len;
    uint32_t           seq, ack_seq;
    uint64_t           key;
    tc_user_t         *u;
    tc_ip_header_t    *ip_header;
    tc_tcp_header_t   *tcp_header;

    resp_cnt++;
    ip_header  = (tc_ip_header_t *) packet;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);


    key = tc_get_key(ip_header->daddr, tcp_header->dest);
    tc_log_debug1(LOG_DEBUG, 0, "key from bak:%llu", key);
    u = tc_retrieve_user(key);

    if (u != NULL) {

        tc_log_debug_trace(LOG_DEBUG, 0, BACKEND_FLAG, ip_header, tcp_header);
        u->srv_window = ntohs(tcp_header->window);
        if (u->wscale) {
            u->srv_window = u->srv_window << (u->wscale);
            tc_log_debug1(LOG_DEBUG, 0, "window size:%u", u->srv_window);
        }
        if (u->state.timestamped) {
            retrieve_options(u, REMOTE, tcp_header);
        }
        size_tcp = tcp_header->doff << 2;
        tot_len  = ntohs(ip_header->tot_len);
        cont_len = tot_len - size_tcp - size_ip;

        if (ip_header->daddr != u->src_addr || tcp_header->dest!= u->src_port) {
            tc_log_info(LOG_NOTICE, 0, " key conflict");
        }
        seq = ntohl(tcp_header->seq);
        u->exp_seq = tcp_header->ack_seq;
        ack_seq = ntohl(tcp_header->ack_seq);

        if (u->last_seq == seq && u->last_ack_seq == ack_seq) {
            u->fast_retransmit_cnt++;
            if (u->fast_retransmit_cnt == 3) {
                fast_retransmit(u, ack_seq);
                return;
            }
        } else {
            update_ack_packets(u, ack_seq);
            u->fast_retransmit_cnt = 0;
        }

        u->last_ack_seq =  ack_seq;
        u->last_seq =  seq;


        if (cont_len > 0) {
            resp_cont_cnt++;
            u->state.resp_waiting = 0;   
            u->exp_ack_seq = htonl(seq + cont_len);
            send_faked_ack(u);
        } else {
            u->exp_ack_seq = tcp_header->seq;
        }
        
        if (tcp_header->syn) {
            tc_log_debug1(LOG_DEBUG, 0, "recv syn from back:%u", 
                    ntohs(u->src_port));
            u->exp_ack_seq = htonl(ntohl(u->exp_ack_seq) + 1);
            if (!u->state.resp_syn_received) {
                conn_cnt++;
                active_conn_cnt++;
                u->state.resp_syn_received = 1;
                handshake_cnt++;
                u->state.status |= SYN_CONFIRM;
                tc_log_debug2(LOG_DEBUG, 0, "exp ack seq:%u, p:%u",
                        ntohl(u->exp_ack_seq), ntohs(u->src_port));
                if (size_tcp > TCP_HEADER_MIN_LEN) {
                    retrieve_options(u, REMOTE, tcp_header);
                    if (u->wscale > 0) {
                        tc_log_debug2(LOG_DEBUG, 0, "wscale:%u, p:%u",
                                u->wscale, ntohs(u->src_port));
                    }
                }
                process_user_packet(u);
                u->state.status |= SYN_ACK;

            } else {
                tc_log_debug1(LOG_DEBUG, 0, "syn, but already syn received:%u",
                    ntohs(u->src_port));
            }
        } else if (tcp_header->fin) {
            tc_log_debug1(LOG_DEBUG, 0, "recv fin from back:%u", 
                    ntohs(u->src_port));
            u->exp_ack_seq = htonl(ntohl(u->exp_ack_seq) + 1);
            u->state.status  |= SERVER_FIN;
            send_faked_rst(u);
            if (!u->state.over) {
                fin_recv_cnt++;
                active_conn_cnt--;
            }
            u->state.over = 1;
        } else if (tcp_header->rst) {
            tc_log_info(LOG_NOTICE, 0, "recv rst from back:%u", 
                    ntohs(u->src_port));
            if (u->state.status == SYN_SENT) {
                if (!u->state.over) {
                    rst_recv_cnt++;
                }
            }
            if (!u->state.over) {
                active_conn_cnt--;
            }
            u->state.over = 1;
            u->state.status  |= SERVER_RST;
        }


    } else {
        tc_log_debug_trace(LOG_DEBUG, 0, BACKEND_FLAG, ip_header,
                tcp_header);
        tc_log_debug0(LOG_DEBUG, 0, "no active session for me");
    }

}

#if (GRYPHON_PCAP_SEND)
void
fill_frame(struct ethernet_hdr *hdr, unsigned char *smac, unsigned char *dmac)
{
    memcpy(hdr->ether_shost, smac, ETHER_ADDR_LEN);
    memcpy(hdr->ether_dhost, dmac, ETHER_ADDR_LEN);
    hdr->ether_type = htons(ETH_P_IP); 
}
#endif



void process_ingress()
{
    tc_user_t      *u = NULL;

    u = tc_retrieve_active_user();

    if (!u->state.over) {
        process_user_packet(u);
    }
}

void
output_stat()
{
    tc_log_info(LOG_NOTICE, 0, "active conns:%llu", active_conn_cnt);
    tc_log_info(LOG_NOTICE, 0, "reset recv:%llu,fin recv:%llu",
            rst_recv_cnt, fin_recv_cnt);
    tc_log_info(LOG_NOTICE, 0, "reset sent:%llu, fin sent:%llu",
            rst_sent_cnt, fin_sent_cnt);
    tc_log_info(LOG_NOTICE, 0, "conns:%llu,resp packs:%llu,c-resp packs:%llu",
            conn_cnt, resp_cnt, resp_cont_cnt);
    tc_log_info(LOG_NOTICE, 0, 
            "syn sent cnt:%llu,clt packs sent :%llu,clt cont sent:%llu",
            syn_sent_cnt, packs_sent_cnt, cont_sent_cnt);
}

void
tc_interval_dispose(tc_event_timer_t *evt)
{
    output_stat();
    evt->msec = tc_current_time_msec + 5000;
}

void 
release_user_resources()
{
    int             i, rst_send_cnt = 0, valid_sess = 0;
    frame_t        *fr, *next_fr;
    tc_user_t      *u;
    p_session_entry e, next;

    if (user_array) {
        for (i = 0; i < size_of_users; i++) {
            u = user_array + i;
            if (!(u->state.status & SYN_CONFIRM)) {
                tc_log_info(LOG_NOTICE, 0, "connection fails:%u", 
                        ntohs(u->src_port));
            }
            if (u->total_packets_sent < u->orig_session->frames) {
                tc_log_debug3(LOG_DEBUG, 0, 
                        "total sent frames:%u, total:%u, p:%u", 
                        u->total_packets_sent, u->orig_session->frames, 
                        ntohs(u->src_port));
            }
            if (u->state.status && !u->state.over) {
                send_faked_rst(u);
                rst_send_cnt++;
            }
        }
    }

    tc_log_info(LOG_NOTICE, 0, "send %d reset packs to release tcp resources", 
            rst_send_cnt);

    if (s_table) {
        for (i = 0; i < s_table->size; i++) {
            e = s_table->entries[i];
            while (e) {
                fr = e->data.first_frame;
                if (e->data.has_req) {
                    valid_sess++;
                }
                while (fr) {
                    next_fr = fr->next;
                    free(fr);
                    fr = next_fr;
                }
                next = e->next;
                free(e);
                e = next;
            }
        }

        tc_log_info(LOG_NOTICE, 0, "valid sessions:%d", valid_sess);
        free(s_table->entries);
        free(s_table);
    }
    s_table = NULL;

    if (user_array) {
        free(user_array);
    }
    user_array = NULL;

    if (user_index_array) {
        free(user_index_array);
    }
    user_index_array = NULL;
}

