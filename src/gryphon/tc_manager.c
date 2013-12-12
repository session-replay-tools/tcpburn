
#include <xcopy.h>
#include <gryphon.h>


/* check resource usage, such as memory usage and cpu usage */
static void
check_resource_usage(tc_event_timer_t *evt)
{
    int           ret, who;
    struct rusage usage;

    who = RUSAGE_SELF;

    ret = getrusage(who, &usage);
    if (ret == -1) {
        tc_log_info(LOG_ERR, errno, "getrusage");
    }

    /* total amount of user time used */
    tc_log_info(LOG_NOTICE, 0, "user time used:%ld", usage.ru_utime.tv_sec);

    /* total amount of system time used */
    tc_log_info(LOG_NOTICE, 0, "sys  time used:%ld", usage.ru_stime.tv_sec);

    /* maximum resident set size (in kilobytes) */
    /* only valid since Linux 2.6.32 */
    tc_log_info(LOG_NOTICE, 0, "max memory size:%ld", usage.ru_maxrss);

    evt->msec = tc_current_time_msec + 60000;
}

void
gryphon_release_resources()
{
    int i;

    tc_log_info(LOG_WARN, 0, "sig %d received", tc_over); 

    output_stat(); 


    tc_time_remove_timer();
    tc_log_info(LOG_NOTICE, 0, "remove timer over");

    release_user_resources();

    tc_event_loop_finish(&event_loop);
    tc_log_info(LOG_NOTICE, 0, "tc_event_loop_finish over");

    tc_log_end();


    if (tc_raw_socket_out > 0) {
        close(tc_raw_socket_out);
        tc_raw_socket_out = -1;
    }

#if (GRYPHON_PCAP_SEND)
    tc_pcap_over();
#endif

    if (clt_settings.transfer.mappings != NULL) {

        for (i = 0; i < clt_settings.transfer.num; i++) {
            free(clt_settings.transfer.mappings[i]);
        }

        free(clt_settings.transfer.mappings);
        clt_settings.transfer.mappings = NULL;
    }

    if (clt_settings.mem_pool != NULL) {
        free(clt_settings.mem_pool);
        clt_settings.mem_pool = NULL;
    }
}

void
gryphon_over(const int sig)
{
    tc_over = sig;
}

static bool send_version(int fd) {
    msg_client_t    msg;

    memset(&msg, 0, sizeof(msg_client_t));
    msg.client_ip = htonl(0);
    msg.client_port = htons(0);
    msg.type = htons(INTERNAL_VERSION);

    if (tc_socket_send(fd, (char *) &msg, MSG_CLIENT_SIZE) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "send version error:%d", fd);
        return false;
    }

    return true;
}

static int
connect_to_server(tc_event_loop_t *event_loop)
{
    int                    i, j, fd;
    uint32_t               target_ip;
    uint16_t               target_port;
    connections_t         *connections;

    /* 
     * add connections to the real servers for sending router info 
     * and receiving response packet
     */
    for (i = 0; i < clt_settings.real_servers.num; i++) {

        target_ip = clt_settings.real_servers.ips[i];
        target_port = clt_settings.real_servers.ports[i];
        if (target_port == 0) {
            target_port = clt_settings.srv_port;
        }

        if (clt_settings.real_servers.active[i] != 0) {
            continue;
        }

        connections = &(clt_settings.real_servers.connections[i]);
        for (j = 0; j < connections->num; j++) {
            fd = connections->fds[j];
            if (fd > 0) {
                tc_log_info(LOG_NOTICE, 0, "it close socket:%d", fd);
                tc_socket_close(fd);
                tc_event_del(clt_settings.ev[fd]->loop, 
                        clt_settings.ev[fd], TC_EVENT_READ);
                tc_event_destroy(clt_settings.ev[fd], 0);
                connections->fds[j] = -1;
            }
        }

        clt_settings.real_servers.connections[i].num = 0;
        clt_settings.real_servers.connections[i].remained_num = 0;

        for (j = 0; j < clt_settings.par_connections; j++) {
            fd = tc_message_init(event_loop, target_ip, target_port);
            if (fd == TC_INVALID_SOCKET) {
                return TC_ERROR;
            }

            if (!send_version(fd)) {
                return TC_ERROR;
            }

            if (j == 0) {
                clt_settings.real_servers.active_num++;
                clt_settings.real_servers.active[i] = 1;
            }

            clt_settings.real_servers.connections[i].fds[j] = fd;
            clt_settings.real_servers.connections[i].num++;
            clt_settings.real_servers.connections[i].remained_num++;

        }

        tc_log_info(LOG_NOTICE, 0, "add dr tunnels for exchanging info:%u:%u",
                target_ip, target_port);
    }

    return TC_OK;


}


/* initiate TCPCopy client */
int
gryphon_init(tc_event_loop_t *event_loop)
{
    int      i;
    uint64_t pool_size;

    /* register some timer */
    tc_event_timer_add(event_loop, 60000, check_resource_usage);

    if (connect_to_server(event_loop) == TC_ERROR) {
        return TC_ERROR;
    }

    if (tc_send_init(event_loop) == TC_ERROR) {
        return TC_ERROR;
    }

    for (i = 0; i < clt_settings.num_pcap_files; i++) {
        calculate_mem_pool_size(clt_settings.pcap_files[i].file, 
                clt_settings.filter);
    }

    tc_log_info(LOG_NOTICE, 0, "pool size:%llu", clt_settings.mem_pool_size);

    pool_size = clt_settings.mem_pool_size;
    if (clt_settings.mem_pool_size > 0) {
        clt_settings.mem_pool = (unsigned char *) calloc(pool_size, 
                sizeof(unsigned char));
        if (clt_settings.mem_pool == NULL) {
            return TC_ERROR;
        }
    }

    for (i = 0; i < clt_settings.num_pcap_files; i++) {
        read_packets_from_pcap(clt_settings.pcap_files[i].file, 
                clt_settings.filter);
    }

    tc_log_info(LOG_NOTICE, 0, "pool used:%llu", clt_settings.mem_pool_index);

    tc_event_timer_add(event_loop, 5000, tc_interval_dispose); 

    return TC_OK;
}

