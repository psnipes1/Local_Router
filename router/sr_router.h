/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"


#define min(a,b) ( (a) < (b) ? (a) : (b) )

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/** number of uint8_ts in the Ethernet header (dst MAC + src MAC + type) */
#define ETH_HEADER_LEN 14

/** max uint8_ts in the payload (usually 1500B, but jumbo may be larger */
#define ETH_MAX_DATA_LEN 2048

/** max uint8_ts in the Ethernet frame (header + data uint8_ts) */
#define ETH_MAX_LEN (ETH_HEADER_LEN + ETH_MAX_DATA_LEN)

/** min uint8_ts in the Ethernet frame */
#define ETH_MIN_LEN 60

#define IPV4_HEADER_LEN 20

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* helper function to determine if an ethernet frame is addressed to a given
 * interface's MAC address
 */
int ether_to_me(unsigned char* my_address, unsigned char* addr_s);

/* call this to consume an ARP packet */
int handle_arp(struct sr_instance * sr, uint8_t * packet, unsigned int len, char * interface);

/* call this to route/consume an ip packet */
int handle_ip(struct sr_instance *sr, uint8_t * packet,unsigned int len,char * interface);

/* call this to compute and set the ip header checksum */
uint16_t checksum_ip( struct sr_ip_hdr * hdr );

/* call this to compute a checksum over len bites starting at buf */
uint16_t checksum( uint16_t* buf, unsigned len );

/* call this to determine whether an ip is destined for any of the router's
 * interfaces' addresses
 */
int ip_to_me(struct sr_instance * , uint32_t );
/* call this to construct and send an ICMP packet */
void icmp_send(struct sr_instance * router,
                uint32_t dst,
                uint32_t src,
                uint8_t * ip_packet,
                unsigned len,
                uint8_t type,
                uint8_t code,
				uint16_t id,
				uint16_t seq);

/* call this to compute and set an icmp checksum */
uint16_t checksum_icmp( sr_icmp_hdr_t* icmp_hdr, unsigned total_len );

/* call this to consume an ICMP packet destined for this router */
void icmp_handle_packet( struct sr_instance * router, uint8_t* ip_packet, unsigned len );

/*
 * call this to create and send an IP packet (for this router, this will
 * mainly be used to send ICMP packets)
 */
int  ip_send_packet_from( struct sr_instance *,
                          uint32_t dst,
                          uint32_t src,
                          uint8_t proto,
                          uint8_t* buf,
                          unsigned len );

/*
 * call this to send an IP packet when the outbound address & interface
 * are not known - requires checking routing table
 */
int ip_send_packet(struct sr_instance * router,
                     uint32_t dst,
                     uint8_t proto,
                     uint8_t* payload,
                     unsigned len );

/*
 * determine the route via the outbound ip and then queue the
 * ethernet frame for sending
 */
int router_send_ethernet_frame( struct sr_instance * router,
                                 uint32_t dst_ip,
                                 uint16_t type,
                                 uint8_t* payload,
                                 unsigned len );

/*
 * given a next hop routing decision and an outbound interface,
 * construct an ethernet packet to the correct MAC address -
 * if this exists in the cache the packet can be sent immediately,
 * otherwise it must be queued while the ARP cache resolves the
 * next hop IP address's MAC address.
 */
int  router_queue_ethernet_frame(struct sr_instance * router,
                                     struct sr_rt * rti,
                                     struct sr_if * intf,
                                     uint16_t type,
                                     uint8_t* payload,
                                     unsigned payload_len ) ;

/*
 * given an IP address, find the next hop routing decision's routing table
 * entry
 */
struct sr_rt * rtable_find_route(struct sr_instance * sr, uint32_t ip);


int handle_arpreq(struct sr_instance * sr,struct sr_arpreq * req);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
