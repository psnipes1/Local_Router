  /* Swarthmore College, CS 43, Lab 7
 * Copyright (c) 2019 Swarthmore College Computer Science Department,
 * Swarthmore PA
 * Professor Vasanta Chaganti
 *
 * Parker Snipes and Kendre Thomas.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Note: sr_send_packet will send a buffer out on the wire immediately.
 * It's defined in sr_vns_comm.c with the following format:

int sr_send_packet(struct sr_instance* sr,
                         uint8_t* buf,
                         unsigned int len,
                         const char* iface)

 * The passed in buffer should include everything that needs to go on the wire,
 * including the ethernet headers, so don't call this until you have all the
 * necessary information (e.g., you know the MAC address of the destination. */


/*---------------------------------------------------------------------

 * Function: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
/* You probably don't need to change this. */
void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

} /* -- sr_init -- */

/* Function: ether_to_me:
 * returns 1 if this local router should process this ethernet packet
 * (if it is to this address or to broadcast)
 * You shouldn't need to change this.
 */
int ether_to_me(unsigned char* my_address, unsigned char* addr_s){
    unsigned char * addr = (unsigned char *)addr_s;
    return ((memcmp(my_address,addr_s,ETHER_ADDR_LEN)==0) ||
            ((addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff));
}

/*---------------------------------------------------------------------
 * Function: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This function is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the function call.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    struct sr_if *incoming_interface;
    uint8_t *quad;

    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    /* incoming_interface has a field named 'addr', which tells you the MAC
     * address of the interface that received the packet.  You can use that,
     * along with ether_to_me to determine whether or not this packet is
     * relevant to your router. */
    incoming_interface = sr_get_interface(sr, interface);
    quad = (uint8_t *) &incoming_interface->ip;

    printf("*** -> Received packet of length %d on interface %s (%d.%d.%d.%d.)\n",
        len, interface, quad[0], quad[1], quad[2], quad[3]);

    // TODO:
    // verify that the ethernet frame has a valid length
    // drop the packet if it does not apply to this interface
    // determine whether the packet is IP or ARP, and if so,
    // handle the payload with handle_ip() and handle_arp(), respectively
    // if the packet is neither IP nor ARP, drop.


    struct sr_ethernet_hdr* ehdr = (struct sr_ethernet_hdr *) packet;

    int right_dest = ether_to_me(incoming_interface->addr,ehdr->ether_dhost);

    if(right_dest != 1){
      printf("Packet wasn't destined for this router.\n");
      return;
    }

    if(len<sizeof(struct sr_ethernet_hdr)){
      printf("Length of packet ethernet_hdr: %ld\n",sizeof(struct sr_ethernet_hdr));
      printf("We dropped the packet we just got.\n");
      return;
    }


    if(ehdr -> ether_type == htons(ethertype_arp)){
      printf("The packet we just got was an arp packet.\n");
      //print_hdr_arp(packet);
      uint8_t * packet_without_header = packet+sizeof(struct sr_ethernet_hdr);
      handle_arp(sr, packet_without_header, len-sizeof(struct sr_ethernet_hdr), interface);
    }
    else if(ehdr-> ether_type == htons(ethertype_ip)){
    //print_hdr_ip(packet);
    printf("The packet we just got was an ip packet.\n");
    uint8_t * packet_without_header = packet+sizeof(struct sr_ethernet_hdr);
    handle_ip(sr, packet_without_header, len-sizeof(struct sr_ethernet_hdr), interface);
    }
    else{
      //Drop packet.
      return;
    }

    /* Note: To drop a packet, simply return from this function without taking
     * any further action. */
}

/* Given a destination, it looks up the interface to forward it out.
 * You shouldn't need to change this. */
struct sr_if * router_lookup_interface_via_ip(struct sr_instance * sr, uint32_t dst)
{
    /* Use rtable_find_route to find route, then look up sr_if based on route
     * interface's name. */
    struct sr_rt * route = rtable_find_route(sr,dst);
    if( !route ) {
        Debug("no route for this IP\n");
        return 0; /* don't have a route for this IP */
    }
    return sr_get_interface(sr,route->interface);

}

/* This packet is either an arp request and we are responsible for replying
 * with our ethernet address or this is an arp reply hopefully to a request we
 * have sent out, in which case we add the entry to our cache. */
int handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
    struct sr_arp_hdr * arp_header;
    struct sr_if * intf;
    struct sr_arpreq * req;
    //uint32_t this_interface_ip;

    arp_header = (struct sr_arp_hdr *) packet;
    intf = sr_get_interface(sr, interface);

    /* ARP request or reply? */
    switch (ntohs(arp_header->ar_op))
    {
        case arp_op_request:
            // TODO:
            // handle this ARP request by sending a reply if necessary.
            // This will entail:
            // verify that the request is for the correct local interface
            // allocate space to store the response
            // set the fields in the ethernet header
            // set the fields in the arp header
            // call sr_send_packet() with the correct buffer, packet length,
            //      and interface

            //this_interface_ip = intf->ip;

            if(ip_to_me(sr,arp_header->ar_tip)!=1){
              printf("Packet wasn't meant for me, in handle_arp\n");
              return -1;
            }

            //printf("We just made it past ip_to_me in handle_arp\n");

            uint8_t* response = malloc(sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arp_hdr));
            //printf("Size of ethernet_hdr+arp_hdr: %d. Size of response: %d. Size of response*: %d\n",a,b,c);

            struct sr_ethernet_hdr* response_hdr = (struct sr_ethernet_hdr*) response;

            memset(response,0,sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arp_hdr));

            memcpy(response_hdr->ether_dhost,arp_header->ar_sha,ETHER_ADDR_LEN);
            //response->ether_dhost = htons(arp_header->ar_sha);
            memcpy(response_hdr->ether_shost,intf->addr,ETHER_ADDR_LEN);
            //response->ether_shost = htons(intf->addr);
            response_hdr->ether_type = htons(ethertype_arp);
            uint8_t* payload = response+sizeof(struct sr_ethernet_hdr);
            struct sr_arp_hdr* payload_hdr = (struct sr_arp_hdr*) payload;
            memcpy(payload_hdr->ar_sha, intf->addr, ETHER_ADDR_LEN);
            //payload->ar_sha = htons(arp_header->ar_sha);
            memcpy(payload_hdr->ar_tha,arp_header->ar_sha, ETHER_ADDR_LEN);
            payload_hdr->ar_tip = arp_header-> ar_sip;
            payload_hdr->ar_sip = intf->ip;
            payload_hdr->ar_hrd = arp_header->ar_hrd;
            payload_hdr->ar_hln = arp_header->ar_hln;
            payload_hdr->ar_pln = arp_header->ar_pln;
            payload_hdr->ar_op = htons(arp_op_reply); //might be different? Not sure.
            payload_hdr->ar_pro = arp_header->ar_pro;

            print_hdr_arp(payload);

            //printf("We handled an arp request. Size of response: %ld\n",sizeof(response));
            sr_send_packet(sr,response,sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arp_hdr),interface);
            //printf("We just sent a response packet.\n");
            free(response);

            break;
        case arp_op_reply:
          //printf("We handled an arp reply\n");

            // Store the arp reply in the router's arp cache
            req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);

            // If there are packets queued up for which we can now resolve the address,
            // send them.

            if(req!=NULL){
              struct sr_packet* next = req->packets;
              while(next!=NULL){
                struct sr_ethernet_hdr* hdr = (struct sr_ethernet_hdr*) next->buf;
                memcpy(hdr->ether_dhost,arp_header->ar_sha,ETHER_ADDR_LEN);
                sr_send_packet(sr,(uint8_t*)next->buf,next->len,next->iface);
                next = next->next;
              }
          }

            break;
        default:
            Debug("dropping unhandleable ARP packet\n");
    }
    return 0;
}

int handle_ip(struct sr_instance *sr, uint8_t * packet,unsigned int len,char * interface)
{
    struct sr_ip_hdr * hdr = (struct sr_ip_hdr *)packet;
/* Not sure if we need this "size checking."
    if(sizeof(hdr) < sizeof(struct sr_ip_hdr)){
      printf("Packet we just got in handle_ip is badly formed!");
      return -1;
    }
*/
    //TODO: TTL's and other things from Piazza.
    uint16_t sum = hdr->ip_sum;
    if(sum!= checksum_ip(hdr)){
      printf("Dropping packet; bad checksum.\n");
      printf("Checksum: %d. Expected value: %d\n",sum,checksum_ip(hdr));
      return -1;
    }

    struct sr_if* incoming_interface = sr_get_interface(sr, interface);
    //Not sure if we want this

    hdr->ip_ttl--;

    if(hdr->ip_ttl <= 0){
      printf("Sending ICMP TTL Exceeded\n");
      icmp_send(sr,hdr->ip_src,incoming_interface->ip,packet,len,ICMP_TYPE_TIME_EXCEEDED,ICMP_CODE_TTL_EXPIRED,0,0);
      return -1;
    }




    if(ip_to_me(sr,hdr->ip_dst)){
      if(hdr->ip_p==IP_PROTO_ICMP){
        struct sr_icmp_hdr* icmp_hdr = (struct sr_icmp_hdr*) (packet+sizeof(struct sr_ip_hdr));
        //printf("Handling IP to me\n");
        if(icmp_hdr->icmp_type == ICMP_TYPE_ECHO_REQUEST){
          icmp_handle_packet(sr,packet,len);
        }
        else{
          printf("ICMP type: %d\n",icmp_hdr->icmp_type);
          printf("Just got a packet that wasn't an echo request\n");
        }
      }
      else{
        printf("We just sent a DEST UNREACHABLE:PROTO packet.\n");
        icmp_send(sr,hdr->ip_src,incoming_interface->ip,packet,len,ICMP_TYPE_DEST_UNREACH,ICMP_CODE_PROTO_UNREACH,0,0);
      }
    }
    else{
      //printf("Handling IP not to me\n");
      checksum_ip(hdr);
      int result = router_send_ethernet_frame(sr, hdr->ip_dst,htons(ethertype_ip),packet,len);
      if(!result){
        printf("We just sent ICMP Host Unreachable\n");
        //printf("Incoming interface IP: %d",incoming_interface->ip);
        icmp_send(sr,hdr->ip_src,incoming_interface->ip,packet,len,ICMP_TYPE_DEST_UNREACH,ICMP_CODE_HOST_UNREACH,0,0);
      }
    }
      return 0;


    }

    // Handle packets to this router: the only packets specifically
    // addressed to this router that you should respond to are ICMP Ping
    // messages. All other data packets should receive an error response
    // stating that the protocol is unreachable.

    //  handle packets NOT addressed to this router. This will require
    // routing them or dropping them based on the TTL. If a packet is dropped
    // due to TTL, send an ICMP TTL expired message. If a packet is to be
    // forwarded, fix its TTL and checksum here.


/* Compute a checksum for an IP header.  You shouldn't need to change this. */
uint16_t checksum_ip(struct sr_ip_hdr * hdr ) {
    hdr->ip_sum = 0;
    hdr->ip_sum = checksum( (uint16_t*)hdr, IPV4_HEADER_LEN );
    return hdr->ip_sum;
}

/* Compute a checksum for an arbitrary buffer, given a size.  You shouldn't
 * need to change this. */
uint16_t checksum(uint16_t* buf, unsigned len) {
    uint16_t answer;
    uint32_t sum;

    /* add all 16 bit pairs into the total */
    answer = sum = 0;
    while( len > 1 ) {
        sum += *buf++;
        len -= 2;
    }

    /* take care of the last lone uint8_t, if present */
    if( len == 1 ) {
        *(unsigned char *)(&answer) = *(unsigned char *)buf;
        sum += answer;
    }

    /* fold any carries back into the lower 16 bits */
    sum = (sum >> 16) + (sum & 0xFFFF);    /* add hi 16 to low 16 */
    sum += (sum >> 16);                    /* add carry           */
    answer = ~sum;                         /* truncate to 16 bits */

    return answer;
}

/* Allocates memory for an ICMP message, fills in the header fields, and calls
 * one of two appropriate functions to encapsulate it in a packet and send it
 * on its way. */
void icmp_send(struct sr_instance * router,
        uint32_t dst,
        uint32_t src,
        uint8_t* ip_packet, /* or just the data to send back */
        unsigned len,
        uint8_t type,
        uint8_t code,
        uint16_t id,
        uint16_t seq) {
    // allocate an ICMP message and fill in the headers with the given
    // parameters.

    uint8_t* buf = malloc(sizeof(struct sr_icmp_hdr)+ICMP_DATA_SIZE);
    memset(buf,0,sizeof(struct sr_icmp_hdr)+ICMP_DATA_SIZE);
    struct sr_icmp_hdr* hdr = (struct sr_icmp_hdr*) buf;
    //Fill out this packet.
    hdr->icmp_type = type;
    hdr->icmp_code = code;
    memcpy(buf+sizeof(struct sr_icmp_hdr),ip_packet,ICMP_DATA_SIZE);
    hdr->icmp_sum = checksum((uint16_t*) buf,sizeof(struct sr_icmp_hdr)+ICMP_DATA_SIZE);
    hdr->icmp_id = id;
    hdr->icmp_seq = seq;

      if (src) {
          /* If we we're given the source, call ip_send_packet_from, which lets
           * us specify the src address. */

           ip_send_packet_from(router, dst, src, IP_PROTO_ICMP, buf, sizeof(struct sr_icmp_hdr)+ICMP_DATA_SIZE);
      } else {
          /* If we weren't given the source, it means this router *is* the
           * source. Call ip_send_packet, which will figure out which of the
           * router's interfaces to sent it out, and use that interface's IP
           * address as the source. */
          printf("Router just sent a packet\n");
          ip_send_packet(router,dst, IP_PROTO_ICMP, buf, sizeof(struct sr_icmp_hdr)+ICMP_DATA_SIZE);
      }
      free(buf);
    }



/* Sends an IP packet from this router.  Given the destination of the packet,
 * it looks up which of its own IP addresses it should use as the source
 * address and then calls ip_send_packet_from() to craft the packet.
 * Returns 0 on success, non-zero on failure.
 * You shouldn't need to change this. */
int ip_send_packet(struct sr_instance * router,
        uint32_t dst,
        uint8_t proto_id,
        uint8_t* payload,
        unsigned len ) {
    struct sr_if * intf;
    uint32_t found_src;
    uint8_t * quad = (uint8_t*)&dst;
    int result = 0;

    //TODO: Set fields of payload.

    /* lookup the src address we'll send from to get to dst */
    // outgoing interface
    intf = router_lookup_interface_via_ip(router, dst);
    if(intf) {
        // outgoing interface's IP
        found_src = intf->ip;
        result = ip_send_packet_from(router, dst, found_src, proto_id, payload, len);
    }

    /* couldn't route to dst */
  printf( "Error: unable to find route in ip_send_packet for %u.%u.%u.%u\n",quad[0],quad[1],quad[2],quad[3] );

    return result;
}


/* Walks the list of local interfaces and returns True if the destination
 * matches one of them (i.e., it's destined for this router). You shouldn't
 * need to change this. */
int ip_to_me(struct sr_instance * sr, uint32_t dst)
{
    struct sr_if* if_walker = sr->if_list;
    while(if_walker)
    {
        if (if_walker->ip ==dst)
            return 1;
        if_walker = if_walker->next;
    }
    return 0;
}

/* Sends back an ICMP echo (ping) reply upon receiving a ping request.
 * You shouldn't need to change this function. */
void icmp_handle_packet(struct sr_instance * router,
        uint8_t* ip_packet,
        unsigned len ) {
    struct sr_ip_hdr *  hdr_ip;
    sr_icmp_hdr_t* hdr;
    unsigned headers_len;
    unsigned icmp_packet_len;
    uint16_t old_sum;

    hdr = (sr_icmp_hdr_t*)(ip_packet + sizeof(struct sr_ip_hdr));
    icmp_packet_len = len - sizeof(struct sr_ip_hdr);

    /* We assume only ICMP echo messages are the only thing we'll receive. */
    if( hdr->icmp_type != ICMP_TYPE_ECHO_REQUEST ) {
        Debug( "%s only Echo Request and Reply is handled (received type %u)",
                "ICMP packet dropped:",
                hdr->icmp_type );
        return;
    }

    printf("We've set the header in icmp_handle_packet.\n");

    /*  Do a checkum, and throw it out if the checksum fails. */
    old_sum = hdr->icmp_sum;
    if(old_sum != checksum_icmp(hdr, icmp_packet_len) ) {
        Debug( "%s checksum %u is incorrect:: should be %u",
                "ICMP packet dropped:",
                old_sum,
                hdr->icmp_sum );
        return;
    }

    /* Determine how much data came with the request */
    headers_len = sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr);

    /* Send the echo reply back to sender from us (swapped dst/src fields) */
    hdr_ip = (struct sr_ip_hdr*)ip_packet;
    icmp_send( router,
            hdr_ip->ip_src, hdr_ip->ip_dst,
            ip_packet+headers_len, len - headers_len,
            ICMP_TYPE_ECHO_REPLY, 0, hdr->icmp_id, hdr->icmp_seq);
}

/* Compute a checksum for ICMP.  You shouldn't need to change this. */
uint16_t checksum_icmp(sr_icmp_hdr_t* icmp_hdr, unsigned total_len) {
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = checksum( (uint16_t*)icmp_hdr, total_len );
    return icmp_hdr->icmp_sum;
}

/* Allocates memory for a packet, fills in the header fields, and calls
 * router_send_ethernet_frame() to get the packet on its way. */
int ip_send_packet_from( struct sr_instance* router,
        uint32_t dst,
        uint32_t src,
        uint8_t proto_id,
        uint8_t* buf,
        unsigned len ) {

    int ret = 0;

    uint8_t* payload= malloc(sizeof(struct sr_ip_hdr)+len);
    memset(payload,0,sizeof(struct sr_ip_hdr)+len);

    sr_ip_hdr_t * hdr= (sr_ip_hdr_t*) payload; //ip header

    hdr->ip_src= src;
    hdr->ip_dst= dst;
    hdr->ip_len = htons(sizeof(struct sr_ip_hdr)+len);
    hdr->ip_v=4;
    hdr->ip_hl = 5;
    hdr->ip_id =0;
    hdr->ip_ttl=64;
    hdr->ip_p= proto_id;
    hdr->ip_off=0;
    hdr->ip_tos=0;

    uint16_t sum=checksum_ip(hdr);
    sum++;


    memcpy(payload+sizeof(struct sr_ip_hdr), buf, len);

    //printf("Calling router_send_ethernet_frame from ip_send_packet_from\n");
    ret = router_send_ethernet_frame(router,dst, htons(ethertype_ip),payload,sizeof(struct sr_ip_hdr)+len);
    // TODO: allocate space for an IP packet and fill in the
    // appropriate fields and payload.

    // TODO: use router_send_ethernet_frame to send the packet on its way.
    // ret = router_send_ethernet_frame(...);
    free(payload);

    return ret;
}

/* Given a routing table and destination IP address, this function should
 * return the interface out which you'd send to reach that destination. */
struct sr_rt * rtable_find_route(struct sr_instance * sr, uint32_t dst_ip)
{
    // find the best route in your routing table for a given
    // IP address. The current implementation stores the available routes
    // unordered in the routing table, so you will have to iterate over
    // its linked list and find the best route. The first entry
    // in the routing table is stored at sr->routing_table.  Its type is
    // sr_rt, which has the following fields (defined in sr_rt.h):
    /*


    struct sr_rt {
        struct in_addr dest;
        struct in_addr gw;
        struct in_addr mask;
        char   interface[sr_IFACE_NAMELEN];
        struct sr_rt* next;
    };
    */
    // 'next' points to the next item in the linked list of table entires.

    // Assuming you find a valid route, this function should return a pointer
    // to the sr_rt struct that best corresponds to the destination.

    /* Return NULL if we didn't find a match. */

    struct sr_rt* rtable = sr->routing_table;
    if(rtable->dest.s_addr == dst_ip){
      return rtable;
    }
    while(rtable->next !=NULL){
      if(rtable->next->dest.s_addr == dst_ip){
        printf("We found a route in the rtable!\n");
        return rtable->next;
      }
      rtable = rtable->next;
    }
    return NULL;
}

/* Given a packet and destination, this finds the interface to use and calls
 * router_queue_ethernet_frame to queue it for sending.  You shouldn't need
 * to change this. */
int router_send_ethernet_frame( struct sr_instance * router,
        uint32_t dst_ip,
        uint16_t type,
        uint8_t* payload,
        unsigned len ) {
    struct sr_rt * rti;
    struct sr_if * intf;
    /* lookup which route to use */
    rti = rtable_find_route( router, dst_ip );
    if( !rti ) {
        Debug("no route for this IP\n");
        return 0; /* don't have a route for this IP */
    }
    intf = sr_get_interface(router,rti->interface);
    router_queue_ethernet_frame(router, rti,intf, type, payload, len );
    return 1;
}

/* Craft an ethernet frame (buf) by encapsulating the given payload.
 * Do a check to see if we have all the relevant information (namely, the
 * destination MAC address) to send the packet.  If so, send it.  If not
 * queue it until we can resolve the destination MAC via ARP. */
int router_queue_ethernet_frame(struct sr_instance * sr,
        struct sr_rt * rti,
        struct sr_if * intf,
        uint16_t type,
        uint8_t* payload,
        unsigned payload_len ) {

    struct sr_arpentry *arp_entry;
    struct sr_arpreq * req;
    uint8_t * buf;
    int len = sizeof(struct sr_ethernet_hdr)+payload_len;

    buf = malloc(sizeof(struct sr_ethernet_hdr)+payload_len);
    memset(buf,0,sizeof(struct sr_ethernet_hdr)+payload_len);

    sr_ethernet_hdr_t * ethernet_hdr= (sr_ethernet_hdr_t *) buf;

    memcpy(buf+sizeof(struct sr_ethernet_hdr),payload,payload_len);

    memcpy(ethernet_hdr->ether_shost,intf->addr,ETHER_ADDR_LEN*sizeof(uint8_t));
    ethernet_hdr->ether_type = type;


    arp_entry = sr_arpcache_lookup(&sr->cache, rti->gw.s_addr);
    if(arp_entry)
    {

      memcpy(ethernet_hdr->ether_dhost,arp_entry->mac,ETHER_ADDR_LEN*sizeof(uint8_t));

        //
        // at this point in the code, an ARP cache entry has been
        // found for the destination IP.  Send the packet immediately.

        // sr_send_packet(...)
        printf("We're about to send an ICMP response to the ping we just got.\n");
        sr_send_packet(sr,buf,len,intf->name);
    } else{
        printf("We don't have the destination MAC address for the packet we wanted to send.\n");
        /* If we don't have an entry in our ARP cache for this destination,
         * we can't send the packet yet, since we don't know who to address it
         * to at the link layer (ethernet).  In this case, we add it to a queue
         * of packets that are waiting for the MAC address to be resolved, and
         * then call handle_arpreq, which will generate and send an ARP
         * request, if necessary. */
        req = sr_arpcache_queuereq(&sr->cache, rti->gw.s_addr, buf, len, intf->name);
        handle_arpreq(sr,req);
    }
    free(buf);
    free(arp_entry);
    return 0;
}


/* This function is called:
 * 1) By router_queue_ethernet_frame() above when it goes to send a frame and discovers
 * that it does not already know the MAC address of the destination.
 * 2) Every ~1 second by a thread that sweeps through every entry in the cache.
 *
 * struct sr_arpreq is defined in sr_arpcache.h as:
 *
 * struct sr_arpreq {
    uint32_t ip;
    time_t sent;                   Last time this ARP request was sent. You
                                   should update this. If the ARP request was
                                   never sent, will be 0.
    uint32_t times_sent;           Number of times this request was sent. You
                                   should update this.
    struct sr_packet *packets;     List of pkts waiting on this req to finish
    struct sr_arpreq *next;
 */
int handle_arpreq(struct sr_instance * sr,struct sr_arpreq * req)
{
    /* You shouldn't need to worry about the locking of this structure.  In case you're
     * digging around and looking at this lock, it's initialized as a recursive pthread
     * mutex, so don't panic if it looks like it's being locked multiple times by the
     * same thread, that's ok as long as it does an equal number of unlocks. */
    pthread_mutex_lock(&(sr->cache.lock));



    /* TODO: check the given cache entry.  If one or more seconds have passed
     * since the last time we looked at this entry, check to see how many times
     * we've tried.  If it's less than 5, send an ARP request.  If we've sent
     * it five times, give up on getting a response and send an ICMP
     * unreachable message to the source of any packets queued on the request.
     *
     * Pseudocode sketch:
        if difftime(now, req->sent) > 1.0:
            if req->times_sent >= 5:
                send icmp host unreachable to src addr of pkts waiting on request
                arpreq_destroy(req)
            else:
                generate and send arp request
                req->sent = now
                req->times_sent++
     */

     time_t current_time;
     time(&current_time);
     int difftime = (current_time-req->sent);
     //printf("Difftime for packets we're sending: %d\n",difftime);
     if(difftime > 1.0){
       if(req->times_sent >= 5){
         //printf("We've sent more than 5 times.\n");
         struct sr_packet* next = req->packets;
         while(next!= NULL){
         //icmp_send(next->buf->ether_shost,)

         struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*) (next->buf+sizeof(struct sr_ethernet_hdr));
         icmp_send(sr, ip_hdr->ip_src,0,next->buf,next->len,ICMP_TYPE_DEST_UNREACH,ICMP_CODE_HOST_UNREACH, 0, 0);
         next = next->next;
       }
       sr_arpreq_destroy(&(sr->cache), req);
     }
       else{
         //printf("Starting to send an arp req packet in handle_arpreq\n");
         struct sr_packet* next = req->packets;
         struct sr_if* intf;
           uint8_t* packet = malloc(sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arp_hdr));
           memset(packet,0,sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arp_hdr));
           intf = sr_get_interface(sr,req->packets->iface);
           struct sr_ethernet_hdr* ehdr = (struct sr_ethernet_hdr*) packet;
           struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*) (packet+sizeof(struct sr_ethernet_hdr));
           memcpy(ehdr->ether_shost,intf->addr,ETHER_ADDR_LEN);
           memset(ehdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
           ehdr->ether_type = htons(ethertype_arp);
           memset(arp_hdr->ar_tha,0xff,ETHER_ADDR_LEN);
           arp_hdr->ar_op = htons(arp_op_request);
           memcpy(arp_hdr->ar_sha,intf->addr,ETHER_ADDR_LEN);
           arp_hdr->ar_sip = intf->ip;
           arp_hdr->ar_tip = req->ip;
           arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
           arp_hdr->ar_pro = htons(ethertype_ip);
           arp_hdr->ar_hln = ETHER_ADDR_LEN;
           arp_hdr->ar_pln = 4;
           printf("Sending an arp request because we didn't have the client's MAC address\n");
           sr_send_packet(sr,packet,sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arp_hdr),next->iface);
           //printf("We just sent a packet.\n");
           free(packet);
           time_t now;
           time(&now);
           req->sent = now;
           req->times_sent++;
       }
   }
    pthread_mutex_unlock(&(sr->cache.lock));
    return 0;
}
