/*
 * (C) 2010 by Italo Valcy <italo@dcc.ufba.br>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Note:
 *	Portions of this code has been stolen from conntrack ;)
 *	Special thanks to the the Netfilter Core Team.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "list.h"

#define PROGNAME "nfct-snatlog"

#define proto_str(u8_proto) (u8_proto==IPPROTO_TCP) ? "tcp" : "udp"

static struct nfct_handle *cth;

struct conntrack_list *ct_list = NULL;

char * net2addr(u_int32_t u32_addr) {
   struct in_addr addr = { .s_addr = u32_addr};
   return inet_ntoa(addr);
}

static int event_cb(enum nf_conntrack_msg_type type,
		    struct nf_conntrack *ct,
		    void *data) {
   struct conntrack_list *no;
   u_int8_t l4proto;

   // we are interested only in SNAT connections
   if (!nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT))
      return NFCT_CB_CONTINUE;

   // We are interested only in TCP/UDP L4 protocols...
   l4proto = nfct_get_attr_u8(ct,ATTR_ORIG_L4PROTO);
   if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP)
      return NFCT_CB_CONTINUE;

   printf("[%s] %s id=%u orig-src=%s orig-dst=%s orig-sport=%d orig-dport=%d "
         "repl-src=%s repl-dst=%s repl-sport=%d repl-dport=%d\n",
         (type==NFCT_T_NEW) ? "NEW" : "DESTROY",
         proto_str(l4proto),
         nfct_get_attr_u32(ct,ATTR_ID),
         net2addr(nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC)),
         net2addr(nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_DST)),
         ntohs(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC)),
         ntohs(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_DST)),
         net2addr(nfct_get_attr_u32(ct,ATTR_REPL_IPV4_SRC)),
         net2addr(nfct_get_attr_u32(ct,ATTR_REPL_IPV4_DST)),
         ntohs(nfct_get_attr_u16(ct,ATTR_REPL_PORT_SRC)),
         ntohs(nfct_get_attr_u16(ct,ATTR_REPL_PORT_DST)));

   switch(type) {
      case NFCT_T_NEW:
         no = (struct conntrack_list *)malloc(sizeof(struct conntrack_list));
         no->id = nfct_get_attr_u32(ct,ATTR_ID);
         no->orig_ipv4_src = nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC);
         no->orig_port_src = nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC);
         no->timestamp = time(NULL);
         list_add(&ct_list, no);
         break;
      case NFCT_T_DESTROY:
         no = list_find(ct_list,
               nfct_get_attr_u32(ct,ATTR_ID),
               nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC),
               nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC));
         if (no) {
            printf("End of a %s SNAT connection: Original_Src: %s/%u "
                  "Translated_Src: %s/%u "
                  "Lifetime: %ld seconds\n",
                  proto_str(l4proto),
                  net2addr(nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC)),
                  ntohs(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC)),
                  net2addr(nfct_get_attr_u32(ct,ATTR_REPL_IPV4_DST)),
                  ntohs(nfct_get_attr_u16(ct,ATTR_REPL_PORT_DST)),
                  time(NULL) - no->timestamp);
            list_del(&ct_list,no);
         }
         break;
      default:
         break;
   }

   fflush(stdout);

   return NFCT_CB_CONTINUE;
}

static void event_sighandler(int s) {
   nfct_close(cth);
   fprintf(stderr, "%s :: finishing...\n",PROGNAME);
   exit(EXIT_SUCCESS);
}

void print_error(const char *msg, int errnum) {
   fprintf(stderr,"[ERROR] %s :: %s (%s)\n",PROGNAME, msg, strerror(errnum));
}

int main(int argc, char *argv[]) {

   cth = nfct_open(CONNTRACK,
         NF_NETLINK_CONNTRACK_NEW|NF_NETLINK_CONNTRACK_DESTROY);
   
   if (!cth) {
      print_error("Can't open a ctnetlink handler", errno);
      exit(EXIT_FAILURE);
   }

   signal(SIGINT, event_sighandler);
	signal(SIGTERM, event_sighandler);
	
   nfct_callback_register(cth, NFCT_T_NEW|NFCT_T_DESTROY, event_cb, NULL);

   if (nfct_catch(cth) == -1) {
      fprintf(stderr, "ERROR: %s\n", strerror(errno));
   }

   nfct_close(cth);

   return EXIT_SUCCESS;
}
