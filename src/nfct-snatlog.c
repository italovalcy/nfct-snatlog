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
#include <getopt.h>
#include <syslog.h>
#include <unistd.h>

#include "list.h"

#define PROGNAME "nfct-snatlog"

#define BUF_LEN 1024

#define proto_str(u8_proto) (u8_proto==IPPROTO_TCP) ? "tcp" : "udp"

#define BUFFER_SIZE(ret, size, len, offset)		\
	size += ret;					\
	if (ret > len)					\
		ret = len;				\
	offset += ret;					\
	len -= ret;

static struct nfct_handle *cth;

static u_int8_t debug_flag = 0;
static u_int8_t daemon_flag = 0;

struct conntrack_list *ct_list = NULL;


void usage() {
   printf("Usage: %s [options]\n\n", PROGNAME);
   printf("Options:\n");
   printf("  -s, --daemon\t\t\tRun %s as a daemon.\n", PROGNAME);
   printf("  -d, --debug\t\t\tPrint debug messages.\n");
   printf("  -f, --facility FACILITY\t\tSyslog facility (default: LOCAL4)\n");
   printf("  -h, --help\t\t\tDisplay a short help messsage\n");
   printf("\nFor a more detailed information, see %s(8)\n", PROGNAME);
}

void write_msg(int priority, const char *msg) {
   if (daemon_flag) {
      syslog(priority, msg);
   } else {
      fprintf(priority == LOG_ERR ? stderr : stdout ,"%s\n",msg);
      fflush( priority == LOG_ERR ? stderr : stdout);
   }
}

char * net2addr(u_int32_t u32_addr) {
   struct in_addr addr = { .s_addr = u32_addr};
   return inet_ntoa(addr);
}

int __snprintf_start_log(char *buf, unsigned int len, char *log_type) {
   time_t now;
   int ret, size = 0, offset = 0;

   // if we run in daemon mode, we does not need print
   // the timestamp part... syslog does it for us. Otherwise
   // this code is needed
   if (!daemon_flag) {
      time(&now);
      ret = strftime(buf, len, "%Y-%m-%d %H:%M:%S %z", localtime(&now));
      BUFFER_SIZE(ret, size, len, offset);

      ret = snprintf(buf+offset, len, " %s: ", PROGNAME);
      BUFFER_SIZE(ret, size, len, offset);
   }

   ret = snprintf(buf+offset, len, "[%s]", log_type);
   BUFFER_SIZE(ret, size, len, offset);

   return size;
}

int __str2facility(char *str) {
   if (strcmp(str,"LOCAL0")) return LOG_LOCAL0;
   if (strcmp(str,"LOCAL1")) return LOG_LOCAL1;
   if (strcmp(str,"LOCAL2")) return LOG_LOCAL2;
   if (strcmp(str,"LOCAL3")) return LOG_LOCAL3;
   if (strcmp(str,"LOCAL4")) return LOG_LOCAL4;
   if (strcmp(str,"LOCAL5")) return LOG_LOCAL5;
   if (strcmp(str,"LOCAL6")) return LOG_LOCAL6;
   if (strcmp(str,"LOCAL7")) return LOG_LOCAL7;
   if (strcmp(str,"USER"))   return LOG_USER;
   if (strcmp(str,"DAEMON")) return LOG_DAEMON;
   return -1;
}

void print_snatlog(struct nf_conntrack *ct, 
      time_t *timestamp, char *proto_str) {
   int ret = 0, size = 0, offset = 0, len = BUF_LEN;
   char buf[BUF_LEN];

   ret = __snprintf_start_log(buf, len, "SNAT_LOG");
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " proto=%s", proto_str);
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " orig-src=%s", 
         net2addr(nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " orig-sport=%d", 
         ntohs(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " trans-src=%s", 
         net2addr(nfct_get_attr_u32(ct,ATTR_REPL_IPV4_DST)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " trans-sport=%d", 
         ntohs(nfct_get_attr_u16(ct,ATTR_REPL_PORT_DST)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " dst=%s",
         net2addr(nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_DST)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " dport=%d",
         ntohs(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_DST)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " duration=%.0lfs", 
         difftime(time(NULL),*timestamp));
   BUFFER_SIZE(ret, size, len, offset);

   buf[size+1 > len ? len-1 : size] = '\0';

   write_msg(LOG_INFO, buf);
}

void print_debug(struct nf_conntrack *ct, 
      enum nf_conntrack_msg_type type, char *proto_str) {
   int ret = 0, size = 0, offset = 0, len = BUF_LEN;
   char buf[BUF_LEN];

   ret = __snprintf_start_log(buf, len, "DEBUG");
   BUFFER_SIZE(ret, size, len, offset);

   switch(type) {
      case NFCT_T_NEW:
         ret = snprintf(buf+offset, len, " NEW");
         BUFFER_SIZE(ret, size, len, offset);
         break;
      case NFCT_T_DESTROY:
         ret = snprintf(buf+offset, len, " DESTROY");
         BUFFER_SIZE(ret, size, len, offset);
         break;
      default:
         break;
   }

   ret = snprintf(buf+offset, len, " id=%u", nfct_get_attr_u32(ct,ATTR_ID));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " proto=%s", proto_str);
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " orig-src=%s", 
         net2addr(nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " orig-dst=%s", 
         net2addr(nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_DST)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " orig-sport=%d", 
         ntohs(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " orig-dport=%d", 
         ntohs(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_DST)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " repl-src=%s", 
         net2addr(nfct_get_attr_u32(ct,ATTR_REPL_IPV4_SRC)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " repl-dst=%s", 
         net2addr(nfct_get_attr_u32(ct,ATTR_REPL_IPV4_DST)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " repl-sport=%d", 
         ntohs(nfct_get_attr_u16(ct,ATTR_REPL_PORT_SRC)));
   BUFFER_SIZE(ret, size, len, offset);

   ret = snprintf(buf+offset, len, " repl-dport=%d", 
         ntohs(nfct_get_attr_u16(ct,ATTR_REPL_PORT_DST)));
   BUFFER_SIZE(ret, size, len, offset);

   buf[size+1 > len ? len-1 : size] = '\0';

   write_msg(LOG_INFO, buf);
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

   if (debug_flag) {
      print_debug(ct, type, proto_str(l4proto));
   }

   switch(type) {
      case NFCT_T_NEW:
         no = (struct conntrack_list *)malloc(sizeof(struct conntrack_list));
         no->id = nfct_get_attr_u32(ct,ATTR_ID);
         no->orig_ipv4_src = nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC);
         no->orig_port_src = nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC);
         time(&no->timestamp);
         list_add(&ct_list, no);
         break;
      case NFCT_T_DESTROY:
         no = list_find(ct_list,
               nfct_get_attr_u32(ct,ATTR_ID),
               nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC),
               nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC));
         if (no) {
            print_snatlog(ct, &no->timestamp, proto_str(l4proto));
            list_del(&ct_list,no);
         }
         break;
      default:
         break;
   }

   return NFCT_CB_CONTINUE;
}

static void event_sighandler(int s) {
   nfct_close(cth);
   write_msg(LOG_INFO, PROGNAME " exiting...");
   exit(EXIT_SUCCESS);
}


int main(int argc, char *argv[]) {
   pid_t pid, sid;
   int c, ret;
   char buf[BUF_LEN];
   int syslog_facility = LOG_LOCAL4;

   while (1) {
      static struct option long_options[] = {
         /* Flags */
         {"debug",   no_argument,       0, 'd'},
         {"daemon",  no_argument,       0, 's'},
         {"help",    no_argument,       0, 'h'},
         {"facility",required_argument, 0, 'f'},
         {0, 0, 0, 0}
      };
      /* getopt_long stores the option index here. */
      int option_index = 0;
      
      c = getopt_long (argc, argv, "dshf:",long_options, &option_index);

      if (c == -1)
         break;

      switch(c) {
         case 'd':
            debug_flag = 1;
            break;
         case 's':
            daemon_flag = 1;
            break;
         case 'h':
            usage();
            exit(EXIT_SUCCESS);
            break;
         case 'f':
            syslog_facility = __str2facility(optarg);
            if (syslog_facility == -1) {
               ret = snprintf(buf,BUF_LEN-1,
                     "Invalid syslog facility parameter: %s", optarg);
               buf[ret] = '\0';
               write_msg(LOG_ERR,buf);
               usage();
               exit(EXIT_FAILURE);
            }
            break;
         case '?':
         default:
            usage();
            exit(EXIT_FAILURE);
            break;
      }

   }
 
   if (daemon_flag) {
       setlogmask(LOG_UPTO(LOG_INFO));
       openlog(PROGNAME, LOG_CONS, syslog_facility);

       /* Fork off the parent process */
       pid = fork();
       if (pid < 0) {
           exit(EXIT_FAILURE);
       }
       /* If we got a good PID, then
          we can exit the parent process. */
       if (pid > 0) {
           exit(EXIT_SUCCESS);
       }

       /* Create a new SID for the child process */
       sid = setsid();
       if (sid < 0) {
           /* Log the failure */
           exit(EXIT_FAILURE);
       }

       /* Change the current working directory */
       if ((chdir("/")) < 0) {
           /* Log the failure */
           exit(EXIT_FAILURE);
       }

       /* Close out the standard file descriptors */
       close(STDIN_FILENO);
       close(STDOUT_FILENO);
       close(STDERR_FILENO);
   }

   cth = nfct_open(CONNTRACK,
         NF_NETLINK_CONNTRACK_NEW|NF_NETLINK_CONNTRACK_DESTROY);
   
   if (!cth) {
      ret = snprintf(buf, BUF_LEN-1, "Can't open a ctnetlink handler (%s)", 
            strerror(errno));
      buf[ret] = '\0';
      write_msg(LOG_ERR, buf);
      exit(EXIT_FAILURE);
   }

   signal(SIGINT, event_sighandler);
	signal(SIGTERM, event_sighandler);
	
   nfct_callback_register(cth, NFCT_T_NEW|NFCT_T_DESTROY, event_cb, NULL);

   if (nfct_catch(cth) == -1) {
      ret = snprintf(buf, BUF_LEN-1, "Can't catch events (%s)", 
            strerror(errno));
      buf[ret] = '\0';
      write_msg(LOG_ERR, buf);
   }

   nfct_close(cth);

   return EXIT_SUCCESS;
}
