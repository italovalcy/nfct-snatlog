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
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define PROGNAME "nfct-snatlog"

enum exittype {
	OTHER_PROBLEM = 1,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM
};

static struct nfct_handle *cth;

static int event_cb(enum nf_conntrack_msg_type type,
		    struct nf_conntrack *ct,
		    void *data) {
   if (!nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT))
      return NFCT_CB_CONTINUE;

   switch(type) {
      case NFCT_T_NEW:
         printf("[NEW] ");
         break;
      case NFCT_T_DESTROY:
         printf("[DESTROY] ");
         break;
      default:
         break;
   }
   //printf(" id=%u\n",ct->id);
   printf("\n");

   return NFCT_CB_CONTINUE;
}

static void event_sighandler(int s) {
   nfct_close(cth);
   exit(EXIT_SUCCESS);
}

void exit_error(enum exittype status, const char *msg) {
   fprintf(stderr,"[ERROR] %s :: %s\n",PROGNAME, msg);
   exit(status);
}

int main(int argc, char *argv[]) {

   cth = nfct_open(CONNTRACK,
         NF_NETLINK_CONNTRACK_NEW|NF_NETLINK_CONNTRACK_DESTROY);
   
   if (!cth)
		exit_error(OTHER_PROBLEM, "Can't open handler");

   signal(SIGINT, event_sighandler);
	signal(SIGTERM, event_sighandler);
	
   nfct_callback_register(cth, NFCT_T_NEW|NFCT_T_DESTROY, event_cb, NULL);

   if (nfct_catch(cth) == -1) {
      fprintf(stderr, "ERROR: %s\n", strerror(errno));
   }

   nfct_close(cth);

   return EXIT_SUCCESS;
}
