#ifndef _LIST_H_
#define _LIST_H_

#include <sys/types.h>
#include <time.h>

struct conntrack_list {
   struct conntrack_list *prev, *next;
   u_int32_t id;
   u_int32_t orig_ipv4_src;
   u_int16_t orig_port_src;
   time_t timestamp;
};

void list_add(struct conntrack_list **head, struct conntrack_list *no);
void list_del(struct conntrack_list **head, struct conntrack_list *no);
struct conntrack_list *list_find(struct conntrack_list *head,
      u_int32_t id,
      u_int32_t orig_ipv4_src,
      u_int16_t orig_port_src);

#endif
