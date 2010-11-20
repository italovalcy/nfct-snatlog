#include "list.h"

#include <stdlib.h>

void list_add(struct conntrack_list **head, struct conntrack_list *no) {
   if (!*head) {
      *head = no;
      (*head)->prev = no;
      (*head)->next = no;
      return;
   }
   (*head)->prev->next = no;
   no->prev = (*head)->prev;
   (*head)->prev = no;
   no->next = *head;
}

void list_del(struct conntrack_list **head, struct conntrack_list *no) {
   if (!(*head) || !no) {
      return;
   }

   no->prev->next = no->next;
   no->next->prev = no->prev;

   if (*head == no) {
      if (no == no->next) {
         *head = NULL;
      } else {
         *head = (*head)->next;
      }
   }

   free(no);
}

struct conntrack_list *list_find(struct conntrack_list *head,
      u_int32_t id,
      u_int32_t orig_ipv4_src,
      u_int16_t orig_port_src) {
   struct conntrack_list *it;

   it = head;
   if (!it)
      return NULL;

   do {
      if (it->id == id &&
            it->orig_ipv4_src == orig_ipv4_src &&
            it->orig_port_src == orig_port_src)
         return it;
      it = it->next;
   } while (it!=head);

   return NULL;
}
