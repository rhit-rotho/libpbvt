// cc examples/linked-list.c -O2 -Iinclude -lpbvt -o linked-list
// ./linked-list

#include "pbvt.h"

typedef struct Node Node;
typedef struct Node {
  Node *next;
  char val;
} Node;

Node *ll_create(char *s) {
  Node *n = pbvt_calloc(1, sizeof(Node));
  Node *h = n;
  n->next = NULL;
  n->val = *s++;
  pbvt_commit();
  while (*s) {
    n->next = pbvt_calloc(1, sizeof(Node));
    n = n->next;
    n->val = *s++;
    pbvt_commit();
  }
  return h;
}

void ll_append(Node *n1, Node *n2) {
  while (n1->next)
    n1 = n1->next;
  n1->next = n2;
  pbvt_commit();
}

void ll_print(Node *n) {
  printf("\"");
  while (n) {
    printf("%c", n->val);
    n = n->next;
  }
  printf("\"\n");
}

void ll_free(Node *n) {
  while (n) {
    Node *t = n;
    n = n->next;
    pbvt_free(t);
  }
}

int main(int argc, char **argv) {
  pbvt_init();
  // pbvt_debug();

  Node *n1 = ll_create("Hello, world!");
  pbvt_branch_commit("main");

  Commit *c = pbvt_head();
  for (int i = 0; i < 6; ++i)
    c = c->parent;
  pbvt_checkout(c);

  ll_append(n1, ll_create("Joe!"));
  pbvt_branch_commit("alt");

  pbvt_branch_checkout("main");
  printf("State: %.16lx\n", pbvt_head()->hash);
  ll_print(n1);

  pbvt_branch_checkout("alt");
  printf("State: %.16lx\n", pbvt_head()->hash);
  ll_print(n1);

  ll_free(n1);

  // This is currently bugged, since the previous free returned all our pages
  // back to the OS.
  // pbvt_branch_checkout("main");

  pbvt_print("linked-list.dot");
  pbvt_stats();
  pbvt_cleanup();
  return 0;
}