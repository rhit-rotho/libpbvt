#include "queue.h"

queue_t *queue_create(void) {
  queue_t *q = calloc(sizeof(queue_t), 1);
  q->capacity = INITIAL_CAPACITY;
  q->arr = calloc(sizeof(void *) * q->capacity, 1);
  q->pos = 0;
  return q;
}

void queue_push(queue_t *q, void *v) {
  if (q->pos + 1 == q->capacity) {
    q->capacity *= 2;
    q->arr = realloc(q->arr, sizeof(void *) * q->capacity);
  }
  q->arr[q->pos++] = v;
}

void *queue_popleft(queue_t *q) {
  void *v = q->arr[0];
  for (uint64_t i = 0; i < q->pos - 1; ++i)
    q->arr[i] = q->arr[i + 1];
  q->arr[q->pos - 1] = NULL;
  q->pos--;
  return v;
}

void *queue_front(queue_t *q) {
  if (q->pos == 0)
    return NULL;
  return q->arr[q->pos - 1];
}

void queue_free(queue_t *q) {
  free(q->arr);
  free(q);
}