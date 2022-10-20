#include "queue.h"

Queue *queue_create(void) {
  Queue *q = calloc(sizeof(Queue), 1);
  q->capacity = INITIAL_CAPACITY;
  q->arr = calloc(sizeof(void *) * q->capacity, 1);
  q->pos = 0;
  return q;
}

void queue_push(Queue *q, void *v) {
  if (q->pos + 1 == q->capacity) {
    q->capacity *= 2;
    q->arr = realloc(q->arr, sizeof(void *) * q->capacity);
  }
  q->arr[q->pos++] = v;
}

void *queue_popleft(Queue *q) {
  void *v = q->arr[0];
  for (uint64_t i = 0; i < q->pos - 1; ++i)
    q->arr[i] = q->arr[i + 1];
  // memmove(&q->arr[0], &q->arr[1], sizeof(void *) * (q->pos - 1));
  q->pos--;
  return v;
}

void *queue_front(Queue *q) {
  if (q->pos == 0)
    return NULL;
  return q->arr[q->pos - 1];
}

void queue_free(Queue *q) {
  free(q->arr);
  free(q);
}