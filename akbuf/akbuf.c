#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>

#include "akbuf.h"

akbuf_ctx *ctx_hash[AKBUF_CTX_HASH_SIZE];
unsigned int ctx_hash_initialized = 0;
unsigned int prng_initialized = 0;

//#define RANDFUNC vanilla_rand /* XXX */
#define RANDFUNC randfunc_inc

//#define AKBUF_DEBUG

#define AK_REALSIZE(size)	(((size) <= GRAIN_SIZE && (size) != 0)? (size) : (((size) | (GRAIN_SIZE - 1)) + 1))
#define CTX_HASH_FN(hnd)	((hnd) & (AKBUF_CTX_HASH_SIZE - 1))

#ifdef AKBUF_TEST
#define AKBUF_DEBUG
#endif

#ifdef AKBUF_DEBUG
void dump_all_ctxs(void)
{
#if 0
  akbuf_ctx *ctx;
  
  printf("dumping ctxs head %.8x:\n", (unsigned int)ctx_head);
  ctx = ctx_head;
  while (ctx != NULL)
  {
    printf("  ctx @ %.8x; handle %.8x bufs %.8x\n", (unsigned int)ctx, (unsigned int)ctx->hnd, (unsigned int)ctx->head);
    ctx = ctx->next;
  }
  printf("end of dump\n");
#endif
}
#endif
unsigned int vanilla_rand(void)
{
  if (prng_initialized == 0)
  {
    struct timeval tv;
    
    gettimeofday(&tv, NULL);
    srand(tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16));
    prng_initialized = 1;
  }
  return rand();
}
static unsigned int cur_ctx;
unsigned int randfunc_inc(void)
{
  if (prng_initialized == 0)
  {
    struct timeval tv;
    
    gettimeofday(&tv, NULL);
    cur_ctx = tv.tv_usec;
    prng_initialized = 1;
  }
  return cur_ctx ++; 
}
void akbuf_panic(unsigned char *file, unsigned int line, unsigned char *from_file, unsigned int from_line, unsigned char *format, ...)
{
  unsigned char msg[2048];
  
  va_list va;
  if (from_file != NULL)
  {
    snprintf(msg, sizeof(msg) - 1, "AKbuf PANIC @ %s:%u (from %s:%u): ", file, line, from_file, from_line); msg[sizeof(msg) - 1] = 0;
  } else
  {
    snprintf(msg, sizeof(msg) - 1, "AKbuf PANIC @ %s:%u: ", file, line); msg[sizeof(msg) - 1] = 0;
  }
  write(2, msg, strlen(msg));
  va_start(va, format);
  vsnprintf(msg, sizeof(msg) - 1, format, va); msg[sizeof(msg) - 1] = 0;
  va_end(va);
  write(2, msg, strlen(msg));
  write(2, "\n", 1);
  _exit(1);
}
akbuf_ctx *akbuf_find_ctx(akbuf_ctxh hnd)
{
  akbuf_ctx *cur;
  
  if (ctx_hash_initialized == 0)
  {
    unsigned int i;
    
    for (i = 0; i < AKBUF_CTX_HASH_SIZE; i ++) ctx_hash[i] = NULL;
    ctx_hash_initialized = 1;
  }
  cur = ctx_hash[CTX_HASH_FN(hnd)];
  while (cur != NULL) { if (cur->hnd == hnd) return cur; cur = cur->next; }
  return NULL;
}
akbuf_ctxh akbuf_new_ctx(void)
{
  akbuf_ctx *new;
  unsigned int idx;
  
  new = malloc(sizeof(*new));
  AKbuf_ASSERT(new != NULL);
  do
  {
    new->hnd = RANDFUNC();
  } while (akbuf_find_ctx(new->hnd) != NULL || new->hnd == AKbuf_INVALID_CTX);
  new->head = NULL;
  new->prev = NULL;
  new->next = ctx_hash[idx = CTX_HASH_FN(new->hnd)];
  if (new->next != NULL) new->next->prev = new;
  ctx_hash[idx] = new;
  return new->hnd;
}
akbuf *akbuf_init(akbuf_ctxh ctxh, AKsize_t _size)
{
  AKsize_t size;
  akbuf *new;
  akbuf_ctx *ctx;
  
  if ((ctx = akbuf_find_ctx(ctxh)) == NULL) AKbuf_PANIC("akbuf_init(): Invalid ctx %.8x", ctxh);
  size = AK_REALSIZE(_size); 
#ifdef AKBUF_DEBUG
  printf("DEBUG: req size %.8x, final size %.8x\n", _size, size);
#endif
  AKbuf_ASSERT(size >= _size);
  new = malloc(sizeof(akbuf));
  AKbuf_ASSERT(new != NULL);
  new->in_use = 1;
  new->size = size;
  new->idx = 0;
  new->prev = NULL;
  new->next = ctx->head;
  new->head = malloc(size);
  AKbuf_ASSERT(new->head != NULL);
  if (ctx->head != NULL) ctx->head->prev = new;
  ctx->head = new;
#ifdef AKBUF_DEBUG
  memset(new->head, 'A', new->size);
#endif
  return new;
}
void akbuf_set_size(akbuf *buf, AKsize_t _size)
{
  AKsize_t size;
  
  AKbuf_dASSERT(buf != NULL);
  size = AK_REALSIZE(_size);
  AKbuf_ASSERT(size >= _size);
  if (size == buf->size) return;
  buf->head = realloc(buf->head, size);
  AKbuf_ASSERT(buf->head != NULL);
  buf->size = size;
  if (buf->idx > size) buf->idx = size;
  return;
}
void akbuf_consume(akbuf *buf, AKsize_t len)
{
  AKbuf_dASSERT(buf != NULL);
  if (len == 0) return;
  AKbuf_ASSERT(buf->idx >= len && buf->idx <= buf->size);
  memcpy(buf->head, buf->head + len, buf->idx - len);
  buf->idx -= len;
  if (len >= GRAIN_SIZE) akbuf_set_size(buf, buf->idx);
  return;
}
unsigned char akbuf_eat_byte(akbuf *buf)
{
  unsigned char ret;
  
  AKbuf_dASSERT(buf != NULL);
  AKbuf_ASSERT(buf->idx > 0 && buf->idx <= buf->size);
  ret = *buf->head;
  memcpy(buf->head, buf->head + 1, buf->idx - 1);
  buf->idx --;
  return ret;
}
void akbuf_set_data(akbuf *buf, unsigned char *data, AKsize_t len)
{
  AKbuf_dASSERT(buf != NULL && data != NULL);
  if (len > buf->size) akbuf_set_size(buf, len);
  memcpy(buf->head, data, len);
  buf->idx = len;
  return;
}
void akbuf_vsprintf(akbuf *buf, unsigned char *format, va_list va)
{
  AKssize_t n;
    
  AKbuf_dASSERT(buf != NULL && format != NULL);
  if ((n = vsnprintf(buf->head, buf->size, format, va)) >= buf->size && n >= 0)
  {
    AKbuf_ASSERT((n + 1) > n);
    akbuf_set_size(buf, n + 1);
    n = vsnprintf(buf->head, buf->size, format, va);
  }
  AKbuf_ASSERT(n >= 0);
  buf->idx = n;
  return;
}
void akbuf_sprintf(akbuf *buf, unsigned char *format, ...)
{
  va_list va;
  
  va_start(va, format);
  akbuf_vsprintf(buf, format, va);
  va_end(va);
  return;
}
void akbuf_appendf(akbuf *buf, unsigned char *format, ...)
{
  akbuf_ctxh ctx;
  akbuf *appendbuf;
  va_list va;
  
  ctx = akbuf_new_ctx();
  appendbuf = akbuf_init(ctx, 0);
  va_start(va, format);
  akbuf_vsprintf(appendbuf, format, va);
  va_end(va);
  akbuf_append_buf(buf, appendbuf); 
  akbuf_free_ctx(ctx);
}
void akbuf_append_data(akbuf *buf, unsigned char *data, AKsize_t len)
{
  AKbuf_dASSERT(buf != NULL && data != NULL);
  AKbuf_ASSERT(buf->idx + len >= buf->idx && buf->idx <= buf->size);
  if (buf->idx + len >= buf->size) akbuf_set_size(buf, buf->idx + len);
  memcpy(buf->head + buf->idx, data, len); buf->idx += len;
  return;
}
void akbuf_append_byte(akbuf *buf, unsigned char b)
{
  AKbuf_dASSERT(buf != NULL);
  AKbuf_ASSERT(buf->idx + 1 > buf->idx && buf->idx <= buf->size);
  if (buf->idx + 1 >= buf->size) akbuf_set_size(buf, buf->idx + 1);
  buf->head[buf->idx ++] = b;
  return;
}
int akbuf_chr(akbuf *buf, unsigned char b)
{
  unsigned char *p;
  
  AKbuf_dASSERT(buf != NULL);
  if ((p = memchr(buf->head, b, buf->idx)) == NULL) return -1;
  return (int)(p - buf->head);
}
void akbuf_asciiz(akbuf *buf)
{
  AKbuf_dASSERT(buf != NULL);
  AKbuf_ASSERT(buf->idx + 1 > buf->idx && buf->idx <= buf->size);
  if (buf->idx == buf->size) akbuf_set_size(buf, buf->idx + 1);
  buf->head[buf->idx] = 0;
  return;
}
void akbuf_free(akbuf_ctxh ctxh, akbuf *buf)
{
  akbuf_ctx *ctx;
  akbuf *cur;
  
  AKbuf_dASSERT(buf != NULL);
  if ((ctx = akbuf_find_ctx(ctxh)) == NULL) AKbuf_PANIC("akbuf_free(): Invalid ctx %.8x", ctxh);
  cur = ctx->head;
  while (cur != buf && cur != NULL) cur = cur->next;
  if (cur == NULL) AKbuf_PANIC("akbuf_free(): Unknown akbuf %.8x", (unsigned int)buf);
#ifdef AKBUF_DEBUG
  printf("DEBUG: freeing buf %.8x\n", (unsigned int)cur);
#endif
  AKbuf_ASSERT(cur->in_use == 1 && cur->head != NULL);
  cur->in_use = 0;
  if (cur->prev != NULL) cur->prev->next = cur->next;
  if (cur->next != NULL) cur->next->prev = cur->prev;
  if (cur == ctx->head) ctx->head = cur->next;
  cur->prev = cur->next = NULL;
  cur->idx = (unsigned int)-1;
#ifdef AKBUF_DEBUG
  memset(cur->head, 'F', cur->size);
#else
  //memset(cur->head, 'F', (cur->size > GRAIN_SIZE)? GRAIN_SIZE : cur->size);
#endif  
  cur->size = 0;
  AKfree(cur->head); cur->head = NULL;
  free(cur);
}
void _akbuf_free_ctx(akbuf_ctxh ctxh, unsigned char *from_file, unsigned int from_line)
{
  akbuf_ctx *ctx;
  akbuf *cur, *prev;
  unsigned int idx;
  
  if (ctxh == AKbuf_INVALID_CTX) return;
  if ((ctx = akbuf_find_ctx(ctxh)) == NULL) AKbuf_PANIC_FROM("akbuf_free_ctx(): Invalid ctx %.8x", ctxh);
  cur = ctx->head;
  while (cur != NULL)
  {
    prev = cur;
    cur = cur->next;
    AKbuf_ASSERT(prev->in_use == 1 && prev->head != NULL);
    prev->in_use = 0;
    prev->prev = prev->next = NULL;
    prev->idx = (unsigned int)-1;
#ifdef AKBUF_DEBUG
    printf("DEBUG: prev %.8x prev->size %.8x\n", (unsigned int)prev, prev->size);
    memset(prev->head, 'G', prev->size);
#endif    
    //memset(prev->head, 'F', (prev->size > GRAIN_SIZE)? GRAIN_SIZE : prev->size);
    prev->size = 0;
    AKfree(prev->head); prev->head = NULL;
    free(prev);
  }
  ctx->head = NULL;
  if (ctx->prev != NULL) ctx->prev->next = ctx->next;
  if (ctx->next != NULL) ctx->next->prev = ctx->prev;
  if (ctx == ctx_hash[idx = CTX_HASH_FN(ctxh)]) ctx_hash[idx] = ctx->next;
#ifdef AKBUF_DEBUG
  memset(ctx, 'C', sizeof(akbuf_ctx));
#endif
  free(ctx);
}
akbuf_table *akbuf_table_init(akbuf_ctxh ctxh, unsigned int type)
{
  akbuf *tblbuf;
  akbuf_table *ret;
  
  tblbuf = akbuf_init(ctxh, sizeof(akbuf_table));
  AKbuf_dASSERT(tblbuf != NULL);
  akbuf_set_idx(tblbuf, sizeof(akbuf_table));
  ret = (akbuf_table *)akbuf_data(tblbuf);
  ret->head = ret->tail = NULL;
  ret->type = type;
  ret->ctxh = ctxh;
  return ret;
}
akbuf_table_entry *akbuf_table_entry_add(akbuf_ctxh ctxh, akbuf_table *tbl, unsigned char *key, akbuf *data)
{
  akbuf *entbuf;
  akbuf_table_entry *new;
  
  AKbuf_dASSERT(tbl != NULL && key != NULL && data != NULL);
  AKbuf_ASSERT(ctxh == tbl->ctxh);
  if (akbuf_find_ctx(ctxh) == NULL) AKbuf_PANIC("akbuf_table_entry_add(): Invalid ctx %.08x", ctxh);
  if ((new = akbuf_table_entry_find(tbl, key)) != NULL)
  {
    akbuf_clone(new->data, data);
    return new;
  }
  entbuf = akbuf_init(ctxh, sizeof(akbuf_table_entry));
  AKbuf_dASSERT(entbuf != NULL);
  akbuf_set_idx(entbuf, sizeof(akbuf_table_entry));
  new = (akbuf_table_entry *)akbuf_data(entbuf);
  new->key = akbuf_init(ctxh, 0);
  akbuf_strcpy(new->key, key);
  akbuf_append_byte(new->key, 0);
  new->data = akbuf_init(ctxh, akbuf_idx(data));
  akbuf_clone(new->data, data);
  new->prev = tbl->tail;
  new->next = NULL;
  if (tbl->head == NULL) 
  {
    tbl->head = new;
  } else
  {
    tbl->tail->next = new;
  }
  tbl->tail = new;
  return new;
}
akbuf_table_entry *akbuf_table_entry_add_buf(akbuf_ctxh ctxh, akbuf_table *tbl, akbuf *key, akbuf *data)
{
  akbuf *entbuf;
  akbuf_table_entry *new;

  AKbuf_dASSERT(tbl != NULL && key != NULL && data != NULL);
  AKbuf_ASSERT(tbl->type == AKBUF_TABLE_BIN);
  AKbuf_ASSERT(ctxh == tbl->ctxh);
  if (akbuf_find_ctx(ctxh) == NULL) AKbuf_PANIC("akbuf_table_entry_add(): Invalid ctx %.08x", ctxh);
  entbuf = akbuf_init(ctxh, sizeof(akbuf_table_entry));
  AKbuf_dASSERT(entbuf != NULL);
  akbuf_set_idx(entbuf, sizeof(akbuf_table_entry));
  new = (akbuf_table_entry *)akbuf_data(entbuf);
  new->key = akbuf_init(ctxh, akbuf_idx(key));
  akbuf_clone(new->key, key);
  akbuf_append_byte(new->key, 0);
  new->data = akbuf_init(ctxh, akbuf_idx(data));
  akbuf_clone(new->data, data);
  new->prev = tbl->tail;
  new->next = NULL;
  if (tbl->head == NULL) 
  {
    tbl->head = new;
  } else
  {
    tbl->tail->next = new;
  }
  tbl->tail = new;
  return new;
}
akbuf_table_entry *akbuf_table_entry_add_str(akbuf_ctxh ctxh, akbuf_table *tbl, unsigned char *key, unsigned char *data)
{
  akbuf *buf;
  akbuf_ctxh ctx;
  akbuf_table_entry *ret;
  
  ctx = akbuf_new_ctx();
  buf = akbuf_init(ctx, 0);
  akbuf_strcpy(buf, data); akbuf_append_byte(buf, 0);
  ret = akbuf_table_entry_add(ctxh, tbl, key, buf);
  akbuf_free_ctx(ctx);
  return ret;
}
akbuf_table_entry *akbuf_table_entry_find(akbuf_table *tbl, unsigned char *key)
{
  int (*cmpfn)();
  akbuf_table_entry *ent;
  
  AKbuf_dASSERT(tbl != NULL && key != NULL);
  AKbuf_ASSERT(tbl->type == AKBUF_TABLE_NOCASE || tbl->type == AKBUF_TABLE_CASE);
  cmpfn = (tbl->type == AKBUF_TABLE_CASE)? strcmp : strcasecmp;
  ent = tbl->head;
  while (ent != NULL)
  {
    if (cmpfn(akbuf_data(ent->key), key) == 0) return ent;
    ent = ent->next;
  }
  return NULL;
}
akbuf *akbuf_table_entry_get(akbuf_table *tbl, unsigned char *key)
{
  akbuf_table_entry *ent;
  
  if ((ent = akbuf_table_entry_find(tbl, key)) == NULL) return NULL;
  return ent->data;
}
unsigned char *akbuf_table_entry_get_str(akbuf_table *tbl, unsigned char *key)
{
  akbuf *buf;
  
  if ((buf = akbuf_table_entry_get(tbl, key)) == NULL) return NULL;
  akbuf_asciiz(buf);
  return akbuf_data(buf); 
}

void akbuf_urlencode_data(unsigned char *data, AKsize_t len, akbuf *outbuf)
{
  unsigned int i;
  unsigned int c;

  for (i = 0; i < len; i ++)
  {
    unsigned char hexchars[] = "0123456789ABCDEF";

    c = data[i];
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= '<'))
    {
      akbuf_append_byte(outbuf, c);
    } else
    {
      akbuf_append_byte(outbuf, '%');
      akbuf_append_byte(outbuf, hexchars[(c >> 4) & 0xf]);
      akbuf_append_byte(outbuf, hexchars[c & 0xf]);
    }
  }
}
void akbuf_base64encode_data(unsigned char *data, AKsize_t len, akbuf *outbuf)
{
  AKsize_t rem;
  unsigned char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  rem = len;
  while (rem > 2)
  {
    akbuf_append_byte(outbuf, b64chars[data[0] >> 2]);
    akbuf_append_byte(outbuf, b64chars[((data[0] & 0x03) << 4) + (data[1] >> 4)]);
    akbuf_append_byte(outbuf, b64chars[((data[1] & 0x0f) << 2) + (data[2] >> 6)]);
    akbuf_append_byte(outbuf, b64chars[data[2] & 0x3f]);
    data += 3;
    rem -= 3;
  }
  if (rem != 0)
  {
    akbuf_append_byte(outbuf, b64chars[data[0] >> 2]);
    if (rem > 1)
    {
      akbuf_append_byte(outbuf, b64chars[((data[0] & 0x03) << 4) + (data[1] >> 4)]);
      akbuf_append_byte(outbuf, b64chars[((data[1] & 0x0f) << 2)]);
      akbuf_append_byte(outbuf, '=');
    } else
    {
      akbuf_append_byte(outbuf, b64chars[((data[0] & 0x03) << 4)]);
      akbuf_append_byte(outbuf, '=');
      akbuf_append_byte(outbuf, '=');
    }
  }
}

#ifdef AKBUF_TEST
int main(int argc, char *argv[])
{
  akbuf_ctxh ctx;
  akbuf *buf, *buf2;
  int i;
  akbuf_table *tbl;
  akbuf_table_entry *ent;
  
  printf("akbuf_new_ctx()\n");
  ctx = akbuf_new_ctx();
  printf(" = %.8x\n", (unsigned int)ctx);
  printf("akbuf_new_ctx() second = %.8x\n", (unsigned int)akbuf_new_ctx());
  dump_all_ctxs();
  
  buf = akbuf_init(ctx, 0);
  akbuf_strcpy(buf, "blutti");
  printf("akbuf_table_init() =\n");
  tbl = akbuf_table_init(ctx, 0);
  printf("  %.08x\n", (unsigned int)tbl);
  printf("akbuf_table_entry_add() =\n");
  ent = akbuf_table_entry_add(ctx, tbl, "foobar", buf);
  printf("  %.08x\n", (unsigned int)ent);
  printf("[%s]\n", akbuf_data(ent->key));
  akbuf_strcpy(buf, "fnutti");
  ent = akbuf_table_entry_add(ctx, tbl, "foobar2", buf);
  printf("  next = %.08x prev = %.08x head = %.08x tail = %.08x\n", (unsigned int)ent->next, (unsigned int)ent->prev, (unsigned int)tbl->head, (unsigned int)tbl->tail);
  printf("akbuf_table_entry_get(..., \"foobar\")\n");
  buf2 = akbuf_table_entry_get(tbl, "foobar");
  if (buf2 != NULL)
  {
    akbuf_asciiz(buf2);
    printf("  [%s]\n", akbuf_data(buf2)); 
  }
  printf("akbuf_table_entry_get(..., \"foobar2\")\n");
  buf2 = akbuf_table_entry_get(tbl, "foobar2");
  if (buf2 != NULL)
  {
    akbuf_asciiz(buf2);
    printf("  [%s]\n", akbuf_data(buf2)); 
  }
  
#if 1
  printf("akbuf_init(0x242)\n");
  buf = akbuf_init(ctx, 0x242);
  printf(" = %.8x\n", (unsigned int)buf);
  //printf("akbuf_init(0xffffffff)\n");
  //akbuf_init(ctx, 0xffffffff);
  akbuf_strcpy(buf, "foobar blutti");
  akbuf_append_str(buf, " fnutti");
  akbuf_asciiz(buf);
  printf("[%s]\n", akbuf_data(buf));
  buf2 = akbuf_init(ctx, 0);
  akbuf_strcpy(buf2, "1 2 3");
  akbuf_append_str(buf2," 4 5 6");
  akbuf_consume(buf2, 4);
  akbuf_asciiz(buf2);
  printf("[%s]\n", akbuf_data(buf2));
  buf = akbuf_init(ctx, 0);
  akbuf_sprintf(buf, "foobar %u [%s]", 0x242, "foo");
  akbuf_asciiz(buf);
  printf("fmt [%s]\n", akbuf_data(buf));
  printf("freeing\n");
  akbuf_free_ctx(ctx);
  dump_all_ctxs();
  ctx = akbuf_new_ctx();
  buf = akbuf_init(ctx, 0x666);
  akbuf_strcpy(buf, "foo\nbar\nblutti\nfnutti");
  buf2 = akbuf_init(ctx, 0);
  while ((i = akbuf_chr(buf, '\n')) != -1)
  {
    akbuf_split(buf, buf2, i);
    akbuf_asciiz(buf2);
    printf("split [%s]\n", akbuf_data(buf2));
  }
  akbuf_asciiz(buf);
  printf("rem [%s]\n", akbuf_data(buf));
  dump_all_ctxs();
  akbuf_free_ctx(ctx);
#endif
  akbuf_free_ctx(ctx);
  return 0;
}
#endif
