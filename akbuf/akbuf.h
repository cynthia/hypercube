//#define GRAIN_SIZE		0x1000		/* must be power of 2 */
//#define AKBUF_CTX_HASH_SIZE	0x400000	/* must be power of 2 */
#define GRAIN_SIZE 0x100
#define AKBUF_CTX_HASH_SIZE 0x40000
	
#define AKsize_t	size_t
#define AKssize_t	ssize_t

#define AKbuf_PANIC(f...) akbuf_panic(__FILE__, __LINE__, NULL, 0, ##f)
#define AKbuf_PANIC_FROM(f...) akbuf_panic(__FILE__, __LINE__, from_file, from_line, ##f)
#define AKbuf_ASSERT(cond) if (!(cond)) akbuf_panic(__FILE__, __LINE__, NULL, 0, "Assertion (" __STRING(cond) ") failed")
#ifdef AKBUF_DEBUG
#define AKbuf_dASSERT(cond) AKbuf_ASSERT(cond)
#else
#define AKbuf_dASSERT(cond)
#endif

#define AKfree(ptr) if ((ptr) != NULL) { free(ptr); (ptr) = NULL; }

typedef unsigned int akbuf_ctxh;

#define AKbuf_INVALID_CTX ((akbuf_ctxh)-1)

typedef struct akbuf_s akbuf;
typedef struct akbuf_ctx_s akbuf_ctx;

struct akbuf_s
{
  unsigned int in_use;
  akbuf *prev;
  akbuf *next;
  unsigned int idx;
  AKsize_t size;
  unsigned char *head;
};

struct akbuf_ctx_s
{
  akbuf_ctxh hnd;
  akbuf *head;
  akbuf_ctx *prev;
  akbuf_ctx *next; 
};

typedef struct akbuf_table_s akbuf_table;
typedef struct akbuf_table_entry_s akbuf_table_entry;

struct akbuf_table_s
{
  akbuf_ctxh ctxh;
  unsigned int type;
  akbuf_table_entry *head;
  akbuf_table_entry *tail;
};

struct akbuf_table_entry_s
{
  akbuf *key;
  akbuf *data;
  akbuf_table_entry *prev;
  akbuf_table_entry *next;
};

enum { AKBUF_TABLE_NOCASE, AKBUF_TABLE_CASE, AKBUF_TABLE_BIN };

void akbuf_panic(unsigned char *, unsigned int, unsigned char *, unsigned int, unsigned char *, ...);
akbuf_ctxh akbuf_new_ctx(void);
void akbuf_free(akbuf_ctxh, akbuf *);
void _akbuf_free_ctx(akbuf_ctxh, unsigned char *, unsigned int);
void akbuf_consume(akbuf *, AKsize_t);
unsigned char akbuf_eat_byte(akbuf *);
int akbuf_chr(akbuf *, unsigned char);
void akbuf_asciiz(akbuf *);

akbuf *akbuf_init(akbuf_ctxh, AKsize_t);
void akbuf_set_size(akbuf *, AKsize_t);
void akbuf_set_data(akbuf *, unsigned char *, AKsize_t);
void akbuf_append_data(akbuf *, unsigned char *, AKsize_t);
void akbuf_append_byte(akbuf *, unsigned char);
void akbuf_vsprintf(akbuf *, unsigned char *, va_list);
void akbuf_sprintf(akbuf *, unsigned char *, ...);
void akbuf_appendf(akbuf *, unsigned char *, ...);

akbuf_table *akbuf_table_init(akbuf_ctxh, unsigned int);
akbuf_table_entry *akbuf_table_entry_add(akbuf_ctxh, akbuf_table *, unsigned char *, akbuf *);
akbuf_table_entry *akbuf_table_entry_add_buf(akbuf_ctxh, akbuf_table *, akbuf *, akbuf *);
akbuf_table_entry *akbuf_table_entry_add_str(akbuf_ctxh, akbuf_table *, unsigned char *, unsigned char *);
akbuf_table_entry *akbuf_table_entry_find(akbuf_table *, unsigned char *);
akbuf *akbuf_table_entry_get(akbuf_table *, unsigned char *);
unsigned char *akbuf_table_entry_get_str(akbuf_table *, unsigned char *);

void akbuf_urlencode_data(unsigned char *, AKsize_t, akbuf *);
void akbuf_base64encode_data(unsigned char *, AKsize_t, akbuf *);

#define akbuf_free_ctx(ctx) _akbuf_free_ctx((ctx), __FILE__, __LINE__)
#define akbuf_idx(buf) ((buf)->idx)
#define akbuf_size(buf) ((buf)->size)
#define akbuf_data(buf) ((buf)->head)
#define akbuf_empty(buf) (akbuf_idx(buf) == 0)

#define akbuf_strcpy(buf, str) akbuf_set_data((buf), (str), strlen(str))
#define akbuf_append_str(buf, str) akbuf_append_data((buf), (str), strlen(str))
#define akbuf_clone(buf, src) akbuf_set_data((buf), akbuf_data(src), akbuf_idx(src))
#define akbuf_append_buf(buf, src) akbuf_append_data((buf), akbuf_data(src), akbuf_idx(src))

#define akbuf_urlencode(buf, out) akbuf_urlencode(akbuf_data(buf), akbuf_idx(buf), (out))

#define akbuf_split(buf, dest, idx)\
	{\
	  akbuf_set_data((dest), akbuf_data((buf)), (idx));\
	  akbuf_consume((buf), (idx) + 1);\
	}

#define akbuf_set_byte(buf, idx, byte)\
	{\
	  AKbuf_ASSERT((unsigned int)(idx) < akbuf_idx(buf) && (unsigned int)(idx) < akbuf_size(buf));\
	  *(akbuf_data(buf) + (idx)) = (byte);\
	}
#define akbuf_consume_end(buf, len)\
	{\
	  AKbuf_ASSERT((unsigned int)(len) <= akbuf_idx(buf));\
	  akbuf_idx(buf) -= (len);\
	}
#define akbuf_set_idx(buf, idx)\
	{\
	  AKbuf_ASSERT((unsigned int)(idx) <= akbuf_size(buf));\
	  akbuf_idx(buf) = (idx);\
	}
#define akbuf_get_byte(buf, idx, byte)\
	{\
	  AKbuf_ASSERT((unsigned int)(idx) < akbuf_idx(buf));\
	  (byte) = *(akbuf_data(buf) + (idx));\
	}
