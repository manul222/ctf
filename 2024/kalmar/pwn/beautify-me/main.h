typedef enum type_t {
    T_NULL,
    T_BOOL,
    T_INT,
    T_FLOAT,
    T_STRING,
    T_ARRAY,
    T_OBJECT,
} type_t;

typedef struct Object object_t;
typedef struct Array array_t;
typedef struct Json json_t;

typedef struct Object {
    object_t *next;
    json_t *key, *value;
} object_t;

typedef struct Array {
    array_t *next;
    json_t *value;
} array_t;

typedef struct Json {
    union {
        object_t *object;
        array_t *array;
        char *string;
        char boolean;
        long nint;
        double nfloat;
    };
    type_t type;
} json_t;

char *parse_value (char *s, json_t **out);
void free_value (json_t *data);
