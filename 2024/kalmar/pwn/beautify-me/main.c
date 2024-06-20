#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "main.h"


char *skip_whitespace(char *s) {
    while (isspace(*s)) s++;
    return s;
}

char *parse_object_element (char *s, object_t **out) {
    object_t *elem = malloc(sizeof(object_t));
    if (elem == NULL) return NULL;

    s = parse_value(s, &elem->key);
    if (s == NULL) {
        free(elem);
        return NULL;
    }

    s = skip_whitespace(s);

    if (*s != ':') {
        free_value(elem->key);
        free(elem);
        return NULL;
    }

    s = skip_whitespace(++s);

    s = parse_value(s, &elem->value);
    if (s == NULL) {
        free_value(elem->key);
        free(elem);
        return NULL;
    }
    s = skip_whitespace(s);

    if (*s == '}') {
        elem->next = NULL;
        *out = elem;
        return ++s;
    }
    if (*s == ',') {
        s = skip_whitespace(++s);
        s = parse_object_element(s, &elem->next);
        if (s == NULL) {
            free_value(elem->key);
            free_value(elem->value);
            free(elem);
            return NULL;
        }
        *out = elem;
        return s;
    }
    return NULL;
}

char *parse_object (char *s, json_t **out) {
    json_t *data = malloc(sizeof(json_t));
    if (data == NULL) return NULL;
    data->type = T_OBJECT;

    s = skip_whitespace(s);

    if (*s == '}') {
        data->object = NULL;
        *out = data;
        return ++s;
    }

    s = parse_object_element(s, &data->object);
    if (s == NULL) {
        free(data);
        return NULL;
    }
    *out = data;
    return s;
}

char *parse_array_element (char *s, array_t **out) {
    array_t *elem = malloc(sizeof(array_t));
    if (elem == NULL) return NULL;
    s = parse_value(s, &elem->value);
    if (s == NULL) {
        free(elem);
        return NULL;
    }

    s = skip_whitespace(s);

    if (*s == ']') {
        elem->next = NULL;
        *out = elem;
        return ++s;
    }
    if (*s == ',') {
        s = skip_whitespace(++s);
        s = parse_array_element(s, &elem->next);
        if (s == NULL) {
            free_value(elem->value);
            free(elem);
            return NULL;
        }
    }
    *out = elem;
    return s;
}

char *parse_array (char *s, json_t **out) {
    json_t *data = malloc(sizeof(json_t));
    if (data == NULL) return NULL;
    data->type = T_ARRAY;

    s = skip_whitespace(s);

    if (*s == ']') {
        data->array = NULL;
        *out = data;
        return ++s;
    }

    s = parse_array_element(s, &data->array);
    if (s == NULL) {
        free(data);
        return NULL;
    }
    *out = data;
    return s;
}

char *parse_number (char *s, json_t **out) {
    char *endi, *endf;
    long nint = strtol(s, &endi, 10);
    double nfloat = strtod(s, &endf);

    json_t *data = malloc(sizeof(json_t));
    if (data == NULL) return NULL;

    if (endf > endi) {
        data->type = T_FLOAT;
        data->nfloat = nfloat;
        *out = data;
        return endf;
    } else if (endi != s) {
        data->type = T_INT;
        data->nint = nint;
        *out = data;
        return endi;
    } else {
        free(data);
        return NULL;
    }
}

char *parse_bool (char *s, json_t **out) {
    char val;
    if (strncmp(s, "true", 4) == 0) {
        s += 4;
        val = 1;
    } else if (strncmp(s, "false", 5) == 0) {
        s += 5;
        val = 0;
    } else {
        return NULL;
    }
    json_t *data = malloc(sizeof(json_t));
    if (data == NULL) return NULL;
    data->type = T_BOOL;
    data->boolean = val;
    *out = data;
    return s;
}


char *parse_value (char *s, json_t **out) {
    s = skip_whitespace(s);

    if (*s == '{') {
        return parse_object(++s, out);
    } else if (*s == '[') {
        return parse_array(++s, out);
    } else if (*s == '"') {
        char *end = strchr(++s, '"');
        if (end == NULL) return NULL;
        json_t *data = malloc(sizeof(json_t));
        data->type = T_STRING;
        data->string = strndup(s, end-s);
        *out = data;
        return end+1;
    } else if (*s == 't' || *s == 'f') {
        return parse_bool(s, out);
    } else if (*s == 'n') {
        if (strncmp(s, "null", 4) == 0) {
            json_t *data = malloc(sizeof(json_t));
            if (data == NULL) return NULL;
            data->type = T_NULL;
            *out = data;
            return s+4;
        }
    } else if (isdigit(*s) || *s == '-') {
        return parse_number(s, out);
    }

    return NULL;
}

void print_value (json_t *data, int indent) {
    switch (data->type) {
        case T_NULL:
            printf("null");
            break;
        case T_BOOL:
            printf(data->boolean ? "true" : "false");
            break;
        case T_INT:
            printf("%ld", data->nint);
            break;
        case T_FLOAT:
            printf("%lf", data->nfloat);
            break;
        case T_STRING:
            printf("\"%s\"", data->string);
            break;
        case T_ARRAY:
            {
                array_t *curr = data->array;
                if (curr == NULL) {
                    printf("[]");
                    break;
                }
                printf("[\n");
                while (curr) {
                    for (int i = 0; i < indent+4; i++) putchar(' ');
                    print_value(curr->value, indent+4);
                    curr = curr->next;
                    if (curr) {
                        printf(",\n");
                    }
                }
                putchar('\n');
                for (int i = 0; i < indent; i++) putchar(' ');
                printf("]");
            }
            break;
        case T_OBJECT:
            {
                object_t *curr = data->object;
                if (curr == NULL) {
                    printf("{}");
                    break;
                }
                printf("{\n");
                while (curr) {
                    for (int i = 0; i < indent+4; i++) putchar(' ');
                    printf("\"%s\": ", curr->key->string);
                    print_value(curr->value, indent+4);
                    curr = curr->next;
                    if (curr) {
                        printf(",\n");
                    }
                }
                putchar('\n');
                for (int i = 0; i < indent; i++) putchar(' ');
                printf("}");
            }
            break;
        default:
            printf("Invalid type!");
            exit(-1);
    }
}

void free_value (json_t *data) {
    switch (data->type) {
        case T_STRING:
            free(data->string);
            break;
        case T_ARRAY:
            {
                array_t *next, *curr = data->array;
                while (curr) {
                    free_value(curr->value);
                    next = curr->next;
                    free(curr);
                    curr = next;
                }
            }
            break;
        case T_OBJECT:
            {
                object_t *next, *curr = data->object;
                while (curr) {
                    free_value(curr->key);
                    free_value(curr->value);
                    next = curr->next;
                    free(curr);
                    curr = next;
                }
            }
            break;
        default:
            break;
    }
    free(data);
}

int main () {
    json_t *obj;
    char buf[0x1000];

    setvbuf(stdin, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOFBF, 0);
    
    while (1) {
        printf("> ");
        fflush(stdout);
        if (fgets(buf, sizeof(buf), stdin) == NULL) exit(-1);
        if (parse_value(buf, &obj) == NULL) {
            printf("Invalid JSON!\n");
            continue;
        }
        print_value(obj, 0);
        printf("\n");
        free_value(obj);
    }
}
