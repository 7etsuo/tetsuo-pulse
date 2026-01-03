#include "grok_client.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define GROK_API_URL "https://api.x.ai/v1/chat/completions"
#define DEFAULT_MODEL "grok-4-1-fast-reasoning"
#define DEFAULT_TIMEOUT_MS 30000
#define MAX_ERROR_LEN 256

struct GrokClient {
    char *api_key;
    char *model;
    long timeout_ms;
    CURL *curl;
    char error[MAX_ERROR_LEN];
};

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} Buffer;

static size_t
write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    Buffer *buf = (Buffer *)userp;

    if (buf->len + realsize + 1 > buf->cap) {
        size_t newcap = buf->cap * 2;
        if (newcap < buf->len + realsize + 1)
            newcap = buf->len + realsize + 1;
        char *newdata = realloc(buf->data, newcap);
        if (!newdata) return 0;
        buf->data = newdata;
        buf->cap = newcap;
    }

    memcpy(buf->data + buf->len, contents, realsize);
    buf->len += realsize;
    buf->data[buf->len] = '\0';
    return realsize;
}

static char *
escape_json_string(const char *s)
{
    if (!s) return strdup("");

    size_t len = strlen(s);
    size_t cap = len * 2 + 1;
    char *out = malloc(cap);
    if (!out) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (j + 6 > cap) {
            cap *= 2;
            char *newout = realloc(out, cap);
            if (!newout) { free(out); return NULL; }
            out = newout;
        }

        switch (s[i]) {
            case '"':  out[j++] = '\\'; out[j++] = '"'; break;
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
            case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
            case '\t': out[j++] = '\\'; out[j++] = 't'; break;
            default:
                if ((unsigned char)s[i] < 32) {
                    j += snprintf(out + j, cap - j, "\\u%04x", (unsigned char)s[i]);
                } else {
                    out[j++] = s[i];
                }
        }
    }
    out[j] = '\0';
    return out;
}

static char *
extract_content(const char *json)
{
    const char *choices = strstr(json, "\"choices\"");
    if (!choices) return NULL;

    const char *content = strstr(choices, "\"content\"");
    if (!content) return NULL;

    content = strchr(content, ':');
    if (!content) return NULL;
    content++;

    while (*content == ' ' || *content == '\t') content++;
    if (*content != '"') return NULL;
    content++;

    const char *end = content;
    while (*end && !(*end == '"' && *(end - 1) != '\\')) end++;
    if (!*end) return NULL;

    size_t len = end - content;
    char *result = malloc(len + 1);
    if (!result) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (content[i] == '\\' && i + 1 < len) {
            switch (content[i + 1]) {
                case 'n': result[j++] = '\n'; i++; break;
                case 'r': result[j++] = '\r'; i++; break;
                case 't': result[j++] = '\t'; i++; break;
                case '"': result[j++] = '"'; i++; break;
                case '\\': result[j++] = '\\'; i++; break;
                default: result[j++] = content[i];
            }
        } else {
            result[j++] = content[i];
        }
    }
    result[j] = '\0';
    return result;
}

GrokClient_T
GrokClient_new(const GrokClient_Config *config)
{
    if (!config || !config->api_key) return NULL;

    GrokClient_T client = calloc(1, sizeof(*client));
    if (!client) return NULL;

    client->api_key = strdup(config->api_key);
    client->model = strdup(config->model ? config->model : DEFAULT_MODEL);
    client->timeout_ms = config->timeout_ms > 0 ? config->timeout_ms : DEFAULT_TIMEOUT_MS;

    if (!client->api_key || !client->model) {
        free(client->api_key);
        free(client->model);
        free(client);
        return NULL;
    }

    client->curl = curl_easy_init();
    if (!client->curl) {
        free(client->api_key);
        free(client->model);
        free(client);
        return NULL;
    }

    return client;
}

void
GrokClient_free(GrokClient_T *client)
{
    if (!client || !*client) return;

    GrokClient_T c = *client;
    if (c->curl) curl_easy_cleanup(c->curl);
    free(c->api_key);
    free(c->model);
    free(c);
    *client = NULL;
}

char *
GrokClient_chat(GrokClient_T client,
                const char *system_prompt,
                const char *conversation_history)
{
    if (!client || !system_prompt) return NULL;

    char *escaped_system = escape_json_string(system_prompt);
    char *escaped_history = escape_json_string(conversation_history ? conversation_history : "");
    if (!escaped_system || !escaped_history) {
        free(escaped_system);
        free(escaped_history);
        snprintf(client->error, MAX_ERROR_LEN, "Failed to escape JSON");
        return NULL;
    }

    size_t json_len = strlen(escaped_system) + strlen(escaped_history) + 512;
    char *json = malloc(json_len);
    if (!json) {
        free(escaped_system);
        free(escaped_history);
        snprintf(client->error, MAX_ERROR_LEN, "Out of memory");
        return NULL;
    }

    snprintf(json, json_len,
        "{"
        "\"model\":\"%s\","
        "\"messages\":["
            "{\"role\":\"system\",\"content\":\"%s\"},"
            "{\"role\":\"user\",\"content\":\"%s\"}"
        "],"
        "\"max_tokens\":60,"
        "\"temperature\":0.7"
        "}",
        client->model, escaped_system, escaped_history);

    free(escaped_system);
    free(escaped_history);

    Buffer response = { .data = malloc(4096), .len = 0, .cap = 4096 };
    if (!response.data) {
        free(json);
        snprintf(client->error, MAX_ERROR_LEN, "Out of memory");
        return NULL;
    }
    response.data[0] = '\0';

    char auth_header[256];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", client->api_key);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header);

    curl_easy_reset(client->curl);
    curl_easy_setopt(client->curl, CURLOPT_URL, GROK_API_URL);
    curl_easy_setopt(client->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(client->curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(client->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(client->curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(client->curl, CURLOPT_TIMEOUT_MS, client->timeout_ms);

    CURLcode res = curl_easy_perform(client->curl);

    curl_slist_free_all(headers);
    free(json);

    if (res != CURLE_OK) {
        snprintf(client->error, MAX_ERROR_LEN, "curl: %s", curl_easy_strerror(res));
        free(response.data);
        return NULL;
    }

    long http_code;
    curl_easy_getinfo(client->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        snprintf(client->error, MAX_ERROR_LEN, "HTTP %ld: %.200s", http_code, response.data);
        free(response.data);
        return NULL;
    }

    char *content = extract_content(response.data);
    free(response.data);

    if (!content) {
        snprintf(client->error, MAX_ERROR_LEN, "Failed to parse response");
        return NULL;
    }

    return content;
}

const char *
GrokClient_last_error(GrokClient_T client)
{
    return client ? client->error : "NULL client";
}
