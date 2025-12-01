#include "event_system.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>

// Forward declarations for internal functions
static void on_pipe_connect(uv_connect_t *req, int status);
static void on_pipe_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_pipe_write(uv_write_t *req, int status);
static void on_pipe_connection(uv_stream_t *server, int status);
static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void event_thread_worker(void *arg);

event_system_t* create_event_system(const char *pipe_name, bool is_server) {
    event_system_t *system = malloc(sizeof(event_system_t));
    if (!system) return NULL;
    
    system->loop = uv_default_loop();
    if (!system->loop) {
        free(system);
        return NULL;
    }
    
    strncpy(system->pipe_name, pipe_name, sizeof(system->pipe_name) - 1);
    system->pipe_name[sizeof(system->pipe_name) - 1] = '\0';
    system->is_server = is_server;
    system->is_running = false;
    system->callback = NULL;
    system->user_data = NULL;
    
    if (is_server) {
        uv_pipe_init(system->loop, &system->pipe_server, 0);
        system->pipe_server.data = system;
    } else {
        uv_pipe_init(system->loop, &system->pipe_client, 0);
        system->pipe_client.data = system;
    }
    
    return system;
}

void destroy_event_system(event_system_t *system) {
    if (!system) return;
    
    if (system->is_running) {
        if (system->is_server) {
            stop_event_server(system);
        } else {
            disconnect_event_client(system);
        }
    }
    
    free(system);
}

static void on_pipe_connection(uv_stream_t *server, int status) {
    if (status < 0) {
        fprintf(stderr, "Connection error: %s\n", uv_strerror(status));
        return;
    }
    
    event_system_t *system = (event_system_t*)server->data;
    uv_pipe_t *client = malloc(sizeof(uv_pipe_t));
    uv_pipe_init(system->loop, client, 0);
    client->data = system;
    
    if (uv_accept(server, (uv_stream_t*)client) == 0) {
        uv_read_start((uv_stream_t*)client, alloc_buffer, on_pipe_read);
    } else {
        uv_close((uv_handle_t*)client, NULL);
        free(client);
    }
}

static void on_pipe_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    event_system_t *system = (event_system_t*)stream->data;
    
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error: %s\n", uv_strerror(nread));
        }
        uv_close((uv_handle_t*)stream, NULL);
        if (buf->base) free(buf->base);
        return;
    }
    
    if (nread == 0) {
        if (buf->base) free(buf->base);
        return;
    }
    
    // Process received event
    if (nread >= (ssize_t)sizeof(window_event_t) && system->callback) {
        window_event_t *event = (window_event_t*)buf->base;
        system->callback(event, system->user_data);
    }
    
    if (buf->base) free(buf->base);
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_pipe_write(uv_write_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "Write error: %s\n", uv_strerror(status));
    }
    
    if (req->data) {
        free(req->data);
    }
    free(req);
}

static void on_pipe_connect(uv_connect_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "Connect error: %s\n", uv_strerror(status));
        free(req);
        return;
    }
    
    event_system_t *system = (event_system_t*)req->data;
    printf("[EVENT] Connected to event server: %s\n", system->pipe_name);
    
    free(req);
}

static void event_thread_worker(void *arg) {
    event_system_t *system = (event_system_t*)arg;
    run_event_loop(system);
}

int start_event_server(event_system_t *system, event_callback_t callback, void *user_data) {
    if (!system || !system->is_server) return -1;
    
    system->callback = callback;
    system->user_data = user_data;
    
    // Remove existing pipe if it exists
    unlink(system->pipe_name);
    
    int r = uv_pipe_bind(&system->pipe_server, system->pipe_name);
    if (r) {
        fprintf(stderr, "Bind error: %s\n", uv_strerror(r));
        return r;
    }
    
    r = uv_listen((uv_stream_t*)&system->pipe_server, 128, on_pipe_connection);
    if (r) {
        fprintf(stderr, "Listen error: %s\n", uv_strerror(r));
        return r;
    }
    
    system->is_running = true;
    printf("[EVENT] Server listening on: %s\n", system->pipe_name);
    
    // Start event loop in separate thread
    uv_thread_create(&system->thread, event_thread_worker, system);
    
    return 0;
}

void stop_event_server(event_system_t *system) {
    if (!system || !system->is_running) return;
    
    system->is_running = false;
    uv_stop(system->loop);
    
    // Wait for thread to finish
    uv_thread_join(&system->thread);
    
    printf("[EVENT] Server stopped\n");
}

int connect_event_client(event_system_t *system) {
    if (!system || system->is_server) return -1;
    
    uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
    connect_req->data = system;
    
    uv_pipe_connect(connect_req, &system->pipe_client, system->pipe_name, on_pipe_connect);
    
    return 0;
}

int broadcast_window_event(event_system_t *system, uint32_t flow_id, 
                          const flow_features_t *features, const char *source) {
    if (!system || system->is_server) return -1;
    
    window_event_t *event = malloc(sizeof(window_event_t));
    if (!event) return -1;
    
    event->type = EVENT_WINDOW_UPDATE;
    event->flow_id = flow_id;
    gettimeofday(&event->timestamp, NULL);
    event->features = *features;
    strncpy(event->source_process, source, sizeof(event->source_process) - 1);
    event->source_process[sizeof(event->source_process) - 1] = '\0';
    
    uv_write_t *write_req = malloc(sizeof(uv_write_t));
    write_req->data = event;
    
    uv_buf_t buf = uv_buf_init((char*)event, sizeof(window_event_t));
    
    int r = uv_write(write_req, (uv_stream_t*)&system->pipe_client, &buf, 1, on_pipe_write);
    if (r) {
        fprintf(stderr, "Write error: %s\n", uv_strerror(r));
        free(event);
        free(write_req);
        return r;
    }
    
    return 0;
}

void disconnect_event_client(event_system_t *system) {
    if (!system || system->is_server) return;
    
    uv_close((uv_handle_t*)&system->pipe_client, NULL);
    printf("[EVENT] Client disconnected\n");
}

void run_event_loop(event_system_t *system) {
    if (!system) return;
    
    printf("[EVENT] Starting event loop\n");
    uv_run(system->loop, UV_RUN_DEFAULT);
    printf("[EVENT] Event loop finished\n");
}

int send_shutdown_event(event_system_t *system) {
    if (!system || system->is_server) return -1;
    
    window_event_t *event = malloc(sizeof(window_event_t));
    if (!event) return -1;
    
    event->type = EVENT_SHUTDOWN;
    event->flow_id = 0;
    gettimeofday(&event->timestamp, NULL);
    memset(&event->features, 0, sizeof(flow_features_t));
    strncpy(event->source_process, "proc1", sizeof(event->source_process) - 1);
    event->source_process[sizeof(event->source_process) - 1] = '\0';
    
    uv_write_t *write_req = malloc(sizeof(uv_write_t));
    write_req->data = event;
    
    uv_buf_t buf = uv_buf_init((char*)event, sizeof(window_event_t));
    
    int r = uv_write(write_req, (uv_stream_t*)&system->pipe_client, &buf, 1, on_pipe_write);
    if (r) {
        fprintf(stderr, "Shutdown write error: %s\n", uv_strerror(r));
        free(event);
        free(write_req);
        return r;
    }
    
    return 0;
}