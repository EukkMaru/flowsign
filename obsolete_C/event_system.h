#ifndef EVENT_SYSTEM_H
#define EVENT_SYSTEM_H

#include <uv.h>
#include <stdbool.h>
#include "flow_analyzer.h"

// Event types
typedef enum {
    EVENT_WINDOW_UPDATE,
    EVENT_FLOW_COMPLETE,
    EVENT_SHUTDOWN
} event_type_t;

// Event data structure
typedef struct {
    event_type_t type;
    uint32_t flow_id;
    struct timeval timestamp;
    flow_features_t features;
    char source_process[32];  // "proc1" or "proc2"
} window_event_t;

// Event callback function type
typedef void (*event_callback_t)(window_event_t *event, void *user_data);

// Event system structure
typedef struct {
    uv_loop_t *loop;
    uv_pipe_t pipe_server;
    uv_pipe_t pipe_client;
    char pipe_name[256];
    bool is_server;
    bool is_running;
    event_callback_t callback;
    void *user_data;
    uv_thread_t thread;
} event_system_t;

// Event system functions
event_system_t* create_event_system(const char *pipe_name, bool is_server);
void destroy_event_system(event_system_t *system);

// Server functions (proc2 - rule engine)
int start_event_server(event_system_t *system, event_callback_t callback, void *user_data);
void stop_event_server(event_system_t *system);

// Client functions (proc1 - flow analyzer)
int connect_event_client(event_system_t *system);
int broadcast_window_event(event_system_t *system, uint32_t flow_id, 
                          const flow_features_t *features, const char *source);
void disconnect_event_client(event_system_t *system);

// Utility functions
void run_event_loop(event_system_t *system);
int send_shutdown_event(event_system_t *system);

#endif // EVENT_SYSTEM_H