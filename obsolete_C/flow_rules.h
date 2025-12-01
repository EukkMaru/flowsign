#ifndef FLOW_RULES_H
#define FLOW_RULES_H

#include "flow_analyzer.h"
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#define MAX_RULE_LENGTH 1024
#define MAX_RULES 1000
#define MAX_RULE_MSG 256
#define MAX_CONDITIONS 10

typedef enum {
    CONDITION_FLOW_DURATION,
    CONDITION_FWD_PACKETS,
    CONDITION_BWD_PACKETS,
    CONDITION_FWD_BYTES,
    CONDITION_BWD_BYTES,
    CONDITION_PACKET_LENGTH_MEAN,
    CONDITION_PACKET_LENGTH_STD,
    CONDITION_FWD_PACKET_LENGTH_MEAN,
    CONDITION_BWD_PACKET_LENGTH_MEAN,
    CONDITION_FLOW_BYTES_PER_SEC,
    CONDITION_FLOW_PACKETS_PER_SEC,
    CONDITION_FLOW_IAT_MEAN,
    CONDITION_FLOW_IAT_STD,
    CONDITION_FLOW_IAT_MIN,
    CONDITION_FLOW_IAT_MAX,
    CONDITION_FWD_IAT_MEAN,
    CONDITION_BWD_IAT_MEAN,
    CONDITION_SYN_FLAG_COUNT,
    CONDITION_ACK_FLAG_COUNT,
    CONDITION_FIN_FLAG_COUNT,
    CONDITION_RST_FLAG_COUNT,
    CONDITION_PSH_FLAG_COUNT,
    CONDITION_URG_FLAG_COUNT,
    CONDITION_DOWN_UP_RATIO,
    CONDITION_AVG_PACKET_SIZE
} flow_condition_type_t;

typedef enum {
    OPERATOR_GT,    // >
    OPERATOR_LT,    // <
    OPERATOR_GTE,   // >=
    OPERATOR_LTE,   // <=
    OPERATOR_EQ,    // ==
    OPERATOR_NEQ    // !=
} flow_operator_t;

typedef enum {
    LOGIC_AND,
    LOGIC_OR
} flow_logic_t;

typedef struct {
    flow_condition_type_t type;
    flow_operator_t operator;
    double value;
} flow_condition_t;

typedef struct {
    uint32_t sid;                                    // Rule ID
    char msg[MAX_RULE_MSG];                         // Alert message
    bool enabled;                                   // Rule enabled/disabled
    uint32_t priority;                              // Rule priority (1=highest)
    
    int condition_count;                            // Number of conditions
    flow_condition_t conditions[MAX_CONDITIONS];    // Flow-based conditions
    flow_logic_t logic_operator;                    // AND/OR between conditions
    
    // Statistics
    uint64_t matches;                               // Total matches
    uint64_t evaluations;                           // Total evaluations
} flow_rule_t;

typedef struct {
    flow_rule_t rules[MAX_RULES];
    int rule_count;
    pthread_mutex_t mutex;                          // Thread-safe rule access
} flow_ruleset_t;

typedef struct {
    uint32_t rule_id;
    char message[MAX_RULE_MSG];
    double confidence;                              // Match confidence (0-1)
    struct timeval timestamp;
    flow_features_t features;                       // Features that triggered
} flow_alert_t;

typedef struct {
    flow_alert_t *alerts;
    int capacity;
    int count;
    int head;
    int tail;
    pthread_mutex_t mutex;
    bool is_full;
} flow_alert_queue_t;

typedef struct {
    flow_ruleset_t *ruleset;
    flow_alert_queue_t *alert_queue;
    pthread_t thread_id;
    bool running;
    bool thread_created;
    
    // Statistics
    uint64_t total_evaluations;
    uint64_t total_matches;
    uint64_t total_features_processed;
} flow_rule_engine_t;

// Rule management functions
flow_ruleset_t* create_ruleset();
void destroy_ruleset(flow_ruleset_t *ruleset);
bool add_rule_from_string(flow_ruleset_t *ruleset, const char *rule_str);
bool load_rules_from_file(flow_ruleset_t *ruleset, const char *filename);
void print_ruleset(const flow_ruleset_t *ruleset);

// Rule evaluation functions  
bool evaluate_rule(const flow_rule_t *rule, const flow_features_t *features);
bool evaluate_condition(const flow_condition_t *condition, const flow_features_t *features);
double get_feature_value(const flow_features_t *features, flow_condition_type_t type);

// Alert management
flow_alert_queue_t* create_alert_queue(int capacity);
void destroy_alert_queue(flow_alert_queue_t *queue);
bool enqueue_alert(flow_alert_queue_t *queue, const flow_alert_t *alert);
bool dequeue_alert(flow_alert_queue_t *queue, flow_alert_t *alert);

// Rule engine (Process 2)
flow_rule_engine_t* create_flow_rule_engine(int alert_capacity);
void destroy_flow_rule_engine(flow_rule_engine_t *engine);
bool start_rule_engine_thread(flow_rule_engine_t *engine);
void stop_rule_engine_thread(flow_rule_engine_t *engine);
void process_flow_features(flow_rule_engine_t *engine, const flow_features_t *features);

// Utility functions
const char* condition_type_to_string(flow_condition_type_t type);
const char* operator_to_string(flow_operator_t op);
void print_rule_stats(const flow_ruleset_t *ruleset);

#endif