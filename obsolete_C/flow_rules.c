#define _POSIX_C_SOURCE 200809L
#include "flow_rules.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <unistd.h>

flow_ruleset_t* create_ruleset() {
    flow_ruleset_t *ruleset = malloc(sizeof(flow_ruleset_t));
    if (!ruleset) return NULL;
    
    ruleset->rule_count = 0;
    if (pthread_mutex_init(&ruleset->mutex, NULL) != 0) {
        free(ruleset);
        return NULL;
    }
    
    return ruleset;
}

void destroy_ruleset(flow_ruleset_t *ruleset) {
    if (ruleset) {
        pthread_mutex_destroy(&ruleset->mutex);
        free(ruleset);
    }
}

double get_feature_value(const flow_features_t *features, flow_condition_type_t type) {
    switch (type) {
        case CONDITION_FLOW_DURATION: return features->flow_duration;
        case CONDITION_FWD_PACKETS: return (double)features->total_fwd_packets;
        case CONDITION_BWD_PACKETS: return (double)features->total_bwd_packets;
        case CONDITION_FWD_BYTES: return (double)features->total_fwd_bytes;
        case CONDITION_BWD_BYTES: return (double)features->total_bwd_bytes;
        case CONDITION_PACKET_LENGTH_MEAN: return features->packet_length_mean;
        case CONDITION_PACKET_LENGTH_STD: return features->packet_length_std;
        case CONDITION_FWD_PACKET_LENGTH_MEAN: return features->fwd_packet_length_mean;
        case CONDITION_BWD_PACKET_LENGTH_MEAN: return features->bwd_packet_length_mean;
        case CONDITION_FLOW_BYTES_PER_SEC: return features->flow_bytes_per_sec;
        case CONDITION_FLOW_PACKETS_PER_SEC: return features->flow_packets_per_sec;
        case CONDITION_FLOW_IAT_MEAN: return features->flow_iat_mean;
        case CONDITION_FLOW_IAT_STD: return features->flow_iat_std;
        case CONDITION_FLOW_IAT_MIN: return features->flow_iat_min;
        case CONDITION_FLOW_IAT_MAX: return features->flow_iat_max;
        case CONDITION_FWD_IAT_MEAN: return features->fwd_iat_mean;
        case CONDITION_BWD_IAT_MEAN: return features->bwd_iat_mean;
        case CONDITION_SYN_FLAG_COUNT: return (double)features->syn_flag_count;
        case CONDITION_ACK_FLAG_COUNT: return (double)features->ack_flag_count;
        case CONDITION_FIN_FLAG_COUNT: return (double)features->fin_flag_count;
        case CONDITION_RST_FLAG_COUNT: return (double)features->rst_flag_count;
        case CONDITION_PSH_FLAG_COUNT: return (double)features->psh_flag_count;
        case CONDITION_URG_FLAG_COUNT: return (double)features->urg_flag_count;
        case CONDITION_DOWN_UP_RATIO: return features->down_up_ratio;
        case CONDITION_AVG_PACKET_SIZE: return features->avg_packet_size;
        default: return 0.0;
    }
}

bool evaluate_condition(const flow_condition_t *condition, const flow_features_t *features) {
    double feature_value = get_feature_value(features, condition->type);
    double rule_value = condition->value;
    
    switch (condition->operator) {
        case OPERATOR_GT: return feature_value > rule_value;
        case OPERATOR_LT: return feature_value < rule_value;
        case OPERATOR_GTE: return feature_value >= rule_value;
        case OPERATOR_LTE: return feature_value <= rule_value;
        case OPERATOR_EQ: return feature_value == rule_value;
        case OPERATOR_NEQ: return feature_value != rule_value;
        default: return false;
    }
}

bool evaluate_rule(const flow_rule_t *rule, const flow_features_t *features) {
    if (!rule->enabled || rule->condition_count == 0) return false;
    
    bool first_result = evaluate_condition(&rule->conditions[0], features);
    
    for (int i = 1; i < rule->condition_count; i++) {
        bool current_result = evaluate_condition(&rule->conditions[i], features);
        
        if (rule->logic_operator == LOGIC_AND) {
            first_result = first_result && current_result;
        } else {
            first_result = first_result || current_result;
        }
    }
    
    return first_result;
}

flow_condition_type_t string_to_condition_type(const char *str) {
    if (strcmp(str, "flow_duration") == 0) return CONDITION_FLOW_DURATION;
    if (strcmp(str, "fwd_packets") == 0) return CONDITION_FWD_PACKETS;
    if (strcmp(str, "bwd_packets") == 0) return CONDITION_BWD_PACKETS;
    if (strcmp(str, "fwd_bytes") == 0) return CONDITION_FWD_BYTES;
    if (strcmp(str, "bwd_bytes") == 0) return CONDITION_BWD_BYTES;
    if (strcmp(str, "packet_length_mean") == 0) return CONDITION_PACKET_LENGTH_MEAN;
    if (strcmp(str, "packet_length_std") == 0) return CONDITION_PACKET_LENGTH_STD;
    if (strcmp(str, "fwd_packet_length_mean") == 0) return CONDITION_FWD_PACKET_LENGTH_MEAN;
    if (strcmp(str, "bwd_packet_length_mean") == 0) return CONDITION_BWD_PACKET_LENGTH_MEAN;
    if (strcmp(str, "flow_bytes_per_sec") == 0) return CONDITION_FLOW_BYTES_PER_SEC;
    if (strcmp(str, "flow_packets_per_sec") == 0) return CONDITION_FLOW_PACKETS_PER_SEC;
    if (strcmp(str, "flow_iat_mean") == 0) return CONDITION_FLOW_IAT_MEAN;
    if (strcmp(str, "flow_iat_std") == 0) return CONDITION_FLOW_IAT_STD;
    if (strcmp(str, "flow_iat_min") == 0) return CONDITION_FLOW_IAT_MIN;
    if (strcmp(str, "flow_iat_max") == 0) return CONDITION_FLOW_IAT_MAX;
    if (strcmp(str, "fwd_iat_mean") == 0) return CONDITION_FWD_IAT_MEAN;
    if (strcmp(str, "bwd_iat_mean") == 0) return CONDITION_BWD_IAT_MEAN;
    if (strcmp(str, "syn_flag_count") == 0) return CONDITION_SYN_FLAG_COUNT;
    if (strcmp(str, "ack_flag_count") == 0) return CONDITION_ACK_FLAG_COUNT;
    if (strcmp(str, "fin_flag_count") == 0) return CONDITION_FIN_FLAG_COUNT;
    if (strcmp(str, "rst_flag_count") == 0) return CONDITION_RST_FLAG_COUNT;
    if (strcmp(str, "psh_flag_count") == 0) return CONDITION_PSH_FLAG_COUNT;
    if (strcmp(str, "urg_flag_count") == 0) return CONDITION_URG_FLAG_COUNT;
    if (strcmp(str, "down_up_ratio") == 0) return CONDITION_DOWN_UP_RATIO;
    if (strcmp(str, "avg_packet_size") == 0) return CONDITION_AVG_PACKET_SIZE;
    return CONDITION_FLOW_DURATION; // default
}

flow_operator_t string_to_operator(const char *str) {
    if (strcmp(str, ">") == 0) return OPERATOR_GT;
    if (strcmp(str, "<") == 0) return OPERATOR_LT;
    if (strcmp(str, ">=") == 0) return OPERATOR_GTE;
    if (strcmp(str, "<=") == 0) return OPERATOR_LTE;
    if (strcmp(str, "==") == 0) return OPERATOR_EQ;
    if (strcmp(str, "!=") == 0) return OPERATOR_NEQ;
    return OPERATOR_GT; // default
}

bool parse_rule_condition(const char *condition_str, flow_condition_t *condition) {
    char feature[64], operator[8], value_str[32];
    
    // Parse: "feature operator value"
    if (sscanf(condition_str, "%63s %7s %31s", feature, operator, value_str) != 3) {
        return false;
    }
    
    condition->type = string_to_condition_type(feature);
    condition->operator = string_to_operator(operator);
    condition->value = atof(value_str);
    
    return true;
}

bool add_rule_from_string(flow_ruleset_t *ruleset, const char *rule_str) {
    if (!ruleset || !rule_str || ruleset->rule_count >= MAX_RULES) return false;
    
    pthread_mutex_lock(&ruleset->mutex);
    
    flow_rule_t *rule = &ruleset->rules[ruleset->rule_count];
    memset(rule, 0, sizeof(flow_rule_t));
    
    // Simple rule format: "sid:1001 msg:\"Port Scan Detected\" flow_iat_mean < 1000 AND syn_flag_count > 5"
    char *rule_copy = strdup(rule_str);
    char *token;
    char *saveptr;
    
    rule->enabled = true;
    rule->priority = 3;
    rule->logic_operator = LOGIC_AND;
    rule->condition_count = 0;
    
    token = strtok_r(rule_copy, " ", &saveptr);
    while (token != NULL) {
        if (strncmp(token, "sid:", 4) == 0) {
            rule->sid = atoi(token + 4);
        }
        else if (strncmp(token, "msg:", 4) == 0) {
            // Handle quoted message
            char *msg_start = strchr(token, '"');
            if (msg_start) {
                msg_start++;
                char *msg_end = strrchr(rule_str, '"');
                if (msg_end > msg_start) {
                    int len = msg_end - msg_start;
                    if (len < MAX_RULE_MSG - 1) {
                        strncpy(rule->msg, msg_start, len);
                        rule->msg[len] = '\0';
                    }
                }
            }
        }
        else if (strncmp(token, "priority:", 9) == 0) {
            rule->priority = atoi(token + 9);
        }
        else if (strcmp(token, "OR") == 0) {
            rule->logic_operator = LOGIC_OR;
        }
        else if (strcmp(token, "AND") == 0) {
            rule->logic_operator = LOGIC_AND;
        }
        else {
            // Try to parse as condition
            char condition_buf[256];
            snprintf(condition_buf, sizeof(condition_buf), "%s", token);
            
            // Get operator and value
            char *next_token = strtok_r(NULL, " ", &saveptr);
            if (next_token) {
                strcat(condition_buf, " ");
                strcat(condition_buf, next_token);
                
                next_token = strtok_r(NULL, " ", &saveptr);
                if (next_token) {
                    strcat(condition_buf, " ");
                    strcat(condition_buf, next_token);
                    
                    if (rule->condition_count < MAX_CONDITIONS) {
                        if (parse_rule_condition(condition_buf, &rule->conditions[rule->condition_count])) {
                            rule->condition_count++;
                        }
                    }
                }
            }
        }
        
        token = strtok_r(NULL, " ", &saveptr);
    }
    
    free(rule_copy);
    
    if (rule->condition_count > 0) {
        ruleset->rule_count++;
        pthread_mutex_unlock(&ruleset->mutex);
        return true;
    }
    
    pthread_mutex_unlock(&ruleset->mutex);
    return false;
}

flow_alert_queue_t* create_alert_queue(int capacity) {
    flow_alert_queue_t *queue = malloc(sizeof(flow_alert_queue_t));
    if (!queue) return NULL;
    
    queue->alerts = malloc(sizeof(flow_alert_t) * capacity);
    if (!queue->alerts) {
        free(queue);
        return NULL;
    }
    
    queue->capacity = capacity;
    queue->count = 0;
    queue->head = 0;
    queue->tail = 0;
    queue->is_full = false;
    
    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        free(queue->alerts);
        free(queue);
        return NULL;
    }
    
    return queue;
}

void destroy_alert_queue(flow_alert_queue_t *queue) {
    if (queue) {
        pthread_mutex_destroy(&queue->mutex);
        free(queue->alerts);
        free(queue);
    }
}

bool enqueue_alert(flow_alert_queue_t *queue, const flow_alert_t *alert) {
    if (!queue || !alert) return false;
    
    pthread_mutex_lock(&queue->mutex);
    
    memcpy(&queue->alerts[queue->tail], alert, sizeof(flow_alert_t));
    queue->tail = (queue->tail + 1) % queue->capacity;
    
    if (queue->count < queue->capacity) {
        queue->count++;
    } else {
        queue->head = (queue->head + 1) % queue->capacity;
        queue->is_full = true;
    }
    
    pthread_mutex_unlock(&queue->mutex);
    return true;
}

bool dequeue_alert(flow_alert_queue_t *queue, flow_alert_t *alert) {
    if (!queue || !alert || queue->count == 0) return false;
    
    pthread_mutex_lock(&queue->mutex);
    
    memcpy(alert, &queue->alerts[queue->head], sizeof(flow_alert_t));
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;
    queue->is_full = false;
    
    pthread_mutex_unlock(&queue->mutex);
    return true;
}

void process_flow_features(flow_rule_engine_t *engine, const flow_features_t *features) {
    if (!engine || !engine->ruleset || !features) return;
    
    pthread_mutex_lock(&engine->ruleset->mutex);
    
    engine->total_features_processed++;
    
    for (int i = 0; i < engine->ruleset->rule_count; i++) {
        flow_rule_t *rule = &engine->ruleset->rules[i];
        rule->evaluations++;
        engine->total_evaluations++;
        
        if (evaluate_rule(rule, features)) {
            rule->matches++;
            engine->total_matches++;
            
            // Create alert
            flow_alert_t alert;
            alert.rule_id = rule->sid;
            strncpy(alert.message, rule->msg, MAX_RULE_MSG - 1);
            alert.message[MAX_RULE_MSG - 1] = '\0';
            alert.confidence = 0.8; // Could be calculated based on rule complexity
            gettimeofday(&alert.timestamp, NULL);
            alert.features = *features;
            
            enqueue_alert(engine->alert_queue, &alert);
        }
    }
    
    pthread_mutex_unlock(&engine->ruleset->mutex);
}

static void* rule_engine_thread_func(void *arg) {
    flow_rule_engine_t *engine = (flow_rule_engine_t*)arg;
    
    while (engine->running) {
        // In a real implementation, this would wait for flow features
        // from Process 1. For now, we'll just sleep.
        struct timespec ts = {0, 10000000}; // 10ms
        nanosleep(&ts, NULL);
    }
    
    return NULL;
}

flow_rule_engine_t* create_flow_rule_engine(int alert_capacity) {
    flow_rule_engine_t *engine = malloc(sizeof(flow_rule_engine_t));
    if (!engine) return NULL;
    
    engine->ruleset = create_ruleset();
    if (!engine->ruleset) {
        free(engine);
        return NULL;
    }
    
    engine->alert_queue = create_alert_queue(alert_capacity);
    if (!engine->alert_queue) {
        destroy_ruleset(engine->ruleset);
        free(engine);
        return NULL;
    }
    
    engine->running = false;
    engine->thread_created = false;
    engine->total_evaluations = 0;
    engine->total_matches = 0;
    engine->total_features_processed = 0;
    
    return engine;
}

void destroy_flow_rule_engine(flow_rule_engine_t *engine) {
    if (engine) {
        if (engine->thread_created && engine->running) {
            stop_rule_engine_thread(engine);
        }
        
        destroy_ruleset(engine->ruleset);
        destroy_alert_queue(engine->alert_queue);
        free(engine);
    }
}

bool start_rule_engine_thread(flow_rule_engine_t *engine) {
    if (!engine || engine->thread_created) return false;
    
    engine->running = true;
    
    if (pthread_create(&engine->thread_id, NULL, rule_engine_thread_func, engine) == 0) {
        engine->thread_created = true;
        return true;
    }
    
    engine->running = false;
    return false;
}

void stop_rule_engine_thread(flow_rule_engine_t *engine) {
    if (engine && engine->thread_created) {
        engine->running = false;
        pthread_join(engine->thread_id, NULL);
        engine->thread_created = false;
    }
}

const char* condition_type_to_string(flow_condition_type_t type) {
    switch (type) {
        case CONDITION_FLOW_DURATION: return "flow_duration";
        case CONDITION_FWD_PACKETS: return "fwd_packets";
        case CONDITION_BWD_PACKETS: return "bwd_packets";
        case CONDITION_FWD_BYTES: return "fwd_bytes";
        case CONDITION_BWD_BYTES: return "bwd_bytes";
        case CONDITION_PACKET_LENGTH_MEAN: return "packet_length_mean";
        case CONDITION_PACKET_LENGTH_STD: return "packet_length_std";
        case CONDITION_FWD_PACKET_LENGTH_MEAN: return "fwd_packet_length_mean";
        case CONDITION_BWD_PACKET_LENGTH_MEAN: return "bwd_packet_length_mean";
        case CONDITION_FLOW_BYTES_PER_SEC: return "flow_bytes_per_sec";
        case CONDITION_FLOW_PACKETS_PER_SEC: return "flow_packets_per_sec";
        case CONDITION_FLOW_IAT_MEAN: return "flow_iat_mean";
        case CONDITION_FLOW_IAT_STD: return "flow_iat_std";
        case CONDITION_FLOW_IAT_MIN: return "flow_iat_min";
        case CONDITION_FLOW_IAT_MAX: return "flow_iat_max";
        case CONDITION_FWD_IAT_MEAN: return "fwd_iat_mean";
        case CONDITION_BWD_IAT_MEAN: return "bwd_iat_mean";
        case CONDITION_SYN_FLAG_COUNT: return "syn_flag_count";
        case CONDITION_ACK_FLAG_COUNT: return "ack_flag_count";
        case CONDITION_FIN_FLAG_COUNT: return "fin_flag_count";
        case CONDITION_RST_FLAG_COUNT: return "rst_flag_count";
        case CONDITION_PSH_FLAG_COUNT: return "psh_flag_count";
        case CONDITION_URG_FLAG_COUNT: return "urg_flag_count";
        case CONDITION_DOWN_UP_RATIO: return "down_up_ratio";
        case CONDITION_AVG_PACKET_SIZE: return "avg_packet_size";
        default: return "unknown";
    }
}

const char* operator_to_string(flow_operator_t op) {
    switch (op) {
        case OPERATOR_GT: return ">";
        case OPERATOR_LT: return "<";
        case OPERATOR_GTE: return ">=";
        case OPERATOR_LTE: return "<=";
        case OPERATOR_EQ: return "==";
        case OPERATOR_NEQ: return "!=";
        default: return "?";
    }
}

void print_ruleset(const flow_ruleset_t *ruleset) {
    if (!ruleset) return;
    
    printf("Flow Ruleset (%d rules):\n", ruleset->rule_count);
    printf("=" "===========================================\n");
    
    for (int i = 0; i < ruleset->rule_count; i++) {
        const flow_rule_t *rule = &ruleset->rules[i];
        
        printf("Rule %d (SID: %u, Priority: %u, %s):\n", 
               i + 1, rule->sid, rule->priority, rule->enabled ? "Enabled" : "Disabled");
        printf("  Message: %s\n", rule->msg);
        printf("  Conditions (%s logic):\n", rule->logic_operator == LOGIC_AND ? "AND" : "OR");
        
        for (int j = 0; j < rule->condition_count; j++) {
            const flow_condition_t *cond = &rule->conditions[j];
            printf("    %s %s %.2f\n", 
                   condition_type_to_string(cond->type),
                   operator_to_string(cond->operator),
                   cond->value);
        }
        
        printf("  Stats: %lu matches / %lu evaluations (%.2f%%)\n", 
               rule->matches, rule->evaluations,
               rule->evaluations > 0 ? (rule->matches * 100.0 / rule->evaluations) : 0.0);
        printf("\n");
    }
}