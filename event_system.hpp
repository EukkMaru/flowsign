#ifndef EVENT_SYSTEM_HPP
#define EVENT_SYSTEM_HPP

#include <uv.h>
#include <memory>
#include <functional>
#include <string>
#include <thread>
#include <atomic>
#include "flow_analyzer.hpp"

enum class EventType {
    WINDOW_UPDATE,
    FLOW_COMPLETE,
    SHUTDOWN
};

struct WindowEvent {
    EventType type;
    uint32_t flow_id;
    struct timeval timestamp;
    FlowFeatures features;
    std::string source_process;  // "proc1" or "proc2"
    
    WindowEvent() : type(EventType::WINDOW_UPDATE), flow_id(0), timestamp{}, features{}, source_process{} {}
};

// event callback function type
using EventCallback = std::function<void(const WindowEvent& event, void* user_data)>;

class EventSystem {
private:
    std::unique_ptr<uv_loop_t> loop_;
    std::unique_ptr<uv_pipe_t> pipe_server_;
    std::unique_ptr<uv_pipe_t> pipe_client_;
    std::string pipe_name_;
    bool is_server_;
    std::atomic<bool> is_running_;
    EventCallback callback_;
    void* user_data_;
    std::thread thread_;

    // write request structure for async operations
    struct WriteReq {
        uv_write_t req;
        uv_buf_t buf;
        std::unique_ptr<char[]> data;
    };

public:
    EventSystem(const std::string& pipe_name, bool is_server);
    ~EventSystem();
    
    // disable copy constructor and assignment
    EventSystem(const EventSystem&) = delete;
    EventSystem& operator=(const EventSystem&) = delete;
    
    // server functions (proc2 - rule engine)
    int start_event_server(EventCallback callback, void* user_data);
    void stop_event_server();
    
    // client functions (proc1 - flow analyzer)  
    int connect_event_client();
    int broadcast_window_event(uint32_t flow_id, const FlowFeatures& features, const std::string& source);
    void disconnect_event_client();
    
    // utility functions
    void run_event_loop();
    int send_shutdown_event();
    
    bool is_running() const { return is_running_.load(); }
    bool is_server() const { return is_server_; }

private:
    // libuv callback functions (static for C compatibility)
    static void alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
    static void read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
    static void connection_cb(uv_stream_t* server, int status);
    static void connect_cb(uv_connect_t* req, int status);
    static void write_cb(uv_write_t* req, int status);
    static void close_cb(uv_handle_t* handle);
    static void walk_cb(uv_handle_t* handle, void* arg);
    
    // helper functions
    void process_received_data(const char* data, size_t len);
    WindowEvent deserialize_event(const char* data, size_t len);
    std::string serialize_event(const WindowEvent& event);
    void cleanup_handles();
};

#endif // EVENT_SYSTEM_HPP