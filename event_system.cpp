#include "event_system.hpp"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sys/time.h>
#include <unistd.h>
#include <sstream>

EventSystem::EventSystem(const std::string& pipe_name, bool is_server)
    : pipe_name_(pipe_name), is_server_(is_server), is_running_(false), 
      callback_(nullptr), user_data_(nullptr) {
    
    // initialize libuv loop
    loop_ = std::make_unique<uv_loop_t>();
    if(uv_loop_init(loop_.get()) != 0) {
        throw std::runtime_error("Failed to initialize libuv loop");
    }
    
    if(is_server_) {
        pipe_server_ = std::make_unique<uv_pipe_t>();
        uv_pipe_init(loop_.get(), pipe_server_.get(), 0);
        pipe_server_->data = this;
    } else {
        pipe_client_ = std::make_unique<uv_pipe_t>();
        uv_pipe_init(loop_.get(), pipe_client_.get(), 0);
        pipe_client_->data = this;
    }
}

EventSystem::~EventSystem() {
    if(is_running_.load()) {
        if(is_server_) {
            stop_event_server();
        } else {
            disconnect_event_client();
        }
    }
    
    cleanup_handles();
    
    if(thread_.joinable()) {
        thread_.join();
    }
    
    if(loop_) {
        uv_loop_close(loop_.get());
    }
}

void EventSystem::cleanup_handles() {
    if(loop_) {
        uv_walk(loop_.get(), walk_cb, nullptr);
        uv_run(loop_.get(), UV_RUN_NOWAIT);
    }
}

int EventSystem::start_event_server(EventCallback callback, void* user_data) {
    if(!is_server_) return -1;
    
    callback_ = callback;
    user_data_ = user_data;
    
    // remove existing pipe if it exists
    unlink(pipe_name_.c_str());
    
    int r = uv_pipe_bind(pipe_server_.get(), pipe_name_.c_str());
    if(r) {
        std::cerr << "Bind error: " << uv_strerror(r) << std::endl;
        return r;
    }
    
    r = uv_listen((uv_stream_t*)pipe_server_.get(), 128, connection_cb);
    if(r) {
        std::cerr << "Listen error: " << uv_strerror(r) << std::endl;
        return r;
    }
    
    is_running_.store(true);
    std::cout << "[EVENT] Server listening on: " << pipe_name_ << std::endl;
    
    // start event loop in separate thread
    thread_ = std::thread([this]() { run_event_loop(); });
    
    return 0;
}

void EventSystem::stop_event_server() {
    if(!is_running_.load()) return;
    
    is_running_.store(false);
    uv_stop(loop_.get());
    
    // wait for thread to finish
    if(thread_.joinable()) {
        thread_.join();
    }
    
    std::cout << "[EVENT] Server stopped" << std::endl;
}

int EventSystem::connect_event_client() {
    if(is_server_) return -1;
    
    auto connect_req = std::make_unique<uv_connect_t>();
    connect_req->data = this;
    
    uv_pipe_connect(connect_req.release(), pipe_client_.get(), pipe_name_.c_str(), connect_cb);
    
    return 0;
}

int EventSystem::broadcast_window_event(uint32_t flow_id, const FlowFeatures& features, const std::string& source) {
    if(is_server_) return -1;
    
    WindowEvent event;
    event.type = EventType::WINDOW_UPDATE;
    event.flow_id = flow_id;
    gettimeofday(&event.timestamp, nullptr);
    event.features = features;
    event.source_process = source;
    
    std::string serialized = serialize_event(event);
    
    auto write_req = std::make_unique<WriteReq>();
    write_req->data = std::make_unique<char[]>(serialized.length());
    std::memcpy(write_req->data.get(), serialized.c_str(), serialized.length());
    
    write_req->buf = uv_buf_init(write_req->data.get(), serialized.length());
    
    WriteReq* req_ptr = write_req.release();
    int r = uv_write(&req_ptr->req, (uv_stream_t*)pipe_client_.get(), &req_ptr->buf, 1, write_cb);
    if(r) {
        std::cerr << "Write error: " << uv_strerror(r) << std::endl;
        delete req_ptr;
        return r;
    }
    
    return 0;
}

int EventSystem::send_shutdown_event() {
    if(is_server_) return -1;
    
    WindowEvent event;
    event.type = EventType::SHUTDOWN;
    event.flow_id = 0;
    gettimeofday(&event.timestamp, nullptr);
    memset(&event.features, 0, sizeof(FlowFeatures));
    event.source_process = "proc1";
    
    std::string serialized = serialize_event(event);
    
    auto write_req = std::make_unique<WriteReq>();
    write_req->data = std::make_unique<char[]>(serialized.length());
    std::memcpy(write_req->data.get(), serialized.c_str(), serialized.length());
    
    write_req->buf = uv_buf_init(write_req->data.get(), serialized.length());
    
    WriteReq* req_ptr = write_req.release();
    int r = uv_write(&req_ptr->req, (uv_stream_t*)pipe_client_.get(), &req_ptr->buf, 1, write_cb);
    if(r) {
        std::cerr << "Shutdown write error: " << uv_strerror(r) << std::endl;
        delete req_ptr;
        return r;
    }
    
    return 0;
}

void EventSystem::disconnect_event_client() {
    if(is_server_) return;
    
    uv_close((uv_handle_t*)pipe_client_.get(), close_cb);
    std::cout << "[EVENT] Client disconnected" << std::endl;
}

void EventSystem::run_event_loop() {
    std::cout << "[EVENT] Starting event loop" << std::endl;
    uv_run(loop_.get(), UV_RUN_DEFAULT);
    std::cout << "[EVENT] Event loop finished" << std::endl;
}

// static libuv callback functions (C-compatible)
void EventSystem::alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    (void)handle;
    buf->base = new char[suggested_size];
    buf->len = suggested_size;
}

void EventSystem::read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    EventSystem* system = static_cast<EventSystem*>(stream->data);
    
    if(nread < 0) {
        if(nread != UV_EOF) {
            std::cerr << "Read error: " << uv_strerror(nread) << std::endl;
        }
        uv_close((uv_handle_t*)stream, close_cb);
        if(buf->base) delete[] buf->base;
        return;
    }
    
    if(nread == 0) {
        if(buf->base) delete[] buf->base;
        return;
    }
    
    // process received event
    if(nread > 0 && system->callback_) {
        system->process_received_data(buf->base, nread);
    }
    
    if(buf->base) delete[] buf->base;
}

void EventSystem::connection_cb(uv_stream_t* server, int status) {
    if(status < 0) {
        std::cerr << "Connection error: " << uv_strerror(status) << std::endl;
        return;
    }
    
    EventSystem* system = static_cast<EventSystem*>(server->data);
    auto client = std::make_unique<uv_pipe_t>();
    uv_pipe_init(system->loop_.get(), client.get(), 0);
    client->data = system;
    
    if(uv_accept(server, (uv_stream_t*)client.get()) == 0) {
        uv_read_start((uv_stream_t*)client.get(), alloc_cb, read_cb);
        // transfer ownership to libuv - will be cleaned up in close_cb
        client.release();
    } else {
        uv_close((uv_handle_t*)client.get(), close_cb);
        client.release();
    }
}

void EventSystem::connect_cb(uv_connect_t* req, int status) {
    if(status < 0) {
        std::cerr << "Connect error: " << uv_strerror(status) << std::endl;
        delete req;
        return;
    }
    
    EventSystem* system = static_cast<EventSystem*>(req->data);
    std::cout << "[EVENT] Connected to event server: " << system->pipe_name_ << std::endl;
    
    delete req;
}

void EventSystem::write_cb(uv_write_t* req, int status) {
    if(status < 0) {
        std::cerr << "Write error: " << uv_strerror(status) << std::endl;
    }
    
    WriteReq* write_req = reinterpret_cast<WriteReq*>(req);
    delete write_req;
}

void EventSystem::close_cb(uv_handle_t* handle) {
    if(handle->type == UV_NAMED_PIPE) {
        delete reinterpret_cast<uv_pipe_t*>(handle);
    }
}

void EventSystem::walk_cb(uv_handle_t* handle, void* arg) {
    (void)arg;
    if(!uv_is_closing(handle)) {
        uv_close(handle, close_cb);
    }
}

void EventSystem::process_received_data(const char* data, size_t len) {
    if(len < sizeof(int) + sizeof(uint32_t) + sizeof(struct timeval) + sizeof(FlowFeatures)) {
        return; // insufficient data for a complete event
    }
    
    WindowEvent event = deserialize_event(data, len);
    if(callback_) {
        callback_(event, user_data_);
    }
}

WindowEvent EventSystem::deserialize_event(const char* data, size_t len) {
    WindowEvent event;
    const char* ptr = data;
    
    // deserialize type
    int type_val = *reinterpret_cast<const int*>(ptr);
    event.type = static_cast<EventType>(type_val);
    ptr += sizeof(int);
    
    // deserialize flow_id
    event.flow_id = *reinterpret_cast<const uint32_t*>(ptr);
    ptr += sizeof(uint32_t);
    
    // deserialize timestamp
    event.timestamp = *reinterpret_cast<const struct timeval*>(ptr);
    ptr += sizeof(struct timeval);
    
    // deserialize features
    event.features = *reinterpret_cast<const FlowFeatures*>(ptr);
    ptr += sizeof(FlowFeatures);
    
    // deserialize source_process string
    size_t remaining = len - (ptr - data);
    if(remaining > 0) {
        size_t str_len = std::min(remaining, (size_t)32);
        event.source_process = std::string(ptr, str_len);
        // remove null terminator if present
        size_t null_pos = event.source_process.find('\0');
        if(null_pos != std::string::npos) {
            event.source_process = event.source_process.substr(0, null_pos);
        }
    }
    
    return event;
}

std::string EventSystem::serialize_event(const WindowEvent& event) {
    std::ostringstream oss;
    
    // serialize type
    int type_val = static_cast<int>(event.type);
    oss.write(reinterpret_cast<const char*>(&type_val), sizeof(int));
    
    // serialize flow_id
    oss.write(reinterpret_cast<const char*>(&event.flow_id), sizeof(uint32_t));
    
    // serialize timestamp
    oss.write(reinterpret_cast<const char*>(&event.timestamp), sizeof(struct timeval));
    
    // serialize features
    oss.write(reinterpret_cast<const char*>(&event.features), sizeof(FlowFeatures));
    
    // serialize source_process string (with null terminator for C compatibility)
    std::string source_padded = event.source_process;
    source_padded.resize(32, '\0'); // pad to 32 chars like original C version
    oss.write(source_padded.c_str(), 32);
    
    return oss.str();
}