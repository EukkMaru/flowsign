CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -g -O2 -D_GNU_SOURCE -I. -Isnort3/src -Isnort3/src/protocols/test -I/usr/local/include
LIBS = -lm -lpthread -luv -lpcap

SOURCES = flow_analyzer.cpp flow_rules.cpp snortsharp_integration.cpp event_system.cpp performance_test.cpp snortsharp_inspector.cpp dataset_loader.cpp unsw_nb15_pcap_loader.cpp parallel_snort_integration.cpp snort3_snortsharp_bridge.cpp
HEADERS = flow_analyzer.hpp flow_rules.hpp snortsharp_integration.hpp event_system.hpp performance_test.hpp snortsharp_inspector.hpp dataset_loader.hpp unsw_nb15_pcap_loader.hpp parallel_snort_integration.hpp snort3_snortsharp_bridge.hpp
OBJECTS = $(SOURCES:.cpp=.o)
TEST_SOURCES = flow_test.cpp
INTERACTIVE_SOURCES = interactive_test.cpp
DEMO_SOURCES = demo_test.cpp
VALIDATION_SOURCES = validation_test.cpp
VERBOSE_SOURCES = verbose_test.cpp
PROC1_SOURCES = proc1_test.cpp
PROC2_SOURCES = proc2_test.cpp
PROC2_EVENTS_SOURCES = proc2_test_events.cpp
BENCHMARK_SOURCES = benchmark_test.cpp
INTEGRATED_SOURCES = integrated_test.cpp
SNORT_INTEGRATION_SOURCES = snort_integration_test.cpp
FULL_INTEGRATION_SOURCES = full_snort_integration_test.cpp
DATASET_BENCHMARK_SOURCES = dataset_benchmark_test.cpp
UNSW_DEMO_SOURCES = unsw_nb15_demo_test.cpp
PARALLEL_INTEGRATION_SOURCES = parallel_integration_test.cpp
SIMPLE_PARALLEL_SOURCES = simple_parallel_test.cpp
UNSW_PARALLEL_SOURCES = unsw_parallel_test.cpp
REAL_SNORT3_INTEGRATION_SOURCES = real_snort3_integration_test.cpp
DUAL_ENGINE_UNSW_SOURCES = dual_engine_unsw_test.cpp
TEST_OBJECTS = $(TEST_SOURCES:.cpp=.o)
INTERACTIVE_OBJECTS = $(INTERACTIVE_SOURCES:.cpp=.o)
DEMO_OBJECTS = $(DEMO_SOURCES:.cpp=.o)
VALIDATION_OBJECTS = $(VALIDATION_SOURCES:.cpp=.o)
VERBOSE_OBJECTS = $(VERBOSE_SOURCES:.cpp=.o)
PROC1_OBJECTS = $(PROC1_SOURCES:.cpp=.o)
PROC2_OBJECTS = $(PROC2_SOURCES:.cpp=.o)
PROC2_EVENTS_OBJECTS = $(PROC2_EVENTS_SOURCES:.cpp=.o)
BENCHMARK_OBJECTS = $(BENCHMARK_SOURCES:.cpp=.o)
INTEGRATED_OBJECTS = $(INTEGRATED_SOURCES:.cpp=.o)
SNORT_INTEGRATION_OBJECTS = $(SNORT_INTEGRATION_SOURCES:.cpp=.o)
FULL_INTEGRATION_OBJECTS = $(FULL_INTEGRATION_SOURCES:.cpp=.o)
DATASET_BENCHMARK_OBJECTS = $(DATASET_BENCHMARK_SOURCES:.cpp=.o)
UNSW_DEMO_OBJECTS = $(UNSW_DEMO_SOURCES:.cpp=.o)
PARALLEL_INTEGRATION_OBJECTS = $(PARALLEL_INTEGRATION_SOURCES:.cpp=.o)
SIMPLE_PARALLEL_OBJECTS = $(SIMPLE_PARALLEL_SOURCES:.cpp=.o)
UNSW_PARALLEL_OBJECTS = $(UNSW_PARALLEL_SOURCES:.cpp=.o)
REAL_SNORT3_INTEGRATION_OBJECTS = $(REAL_SNORT3_INTEGRATION_SOURCES:.cpp=.o)
DUAL_ENGINE_UNSW_OBJECTS = $(DUAL_ENGINE_UNSW_SOURCES:.cpp=.o)

TARGET = libflowanalyzer.a
TEST_TARGET = flow_test
INTERACTIVE_TARGET = interactive_test
DEMO_TARGET = demo_test
VALIDATION_TARGET = validation_test
VERBOSE_TARGET = verbose_test
PROC1_TARGET = proc1_test
PROC2_TARGET = proc2_test
PROC2_EVENTS_TARGET = proc2_test_events
BENCHMARK_TARGET = benchmark_test
INTEGRATED_TARGET = integrated_test
SNORT_INTEGRATION_TARGET = snort_integration_test
FULL_INTEGRATION_TARGET = full_snort_integration_test
DATASET_BENCHMARK_TARGET = dataset_benchmark_test
UNSW_DEMO_TARGET = unsw_nb15_demo_test
PARALLEL_INTEGRATION_TARGET = parallel_integration_test
SIMPLE_PARALLEL_TARGET = simple_parallel_test
UNSW_PARALLEL_TARGET = unsw_parallel_test
REAL_SNORT3_INTEGRATION_TARGET = real_snort3_integration_test
DUAL_ENGINE_UNSW_TARGET = dual_engine_unsw_test

.PHONY: all clean test dual-engine-test

all: $(TARGET) $(TEST_TARGET) $(INTERACTIVE_TARGET) $(DEMO_TARGET) $(VALIDATION_TARGET) $(VERBOSE_TARGET) $(PROC1_TARGET) $(PROC2_TARGET) $(PROC2_EVENTS_TARGET) $(BENCHMARK_TARGET) $(INTEGRATED_TARGET) $(SNORT_INTEGRATION_TARGET) $(FULL_INTEGRATION_TARGET) $(DATASET_BENCHMARK_TARGET) $(UNSW_DEMO_TARGET) $(SIMPLE_PARALLEL_TARGET)

$(TARGET): $(OBJECTS)
	ar rcs $@ $^

$(TEST_TARGET): $(TEST_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(INTERACTIVE_TARGET): $(INTERACTIVE_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(DEMO_TARGET): $(DEMO_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(VALIDATION_TARGET): $(VALIDATION_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(VERBOSE_TARGET): $(VERBOSE_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(PROC1_TARGET): $(PROC1_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(PROC2_TARGET): $(PROC2_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(PROC2_EVENTS_TARGET): $(PROC2_EVENTS_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(BENCHMARK_TARGET): $(BENCHMARK_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(INTEGRATED_TARGET): $(INTEGRATED_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(SNORT_INTEGRATION_TARGET): $(SNORT_INTEGRATION_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(FULL_INTEGRATION_TARGET): $(FULL_INTEGRATION_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(DATASET_BENCHMARK_TARGET): $(DATASET_BENCHMARK_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(UNSW_DEMO_TARGET): $(UNSW_DEMO_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(PARALLEL_INTEGRATION_TARGET): $(PARALLEL_INTEGRATION_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(SIMPLE_PARALLEL_TARGET): $(SIMPLE_PARALLEL_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(UNSW_PARALLEL_TARGET): $(UNSW_PARALLEL_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(REAL_SNORT3_INTEGRATION_TARGET): $(REAL_SNORT3_INTEGRATION_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(DUAL_ENGINE_UNSW_TARGET): $(DUAL_ENGINE_UNSW_OBJECTS) $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

dual-engine-test: $(DUAL_ENGINE_UNSW_TARGET)
	./$(DUAL_ENGINE_UNSW_TARGET)

clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS) $(INTERACTIVE_OBJECTS) $(DEMO_OBJECTS) $(VALIDATION_OBJECTS) $(VERBOSE_OBJECTS) $(PROC1_OBJECTS) $(PROC2_OBJECTS) $(PROC2_EVENTS_OBJECTS) $(BENCHMARK_OBJECTS) $(INTEGRATED_OBJECTS) $(SNORT_INTEGRATION_OBJECTS) $(FULL_INTEGRATION_OBJECTS) $(DATASET_BENCHMARK_OBJECTS) $(UNSW_DEMO_OBJECTS) $(PARALLEL_INTEGRATION_OBJECTS) $(SIMPLE_PARALLEL_OBJECTS) $(TARGET) $(TEST_TARGET) $(INTERACTIVE_TARGET) $(DEMO_TARGET) $(VALIDATION_TARGET) $(VERBOSE_TARGET) $(PROC1_TARGET) $(PROC2_TARGET) $(PROC2_EVENTS_TARGET) $(BENCHMARK_TARGET) $(INTEGRATED_TARGET) $(SNORT_INTEGRATION_TARGET) $(FULL_INTEGRATION_TARGET) $(DATASET_BENCHMARK_TARGET) $(UNSW_DEMO_TARGET) $(PARALLEL_INTEGRATION_TARGET) $(SIMPLE_PARALLEL_TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/lib/
	cp $(HEADERS) /usr/local/include/

interactive: $(INTERACTIVE_TARGET)
	./$(INTERACTIVE_TARGET)

demo: $(DEMO_TARGET)
	./$(DEMO_TARGET)

validate: $(VALIDATION_TARGET)
	./$(VALIDATION_TARGET)

verbose: $(VERBOSE_TARGET)
	./$(VERBOSE_TARGET)

proc1: $(PROC1_TARGET)
	./$(PROC1_TARGET)

proc2: $(PROC2_TARGET)
	./$(PROC2_TARGET)

proc2-events: $(PROC2_EVENTS_TARGET)
	./$(PROC2_EVENTS_TARGET)

benchmark: $(BENCHMARK_TARGET)
	./$(BENCHMARK_TARGET)

integrated: $(INTEGRATED_TARGET)
	./$(INTEGRATED_TARGET)

snort-integration: $(SNORT_INTEGRATION_TARGET)
	./$(SNORT_INTEGRATION_TARGET)

full-integration: $(FULL_INTEGRATION_TARGET)
	./$(FULL_INTEGRATION_TARGET)

dataset-benchmark: $(DATASET_BENCHMARK_TARGET)
	./$(DATASET_BENCHMARK_TARGET)

unsw-demo: $(UNSW_DEMO_TARGET)
	./$(UNSW_DEMO_TARGET)

parallel-basic: $(PARALLEL_INTEGRATION_TARGET)
	./$(PARALLEL_INTEGRATION_TARGET) basic

parallel-pcap: $(PARALLEL_INTEGRATION_TARGET)
	./$(PARALLEL_INTEGRATION_TARGET) pcap

parallel-compare: $(PARALLEL_INTEGRATION_TARGET)
	./$(PARALLEL_INTEGRATION_TARGET) compare

parallel-all: $(PARALLEL_INTEGRATION_TARGET)
	./$(PARALLEL_INTEGRATION_TARGET) all

simple-parallel: $(SIMPLE_PARALLEL_TARGET)
	./$(SIMPLE_PARALLEL_TARGET)

unsw-parallel: $(UNSW_PARALLEL_TARGET)
	./$(UNSW_PARALLEL_TARGET)

real-snort3-integration: $(REAL_SNORT3_INTEGRATION_TARGET)
	./$(REAL_SNORT3_INTEGRATION_TARGET)

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all         - Build library and all test programs"
	@echo "  test        - Build and run basic test program"
	@echo "  interactive - Build and run interactive test program" 
	@echo "  demo        - Build and run demonstration scenarios"
	@echo "  validate    - Build and run validation tests"
	@echo "  verbose     - Build and run verbose internal state viewer"
	@echo "  proc1       - Build and run Process 1 (flow analyzer) test"
	@echo "  proc2       - Build and run Process 2 (rule engine) test"
	@echo "  proc2-events - Build and run Process 2 with libuv event system"
	@echo "  benchmark   - Build and run performance benchmark suite"
	@echo "  integrated  - Build and run Process 1+2 integration test"
	@echo "  snort-integration - Build and run Snort3 integration test"
	@echo "  full-integration - Build and run comprehensive integration test with real traffic"
	@echo "  dataset-benchmark - Build and run UNSW-NB15 dataset benchmark suite"
	@echo "  unsw-demo   - Build and run UNSW-NB15 PCAP processing demo"
	@echo "  parallel-basic - Build and run basic parallel Snort3+SnortSharp test"
	@echo "  parallel-pcap - Build and run PCAP parallel processing test"
	@echo "  parallel-compare - Build and run parallel vs sequential comparison"
	@echo "  parallel-all - Build and run all parallel integration tests"
	@echo "  clean       - Remove all built files"
	@echo "  install     - Install library and headers (requires sudo)"
	@echo "  help        - Show this help message"

# Test runner shortcuts (same as run_tests.sh functionality)
.PHONY: run-basic run-demo run-validate run-verbose run-proc2 run-integrated run-all

run-basic: test

run-demo: demo

run-validate: validate

run-verbose: verbose

run-proc2: proc2

run-integrated: integrated

run-all: run-basic run-demo run-verbose run-proc2 run-integrated run-validate
	@echo
	@echo "ALL CORE TESTS COMPLETED!"
	@echo "Both Process 1 (Flow Analysis) and Process 2 (Rule Engine) working correctly!"