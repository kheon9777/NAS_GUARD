# Makefile
# 사용법
#   make              릴리스 빌드  -> build/release/guard
#   make DEBUG=1      디버그 빌드  -> build/debug/guard  (최적화 끔, 디버그 정보, 메모리 오류 검사)
#   make run          빌드 후 sudo로 실행 (DEBUG=1과 같이 쓰면 디버그 빌드 실행)
#   make clean        build 폴더 전체 삭제

TARGET   := guard
SRC_DIR  := src
INC_DIR  := include

CXX      := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -Wpedantic -I$(INC_DIR) -MMD -MP
LDFLAGS  :=
LDLIBS   := -lsqlite3

ifeq ($(DEBUG),1)
    BUILD_DIR := build/debug
    CXXFLAGS  += -O0 -g -fsanitize=address,undefined
    LDFLAGS   += -fsanitize=address,undefined
else
    BUILD_DIR := build/release
    CXXFLAGS  += -O2
endif

# src 아래 모든 .cpp (하위 폴더 포함)
SRCS := $(shell find $(SRC_DIR) -name '*.cpp')
# src/a/b.cpp -> build/release/a/b.o
OBJS := $(SRCS:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)
# 각 .o 옆에 생기는 헤더 의존성 파일
DEPS := $(OBJS:.o=.d)

.PHONY: all run clean

all: $(BUILD_DIR)/$(TARGET)

# 링크: 모든 .o를 묶어 실행 파일 생성 (라이브러리는 맨 뒤)
$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# 컴파일: .cpp 하나 -> .o 하나
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: all
	sudo ./$(BUILD_DIR)/$(TARGET)

clean:
	rm -rf build

# 헤더가 바뀌면 그 헤더를 쓰는 .cpp만 다시 컴파일되도록
-include $(DEPS)