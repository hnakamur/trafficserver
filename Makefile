CC = clang-16
CXX = clang++-16
CLANG_FORMAT = clang-format-16

build: setup
	cmake --build build --config Release -v

test: build
	cmake --build build --config Release --target test -v

install: test
	sudo cmake --build build --config Release --target install -v
	sudo chown -R $$USER: build

debug_build: setup
	cmake --build build --config Debug -v

debug_test: debug_build
	cmake --build build --config Debug --target test -v

format: setup
	cmake --build build --config Release --target format -v

setup:
	if [ ! -d build ]; then \
	CC=$(CC) CXX=$(CXX) cmake -B build -G "Ninja Multi-Config" -DCLANG_FORMAT=$(CLANG_FORMAT) \
	-DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/trafficserver \
        -DCMAKE_INSTALL_BINDIR=bin \
        -DCMAKE_INSTALL_SBINDIR=bin \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_INSTALL_LIBEXECDIR=lib/modules \
        -DCMAKE_INSTALL_SYSCONFDIR=etc \
        -DCMAKE_INSTALL_LOCALSTATEDIR=var \
        -DCMAKE_INSTALL_RUNSTATEDIR=var/run \
        -DCMAKE_INSTALL_DATAROOTDIR=share \
        -DCMAKE_INSTALL_DATADIR=share/data \
        -DCMAKE_INSTALL_DOCDIR=share/doc \
        -DCMAKE_INSTALL_LOGDIR=var/log \
        -DCMAKE_INSTALL_CACHEDIR=var/cache \
        -DBUILD_EXPERIMENTAL_PLUGINS=ON \
        -DENABLE_MAXMIND_ACL=ON \
        -DENABLE_URI_SIGNING=ON \
        -DENABLE_JEMALLOC=ON \
        -DENABLE_AUTEST=ON; \
	fi

clean:
	@rm -rf build

.PHONY: build test install debug_build debug_test format setup clean
