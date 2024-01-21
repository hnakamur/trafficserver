find_library(wasmtime_LIBRARY NAMES wasmtime)

set(wasm_wasm_sources
    lib/src/bytecode_util.cc
    lib/include/proxy-wasm/bytecode_util.h
    lib/src/context.cc
    lib/include/proxy-wasm/context.h
    lib/include/proxy-wasm/context_interface.h
    lib/src/exports.cc
    lib/include/proxy-wasm/exports.h
    lib/include/proxy-wasm/limits.h
    lib/src/shared_data.cc
    lib/src/shared_queue.cc
    lib/src/hash.cc
    lib/src/hash.h
    lib/src/signature_util.cc
    lib/include/proxy-wasm/signature_util.h
    lib/src/vm_id_handle.cc
    lib/include/proxy-wasm/vm_id_handle.h
    lib/src/pairs_util.cc
    lib/include/proxy-wasm/pairs_util.h
    lib/include/proxy-wasm/wasm_vm.h
    lib/src/wasm.cc
    lib/include/proxy-wasm/wasm.h
    ats_wasm.cc
    ats_wasm.h
    ats_context.cc
    ats_context.h
    wasm_main.cc
    lib/src/common/types.h
    lib/include/proxy-wasm/word.h
    lib/src/wasmtime/wasmtime.cc
    lib/src/wasmtime/types.h
    lib/include/proxy-wasm/wasmtime.h
)

add_atsplugin(wasm ${wasm_wasm_sources})
target_include_directories(wasm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib)
target_compile_definitions(wasm PRIVATE WASMTIME)
target_link_libraries(wasm PRIVATE ${wasmtime_LIBRARY})
