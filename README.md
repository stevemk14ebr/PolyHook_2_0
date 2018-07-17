# PolyHook 2.0
C+11, x86/x64 Hooking Libary v2.0

# Build

```
cd capstone
mkdir build && mkdir build64
cd build
cmake .. -DCAPSTONE_BUILD_TESTS=OFF
cmake --build . --config Release
cmake --build . --config Debug

cd ../build64
cmake .. -DCAPSTONE_BUILD_TESTS=OFF -DCMAKE_GENERATOR_PLATFORM=x64
cmake --build . --config Release
cmake --build . --config Debug
```

# Future
Linux support

# License
MIT - Please consider donating
