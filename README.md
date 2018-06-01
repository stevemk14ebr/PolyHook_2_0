# PolyHook 2.0
Cross-platform, Cross-Architecture, C+11, x86/x64 Hooking Libary v2.0

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

# License
This project is dual-licensed.

* For non-commercial use: MIT

* For commercial use, contact me to arrange a licensing agreement.

Commercial use does NOT include a project funded through donations. If an organization receives 100% of its revenue from donations then PolyHook may be used under the MIT license. Any other situation at all in which PolyHook is used and money is exchanging hands should involve an email or message to me so that a licensing agreement can be made on a per organization basis, until this occurs i reserve all rights. The goal is that commercial organizations will fund the long term development of this project.
