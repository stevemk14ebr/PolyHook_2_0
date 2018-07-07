cd capstone
mkdir build32
mkdir build64
cd build32
cmake -G "Visual Studio 15 2017" ../
cd ../
cd build64
cmake -G "Visual Studio 15 2017 Win64" ../
cd ../
cmake --build build32 --config Debug
cmake --build build32 --config Release
cmake --build build64 --config Debug
cmake --build build64 --config Release