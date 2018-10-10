cd capstone
mkdir build32
mkdir build64
cd build32
cmake -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32 -DCMAKE_BUILD_TYPE=Release ../
make
cmake -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32 -DCMAKE_BUILD_TYPE=Debug -DCMAKE_DEBUG_POSTFIX=_debug ../
make
cd ../
cd build64
cmake -DCMAKE_BUILD_TYPE=Release ../
make
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_DEBUG_POSTFIX=_debug ../
make
