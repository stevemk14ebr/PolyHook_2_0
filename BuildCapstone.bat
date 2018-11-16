@echo off
cd capstone
mkdir build32
mkdir build64
cd build32
if "%1"=="--capstone-full" (
	echo Building full capstone project...
	cmake -G "Visual Studio 15 2017" ../
) else (
	echo Building x86 only capstone project...
	cmake -G "Visual Studio 15 2017" -DCAPSTONE_ARM_SUPPORT=0 -DCAPSTONE_ARM64_SUPPORT=0 -DCAPSTONE_M680X_SUPPORT=0 -DCAPSTONE_M68K_SUPPORT=0 -DCAPSTONE_MIPS_SUPPORT=0 -DCAPSTONE_PPC_SUPPORT=0 -DCAPSTONE_SPARC_SUPPORT=0 -DCAPSTONE_SYSZ_SUPPORT=0 -DCAPSTONE_XCORE_SUPPORT=0 -DCAPSTONE_TMS320C64X_SUPPORT=0 -DCAPSTONE_M680X_SUPPORT=0 -DCAPSTONE_EVM_SUPPORT=0 ../
)
cd ../
cd build64
if "%1"=="--capstone-full" (
	cmake -G "Visual Studio 15 2017 Win64" ../
) else (
	cmake -G "Visual Studio 15 2017 Win64" -DCAPSTONE_ARM_SUPPORT=0 -DCAPSTONE_ARM64_SUPPORT=0 -DCAPSTONE_M680X_SUPPORT=0 -DCAPSTONE_M68K_SUPPORT=0 -DCAPSTONE_MIPS_SUPPORT=0 -DCAPSTONE_PPC_SUPPORT=0 -DCAPSTONE_SPARC_SUPPORT=0 -DCAPSTONE_SYSZ_SUPPORT=0 -DCAPSTONE_XCORE_SUPPORT=0 -DCAPSTONE_TMS320C64X_SUPPORT=0 -DCAPSTONE_M680X_SUPPORT=0 -DCAPSTONE_EVM_SUPPORT=0 ../
)
cd ../
cmake --build build32 --config Debug
cmake --build build32 --config Release
cmake --build build64 --config Debug
cmake --build build64 --config Release
cd ../
