#! /bin/sh

if [ -z "$1" ]; then
    echo "No version provided. Abort."
    exit 1
fi

cp ./sensor/bin/macosx/*/x86_64/debug/rpHostCommonPlatformExe "./prebuilt_binaries/hcp_osx_x64_debug_$1"
cp ./sensor/bin/macosx/*/x86_64/release/rpHostCommonPlatformExe "./prebuilt_binaries/hcp_osx_x64_release_$1"
cp ./sensor/bin/ubuntu/*/x86_64/debug/rpHostCommonPlatformExe "./prebuilt_binaries/hcp_ubuntu_x64_debug_$1"
cp ./sensor/bin/ubuntu/*/x86_64/release/rpHostCommonPlatformExe "./prebuilt_binaries/hcp_ubuntu_x64_release_$1"
cp ./sensor/bin/windows/Win32/Debug/rphcp.exe "./prebuilt_binaries/hcp_win_x86_debug_$1.exe"
cp ./sensor/bin/windows/Win32/Release/rphcp.exe "./prebuilt_binaries/hcp_win_x86_release_$1.exe"
cp ./sensor/bin/windows/x64/Debug/rphcp.exe "./prebuilt_binaries/hcp_win_x64_debug_$1.exe"
cp ./sensor/bin/windows/x64/Release/rphcp.exe "./prebuilt_binaries/hcp_win_x64_release_$1.exe"
cp ./sensor/bin/macosx/*/x86_64/debug/librpHCP_HostBasedSensor.dylib "./prebuilt_binaries/hbs_osx_x64_debug_$1.dylib"
cp ./sensor/bin/macosx/*/x86_64/release/librpHCP_HostBasedSensor.dylib "./prebuilt_binaries/hbs_osx_x64_release_$1.dylib"
cp ./sensor/bin/ubuntu/*/x86_64/debug/librpHCP_HostBasedSensor.so "./prebuilt_binaries/hbs_ubuntu_x64_debug_$1.so"
cp ./sensor/bin/ubuntu/*/x86_64/release/librpHCP_HostBasedSensor.so "./prebuilt_binaries/hbs_ubuntu_x64_release_$1.so"
cp ./sensor/bin/windows/Win32/Debug/rpHCP_HostBasedSensor.dll "./prebuilt_binaries/hbs_win_x86_debug_$1.dll"
cp ./sensor/bin/windows/Win32/Release/rpHCP_HostBasedSensor.dll "./prebuilt_binaries/hbs_win_x86_release_$1.dll"
cp ./sensor/bin/windows/x64/Debug/rpHCP_HostBasedSensor.dll "./prebuilt_binaries/hbs_win_x64_debug_$1.dll"
cp ./sensor/bin/windows/x64/Release/rpHCP_HostBasedSensor.dll "./prebuilt_binaries/hbs_win_x64_release_$1.dll"

mkdir ./sensor/bin/windows/kernel
cp ./sensor/bin/windows/Win32/Release/hbs_kernel_acquisition.sys ./sensor/bin/windows/kernel/hbs_kernel_acquisition_32.sys
cp ./sensor/bin/windows/x64/Release/hbs_kernel_acquisition.sys ./sensor/bin/windows/kernel/hbs_kernel_acquisition_64.sys

cp ./sensor/bin/macosx/*/x86_64/debug/librpHCP_KernelAcquisition.dylib "./prebuilt_binaries/kernel_osx_x64_debug_$1.dylib"
cp ./sensor/bin/macosx/*/x86_64/release/librpHCP_KernelAcquisition.dylib "./prebuilt_binaries/kernel_osx_x64_release_$1.dylib"

cp ./sensor/bin/windows/x64/Release/rpHCP_KernelAcquisition.dll "./prebuilt_binaries/kernel_win_x64_debug_$1.dll"
cp ./sensor/bin/windows/x64/Debug/rpHCP_KernelAcquisition.dll "./prebuilt_binaries/kernel_win_x64_release_$1.dll"
cp ./sensor/bin/windows/Win32/Release/rpHCP_KernelAcquisition.dll "./prebuilt_binaries/kernel_win_x86_debug_$1.dll"
cp ./sensor/bin/windows/Win32/Debug/rpHCP_KernelAcquisition.dll "./prebuilt_binaries/kernel_win_x86_release_$1.dll"

python ./sensor/scripts/set_sensor_config.py ./sensor/sample_configs/sample_kernel_osx.conf ./prebuilt_binaries/kernel_osx_x64_debug_*.dylib
python ./sensor/scripts/set_sensor_config.py ./sensor/sample_configs/sample_kernel_osx.conf ./prebuilt_binaries/kernel_osx_x64_release_*.dylib

python ./sensor/scripts/set_sensor_config.py ./sensor/sample_configs/sample_kernel_win64.conf ./prebuilt_binaries/kernel_win_x64_debug_*.dll
python ./sensor/scripts/set_sensor_config.py ./sensor/sample_configs/sample_kernel_win64.conf ./prebuilt_binaries/kernel_win_x64_release_*.dll
python ./sensor/scripts/set_sensor_config.py ./sensor/sample_configs/sample_kernel_win32.conf ./prebuilt_binaries/kernel_win_x86_debug_*.dll
python ./sensor/scripts/set_sensor_config.py ./sensor/sample_configs/sample_kernel_win32.conf ./prebuilt_binaries/kernel_win_x86_release_*.dll

cp "./prebuilt_binaries/hcp_ubuntu_x64_debug_$1" ./sensor/scripts/installers/nix/bin
makeself ./sensor/scripts/installers/nix/ ./prebuilt_binaries/ubuntu_debug_x64_$1_installer.run "LIMA CHARLIE $1 Ubuntu x64 Debug Installer" ./install.sh
rm ./sensor/scripts/installers/nix/bin

cp "./prebuilt_binaries/hcp_ubuntu_x64_release_$1" ./sensor/scripts/installers/nix/bin
makeself ./sensor/scripts/installers/nix/ ./prebuilt_binaries/ubuntu_release_x64_$1_installer.run "LIMA CHARLIE $1 Ubuntu x64 Release Installer" ./install.sh
rm ./sensor/scripts/installers/nix/bin
