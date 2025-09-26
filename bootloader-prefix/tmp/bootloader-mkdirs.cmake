# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/bao/esp/esp-idf/components/bootloader/subproject"
  "/home/bao/esp32project/Smartlock/bootloader"
  "/home/bao/esp32project/Smartlock/bootloader-prefix"
  "/home/bao/esp32project/Smartlock/bootloader-prefix/tmp"
  "/home/bao/esp32project/Smartlock/bootloader-prefix/src/bootloader-stamp"
  "/home/bao/esp32project/Smartlock/bootloader-prefix/src"
  "/home/bao/esp32project/Smartlock/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/bao/esp32project/Smartlock/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/bao/esp32project/Smartlock/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
