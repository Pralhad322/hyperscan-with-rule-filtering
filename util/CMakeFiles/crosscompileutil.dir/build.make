# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/pralhad/hyperscan/hyperscan

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/pralhad/hyperscan/hyperscan

# Include any dependencies generated for this target.
include util/CMakeFiles/crosscompileutil.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include util/CMakeFiles/crosscompileutil.dir/compiler_depend.make

# Include the progress variables for this target.
include util/CMakeFiles/crosscompileutil.dir/progress.make

# Include the compile flags for this target's objects.
include util/CMakeFiles/crosscompileutil.dir/flags.make

util/CMakeFiles/crosscompileutil.dir/cross_compile.cpp.o: util/CMakeFiles/crosscompileutil.dir/flags.make
util/CMakeFiles/crosscompileutil.dir/cross_compile.cpp.o: util/cross_compile.cpp
util/CMakeFiles/crosscompileutil.dir/cross_compile.cpp.o: util/CMakeFiles/crosscompileutil.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/pralhad/hyperscan/hyperscan/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object util/CMakeFiles/crosscompileutil.dir/cross_compile.cpp.o"
	cd /home/pralhad/hyperscan/hyperscan/util && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT util/CMakeFiles/crosscompileutil.dir/cross_compile.cpp.o -MF CMakeFiles/crosscompileutil.dir/cross_compile.cpp.o.d -o CMakeFiles/crosscompileutil.dir/cross_compile.cpp.o -c /home/pralhad/hyperscan/hyperscan/util/cross_compile.cpp

util/CMakeFiles/crosscompileutil.dir/cross_compile.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/crosscompileutil.dir/cross_compile.cpp.i"
	cd /home/pralhad/hyperscan/hyperscan/util && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/pralhad/hyperscan/hyperscan/util/cross_compile.cpp > CMakeFiles/crosscompileutil.dir/cross_compile.cpp.i

util/CMakeFiles/crosscompileutil.dir/cross_compile.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/crosscompileutil.dir/cross_compile.cpp.s"
	cd /home/pralhad/hyperscan/hyperscan/util && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/pralhad/hyperscan/hyperscan/util/cross_compile.cpp -o CMakeFiles/crosscompileutil.dir/cross_compile.cpp.s

# Object files for target crosscompileutil
crosscompileutil_OBJECTS = \
"CMakeFiles/crosscompileutil.dir/cross_compile.cpp.o"

# External object files for target crosscompileutil
crosscompileutil_EXTERNAL_OBJECTS =

lib/libcrosscompileutil.a: util/CMakeFiles/crosscompileutil.dir/cross_compile.cpp.o
lib/libcrosscompileutil.a: util/CMakeFiles/crosscompileutil.dir/build.make
lib/libcrosscompileutil.a: util/CMakeFiles/crosscompileutil.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/pralhad/hyperscan/hyperscan/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library ../lib/libcrosscompileutil.a"
	cd /home/pralhad/hyperscan/hyperscan/util && $(CMAKE_COMMAND) -P CMakeFiles/crosscompileutil.dir/cmake_clean_target.cmake
	cd /home/pralhad/hyperscan/hyperscan/util && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/crosscompileutil.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
util/CMakeFiles/crosscompileutil.dir/build: lib/libcrosscompileutil.a
.PHONY : util/CMakeFiles/crosscompileutil.dir/build

util/CMakeFiles/crosscompileutil.dir/clean:
	cd /home/pralhad/hyperscan/hyperscan/util && $(CMAKE_COMMAND) -P CMakeFiles/crosscompileutil.dir/cmake_clean.cmake
.PHONY : util/CMakeFiles/crosscompileutil.dir/clean

util/CMakeFiles/crosscompileutil.dir/depend:
	cd /home/pralhad/hyperscan/hyperscan && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/pralhad/hyperscan/hyperscan /home/pralhad/hyperscan/hyperscan/util /home/pralhad/hyperscan/hyperscan /home/pralhad/hyperscan/hyperscan/util /home/pralhad/hyperscan/hyperscan/util/CMakeFiles/crosscompileutil.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : util/CMakeFiles/crosscompileutil.dir/depend

