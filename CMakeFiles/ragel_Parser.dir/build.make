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

# Utility rule file for ragel_Parser.

# Include any custom commands dependencies for this target.
include CMakeFiles/ragel_Parser.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/ragel_Parser.dir/progress.make

CMakeFiles/ragel_Parser: src/parser/Parser.cpp

src/parser/Parser.cpp: src/parser/Parser.rl
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/pralhad/hyperscan/hyperscan/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating src/parser/Parser.cpp"
	/usr/bin/cmake -E make_directory /home/pralhad/hyperscan/hyperscan/src/parser
	/usr/bin/ragel /home/pralhad/hyperscan/hyperscan/src/parser/Parser.rl -o /home/pralhad/hyperscan/hyperscan/src/parser/Parser.cpp

ragel_Parser: CMakeFiles/ragel_Parser
ragel_Parser: src/parser/Parser.cpp
ragel_Parser: CMakeFiles/ragel_Parser.dir/build.make
.PHONY : ragel_Parser

# Rule to build all files generated by this target.
CMakeFiles/ragel_Parser.dir/build: ragel_Parser
.PHONY : CMakeFiles/ragel_Parser.dir/build

CMakeFiles/ragel_Parser.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ragel_Parser.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ragel_Parser.dir/clean

CMakeFiles/ragel_Parser.dir/depend:
	cd /home/pralhad/hyperscan/hyperscan && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/pralhad/hyperscan/hyperscan /home/pralhad/hyperscan/hyperscan /home/pralhad/hyperscan/hyperscan /home/pralhad/hyperscan/hyperscan /home/pralhad/hyperscan/hyperscan/CMakeFiles/ragel_Parser.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ragel_Parser.dir/depend

