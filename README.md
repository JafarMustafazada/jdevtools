# Project Documentation
P.S. not much provided here.

## Table of Contents
- [Introduction](#introduction)
- [Installation](#installation)
- [Usage](#usage)
<!-- - [Examples](examples/code_example.md) -->
- [MIT License](LICENSE) (don't be bothered)

## Introduction
This is my personal collection of simple &amp; useful tools for c++ (for now only header only libraries).
1. [jdevcurl](include/jdevtools/jdevcurl.hpp) Uses local curl from command panel (in silent) for exuciting simple curl commands.
2. [jdevstring](include/jdevtools/jdevstring.hpp) String manipulation and jwt creation tools (+ hmac encoders [sha256hmac](include/jdevtools/sha256hmac.hpp) &amp; [sha512hmac](include/jdevtools/sha512hmac.hpp)).
3. [jdevrandom](include/jdevtools/jdevrandom.hpp) Some random generator using functions (like frequency based random generation `randi`).

## Installation
No installation for now.

## Usage
To use the project, either just add desired header from "[include](include/)" to include of your project. Or add desired project folder from "[src](src/)" to your "`/src`" folder as subdirectory to your cmake project like this:
```cmake
# after adding: add_executable(MyProject  ${MY_SOURCES})


# Add the subdirectory
add_subdirectory(src/jdevtools)


# Links to the executable
target_link_libraries(MyProject PRIVATE jdevtools)
```

## License
For the license details, see the [MIT LICENSE](LICENSE) file. But generally don't be bothered.