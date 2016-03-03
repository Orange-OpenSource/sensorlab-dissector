# SensorLab2 dissector

## Brief

This plugin is the official SensorLab2 dissector for Wireshark.

## Installation

** This plugin requires to build Wireshark from source**

- Get a copy of Wireshark source code[here](https://github.com/wireshark/wireshark)
- Copy/paste the `sensorlab` directory located in the `plugin` directory of this repository to the `plugins` directory of Wireshark
- Follow the instructions of the section 3. of `wireshark/doc/README.plugins`.
    Depending on your build tools (cmake, autotools, etc.), this requires changing a few files of Wiresharks, e.g. `CMakeLists.txt` for cmake, `Makefile.am` and `configure.ac` for autotools, etc.


## Preferences

We provide custom preference settings (customized GUI layout) for the SensorLab2 dissector. To use these settings, copy/paste the `preferences` directory to your `HOME` folder and rename it `.wireshark`. Back-up any pre-existing `.wireshark` directory if needed.

## License

The SensorLab2 dissector is distributed under the terms of the License GPLv2+: GNU GPL version 2 to comply with the licensing terms of Wireshark.
