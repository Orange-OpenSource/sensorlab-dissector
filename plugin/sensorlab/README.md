# SensorLab2 dissector

## Brief

This plugin is the official SensorLab2 dissector for Wireshark.

## Installation


** This plugin requires to build Wireshark from source**

	- Get a copy of Wireshark source code[here](https://github.com/wireshark/wireshark)
	- Copy/paste the `sensorlab` directory to the `plugins` directory of Wireshark
	- Add `sensorlab` to the SUBDIRS environment variable in `Makefile.am` located in the `plugins` directory of Wireshark
	- Build Wireshark by following the official documentation in `INSTALL` (located at the root folder of the Wireshark repository).


## How to add plugin to wireshark

Add this folders to the wireshark plugins folders :

```bash
cp -r * path/to/wireshark/plugins
```