#

_CUSTOM_SUBDIRS_ = \
	sensorlab

_CUSTOM_EXTRA_DIST_ = \
	sensorlab.m4 \
	sensorlab.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/sensorlab/sensorlab.la
