About
=====

A simple tool to display information about DesFire tags (applications, ACL, key
& files count). Based on excellent
[libfreefare](https://github.com/nfc-tools/libfreefare) library and tools.

Most code provides from libfreefare example.

Building
========
* install libfreefare
* make
* enjoy

Running
=======

	./desfire-info [--brute-force]

`--brute-force` will test for default NULL key to access applications key and
keys in keyring for every application.
