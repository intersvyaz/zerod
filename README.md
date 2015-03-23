# zerod

### Build instructions

You need the following libraries installed:
- [cmake](http://www.cmake.org/), >= 2.8, cross-platform, open-source build system
- [libevent](http://libevent.org/), >= 2.0, event-based network I/O library
- [libconfig](http://www.hyperrealm.com/libconfig/), >= 1.4, configuration management library
- [netmap](https://code.google.com/p/netmap/), >= 20131019, fast network packet I/O framework
- [libfreeradius-client](http://freeradius.org/freeradius-client/), >=1.7, framework and library for writing RADIUS Clients
- [libbson](https://github.com/mongodb/libbson), >= 1.0, building, parsing, and iterating BSON documents
- [python](https://www.python.org/), >= 3.0, interactive high-level object-oriented language
- [pymongo](https://github.com/mongodb/mongo-python-driver), BSON implementation for python

Build using cmake:
```bash
mkdir build
cd build
cmake ..
make
```
