# zerod

### Build instructions

You need the following libraries installed:
- [cmake](http://www.cmake.org/), >= 2.8, cross-platform, open-source build system
- [libevent](http://libevent.org/), >= 2.0, event-based network I/O library
- [libconfig](http://www.hyperrealm.com/libconfig/), >= 1.4, configuration management library
- [netmap](https://code.google.com/p/netmap/), >= 20131019, fast network packet I/O framework
- [libfreeradius-client](http://freeradius.org/freeradius-client/), framework and library for writing RADIUS Clients
- [gperftools](https://code.google.com/p/gperftools/), >= 2.0, fast, multi-threaded malloc() and nifty performance analysis tools

Build using cmake:
```bash
mkdir build
cd build
cmake ..
make
```
