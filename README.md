# libpbvt

```
$ make clean all
$ cc driver.c -g2 -gdwarf-3 -O2 -Iinclude -L. -lpbvt -o driver
$ LD_LIBRARY_PATH=$PWD ./driver 1000 10
```
