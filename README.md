# libpbvt

Library that provides version-control for program memory. Check `examples/` for usage. For building for use in other projects (e.g. [rdb](https://github.com/rhit-rotho/rdb)):

```shell
$ sudo apt install -y build-essential
$ make clean all && sudo make install
$ export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
$ cc examples/track-clone.c -lpbvt -o track-clone
$ ./track-clone
...
```

To start tracking memory with version control, call `pbvt_track_range(void *range, size_t n, int perms)` with the desired range. Writes to the memory region will be tracked automatically, and will put the region into a *transitive* state, until a call to `pbvt_commit()`, which will return a `Commit*` handle that can be used to checkout to the previous state of memory.

Additionally, a persistent heap allocator is provided, which will provide smaller chunks of persistent memory. Using `pbvt_malloc` and `pbvt_free` it is possible to create persistent data structures, see `examples/linked-list.c` for an example of a persistent linked list.

## General Usage

- Call `pbvt_init()`
- Put any desired memory regions under version control by calling `pbvt_track_range(...)`, or by using `pbvt_malloc` and `pbvt_free`.
- Make any desired changes to memory.
- Call `pbvt_commit` when done with any changes. This returns a `Commit*` handle that can be used to restore to the current state.
- Call `pbvt_checkout` to restore any version-controlled regions to a previous `Commit*`
- When finished, call `pbvt_cleanup()`.

## TODO

- [ ] Windows support (see e.g., [emeryberger/Heap-Layers](https://github.com/emeryberger/Heap-Layers))
- [ ] HAMT compaction for nodes (see [Introduction to HAMT](https://idea.popcount.org/2012-07-25-introduction-to-hamt/))
