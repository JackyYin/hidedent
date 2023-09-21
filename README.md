# Hide Dentry Lab

Leverage eBPF to hide specific PID from `/proc` folder and `lsof` command.


## Manual

You can install `bpftool` and compile program with:

```
make
```

Or you can install and run the program directly with:
```
make run
```
*Note: root permission required!*

---

After program started, check `/proc` and `lsof` now:
```
ls /proc | grep $PID
lsof | grep $PID
```

Your PID should be excluded from those commands.
