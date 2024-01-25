# rctf

## swiss army knife ctf task automation tool

### brought to you by the rounding error ctf team

## building from source

todo

## installation

todo

## commands

```
$ rctf init help
```

```
$ rctf add help
```

```
$ rctf status help
```

```
$ rctf ghidra help
```

```
$ rctf pwn help
```

## ~/.config/rctf

```
{
  "ghidrainstallpath": "/path/to/ghidra/install",
  "ghidraprojectpath": "ghidra_project_folder_name_default_is_ghidra",
  "pwnscriptname": "custom-pwn-script-name.py"
}
```

## workflows

### example rev task

```
$ mkdir example-rev
$ cd ./example-rev
$ rctf init
$ cp ~/Downloads/task .
$ rctf add ./task
# add all files associated with the task...
$ rctf ghidra
```

### example pwn task

```
$ mkdir example-pwn
$ cd ./example-pwn
$ rctf init
$ cp ~/Downloads/task .
$ rctf add ./task
# add all files associated with the task...
$ rctf pwn
$ rctf ghidra
```