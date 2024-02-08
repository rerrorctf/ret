# rctf

## CTF Task Automation Tool

## Compiling (Optional)

First install `go` https://go.dev/dl/ by following the install instructions.

You can use `go` in system repos but they tend to be fairly old and out of date.

Now, the project root directory, you can simply do:

```
$ go build
```

This will produce the `rctf` binary. This static binary / single file is all you need to use `rctf`.

## Pre-built Binary

You can simply get the latest pre-built binary from https://github.com/rerrorctf/rctf/releases.

Please note that, while `rctf` is a single static file built for x64 linux, you can use go to build this for a range of platforms (although this hasn't been tested yet).

## Installation

Here installation just means putting `rctf` somewhere on your path. I like to copy it to `/usr/local/bin`.

```
$ sudo cp ./rctf /usr/local/bin
```

Other options are available and you may do whatever works best for you.

## ~/.config/rctf

`rctf` will parse `~/.config.rctf` *if* it exists. It will not make this file for you.

While I aim to keep this readme in sync; for the current structure of the config file please consult https://github.com/rerrorctf/rctf/blob/main/data/config.go#L3.

The data in the config must be in the json format. You can may include zero or more of the following in your config:

- `ghidrainstallpath`
  - This is the location where you have installed ghidra, e.g. `/opt/ghidra` is what I use, so that `rctf ghidra` knows where to find `ghidraRun`.
  - The current default value is `/opt/ghidra` as per https://github.com/rerrorctf/rctf/blob/main/config/config.go#L12

- `ghidraprojectpath`
  - This is what you would like the ghidra folder, created by `rctf`, to be called within the `.rctf` folder to be called e.g. `./.rctf/ghidra`.
  - The current default value is `./.rctf/ghidra` as per https://github.com/rerrorctf/rctf/blob/main/config/config.go#L13

- `idainstallpath`
  - This is the location where you have installed ghidra, e.g. `/opt/ida`, so that `rctf ida` knows where to find ida.
  - The current default value is `/opt/ida` as per https://github.com/rerrorctf/rctf/blob/main/config/config.go#L14

- `idaprojectpath`
  - This is what you would like the ida folder, created by `rctf`, to be called within the `.rctf` folder to be called e.g. `./.rctf/ida`.
  - The current default value is `./.rctf/ida` as per https://github.com/rerrorctf/rctf/blob/main/config/config.go#L15

- `pwnscriptname`
  - This is what you would like the script created by `rctf pwn` to be called.
  - The default is `go.py` and is chosen to be short and not clash with any common imports as per https://github.com/rerrorctf/rctf/blob/main/config/config.go#L16

- `monitorwebhook`
  - This is the discord webhook url you would like to use to post `rctf monitor` events.
  - _This is most likely a private server you have setup for the purpose of recieiving these notifications to avoid spamming others_
  - The default is `""` because by default this is not enabled as per https://github.com/rerrorctf/rctf/blob/main/config/config.go#L17 

Here is an example config:

```
{
  "ghidrainstallpath": "/opt/software/ghidra",
  "ghidraprojectpath": "ghidra-project",
  "pwnscriptname": "exploit.py"
  "monitorwebhook": "https://discord.com/api/webhooks/your-webhook-token-goes-here"
}
```

## Commands

### init

### add

### status

### pwn

### ghidra

### ida

### syscall

### writeup

### check

## The .rctf Directory Structure

Certain commands, such as `init`, `add` and `status` will use a hidden directory structure.

This is technically configurable via https://github.com/rerrorctf/rctf/blob/main/config/config.go#L5 but this is not exposed to the user config. In other words you can change this be changing the source code and building your own version if you wish. If there is a strong desire to change this I would consider adding it to the user config.

You can delete this directory if you like or make changes as you see fit but just be aware that the tool makes certain assumptions about the contents.

This directory is structured as follows:

- `.rctf/rctf-task.json`
 - This file contains information about the task being worked on in this directory

- `.rctf/files`
  - This directory contains files and metadata about files added to the task by the `add` command
  - For each file added a subdirectory of files is created that is named using the SHA2-256 hex digest of the file content
    - e.g. `.rctf/files/7ebfc53f17925af4340d4218aafd16ba39b5afa8b6ac1f7adc3dd92952a2a237`
    - Inside of the folder created for each file
      - There is a copy of the file that was added
      - There is the `rctflog.txt` log file for the processes that were run when added that file

- `.rctf/ghidra`
  - This directory is created to store the ghidra project created if you use the `ghidra` command
  - Note that you can change this with `~/.config/rctf` as above

- `.rctf/ida`
  - This directory is created to store the ida project created if you use the `ida` command
  - Note that you can change this with `~/.config/rctf` as above
