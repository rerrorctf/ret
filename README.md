# ret

<img src="https://github.com/rerrorctf/ret/assets/93072266/5a998dbb-5730-4b10-9636-45e35e9fe77e" alt="rounding error ctf team logo" width="400"/>

This tool helps you solve CTF tasks by automating workflow and basic analysis and providing useful utilities.

## Table of Contents
1. [Introduction](https://github.com/rerrorctf/ret?tab=readme-ov-file#introduction)
2. [Installation](https://github.com/rerrorctf/ret?tab=readme-ov-file#installation)
3. [Commands](https://github.com/rerrorctf/ret?tab=readme-ov-file#commands)
  - Core Commands
    - [ctf 🚩](https://github.com/rerrorctf/ret?tab=readme-ov-file#ctf-)
    - [format 🔍](https://github.com/rerrorctf/ret?tab=readme-ov-file#format-)
    - [status 👀](https://github.com/rerrorctf/ret?tab=readme-ov-file#status-)
    - [add 📥](https://github.com/rerrorctf/ret?tab=readme-ov-file#add-)
    - [wizard 🧙](https://github.com/rerrorctf/ret?tab=readme-ov-file#wizard-)
  - Rev Commands
    - [ghidra 🦖](https://github.com/rerrorctf/ret?tab=readme-ov-file#ghidra-)
    - [ida 💃](https://github.com/rerrorctf/ret?tab=readme-ov-file#ida-)
  - Pwn Commands
    - [pwn 🐚](https://github.com/rerrorctf/ret?tab=readme-ov-file#pwn-)
    - [docker 🐋](https://github.com/rerrorctf/ret?tab=readme-ov-file#docker-)
    - [libc 🗽](https://github.com/rerrorctf/ret?tab=readme-ov-file#libc-)
  - Informational Commands
    - [abi 🤝](https://github.com/rerrorctf/ret?tab=readme-ov-file#abi-)
    - [syscall 📞](https://github.com/rerrorctf/ret?tab=readme-ov-file#syscall-)
    - [cheatsheet 📚](https://github.com/rerrorctf/ret?tab=readme-ov-file#cheatsheet-)
  - Utility Commands
    - [decompress 🤏](https://github.com/rerrorctf/ret?tab=readme-ov-file#decompress-)
    - [check ✅](https://github.com/rerrorctf/ret?tab=readme-ov-file#check-)
    - [chat 📢](https://github.com/rerrorctf/ret?tab=readme-ov-file#chat-)
    - [gist 🐙](https://github.com/rerrorctf/ret?tab=readme-ov-file#gist-)
    - [writeup 📝](https://github.com/rerrorctf/ret?tab=readme-ov-file#writeup-)
    - [gpt 🧠](https://github.com/rerrorctf/ret?tab=readme-ov-file#gpt-)
4. [Config](https://github.com/rerrorctf/ret?tab=readme-ov-file#configret)

## Introduction

To see a list of available commands:

```
$ ret help
```

At the start of a new CTF set the flag format globally. This is a evaluated as a regex and used to perform a few things including grep2win against all added files.

```
$ ret format example{.+}
```

You can inspect the current flag format by specifying no arguments.

```
$ ret format
```

For each task you solve first setup a directory for that task:

```
$ mkdir task
$ cd task
$ cp ~/Downloads/task .
```

For each file associated with that task add it:

```
$ ret add task
```

You can see the currently added files with status:

```
$ ret status
```

To automatically import and analyse all added files with ghidra simply use:

```
$ ret ghidra
```

To make a pwntools script simply use:

```
$ ret pwn
```

This will infer the binary you wish to target and use a simple template to make a script for you.

If you have details for remote infrastructure you can supply those too:

```
$ ret pwn ctf.example.com 9001
```

## Installation

You can simply get the latest pre-built binary from https://github.com/rerrorctf/ret/releases.

Please note that, while `ret` is a single file built for x64 linux, you can use go to build this for a range of platforms (although this hasn't been tested yet).

Here installation just means putting `ret` somewhere on your path. I like to make a symlink it to in `/usr/local/bin`.

```
$ sudo ln -s ./ret /usr/local/bin/ret
```

Other options are available and you may do whatever works best for you.

### Compiling (Optional)

First install `go` https://go.dev/dl/ by following the install instructions.

You can use `go` in system repos but they tend to be fairly old and out of date.

Now, the project root directory, you can simply do:

```
$ go build
```

This will produce the `ret` binary. This static binary / single file is all you need to use `ret`.

## Commands

You can list all the commands by using `-h`, `--help`, `help` or simply providing no arguments:

```
$ ret help
```

You can get help for a command by giving `help` as an argument to the command:

```
$ ret command help
```

### ctf 🚩

```
usage: ret ctf [flag]
```

Records the provided flag as the solution for the current task.

If no flag is provided will report the currently recorded flag if any exists.

https://github.com/rerrorctf/ret/blob/main/commands/ctf.go

### format 🔍

```
usage: ret format [regex]
```

Prints the current flag format regex or updates it if an argument is supplied.

This creates or rewrites the contents `~/.config/ret`.

https://github.com/rerrorctf/ret/blob/main/commands/format.go

### wizard 🧙

```
usage: ret wizard [ip] [port]
```

Wizard is here to help! They simply run a few common commands for a typical workflow. The workflow is quite well suited for typical rev and pwn tasks. Sometimes the wizard makes mistakes!

1) Executes the `wizardprecommand` from ~/.config/ret.
2) Searches for interesting files within the current directory.
3) Ensures that the hidden .ret directory skeleton exists.
4) Unzips any .zip files that it can.
5) Adds any interesting files. This includes those found by unzipping and ignores .zip files.
6) Shows `status`.
7) If the wizard thinks there is an elf file it will invoke `pwn` for you.
8) If you provided an ip or an ip and a port wizard will pass these to `pwn` for you.
9) Executes the `wizardpostcommand` from ~/.config/ret.

https://github.com/rerrorctf/ret/blob/main/commands/wizard.go

### add 📥

```
usage: ret add file1 [file2 file3...]
```

This command adds one or more files to the task.

This involves taking a copy of the file and performing some basic analysis on the file.

Added files can be viewed with the `status` command.

This command deduplicates files by comparing a file content's SHA2-256 hash with the hash of files previously added.

Added files are stored in in the hidden directory `.ret/files` inside a subfolder that is named using the SHA2-256 hex digest of the file content.

Added files are subject to being automatically ingested by the commands `ghidra` and `ida`.

https://github.com/rerrorctf/ret/blob/main/commands/add.go

### decompress 🤏

```
usage: ret decompress file1 [file2 file3...]
```

https://github.com/rerrorctf/ret/blob/main/commands/decompress.go

### status 👀

```
usage: ret status
```

Prints information about the task including any added files.

https://github.com/rerrorctf/ret/blob/main/commands/status.go

### pwn 🐚

```
usage: ret pwn [ip] [port]
```

Creates a pwntools script from a template.

If `~/.config/ret` contains a value for `pwnscripttemplate` the contents of this file will be used as the template instead.

If a custom template is in use `pwn` will take the contents of the file at this path and do the following substitutions:
  - :%s/\%BINARY\%/task
    - where task is the result of util.GuessBinary()
  - :%s/\%IP\%/127.0.0.1
    - where 127.0.0.1 is the supplied ip address
  - :%s/\%PORT\%/9001
    - where 9001 is the supplied port

For example:

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./%BINARY%", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("%IP%", %PORT%)

p.interactive()
```

Might be transformed into:

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("127.0.0.1", 9001)

p.interactive()
```

Note the placement of the `"` characters.

https://github.com/rerrorctf/ret/blob/main/commands/pwn.go

### ghidra 🦖

```
usage: ret ghidra [file1 file2...]
```

Creates a ghidra project in the hidden directory `.ret/ghidra`.

Optionally adds one or more new files.

Imports and analyzes all added files using headless mode.

Opens the ghidra project after the analysis has completed.

Make sure ghidra is installed (or symlinked) at `/opt/ghidra` or use the config file to adjust the default ghidra installation location.

From a workflow point of view I tend to run this after running the wizard in the background. This means that when i'm ready to use ghidra everything is already fully analyzed.

https://github.com/rerrorctf/ret/blob/main/commands/ghidra.go

### ida 💃

```
usage: ret ida [file1 file2...]
```

Optionally adds one or more new files.

Imports all added files.

Opens ida.

Make sure ida is installed (or symlinked) at `/opt/ida` or use the config file to adjust the default ida installation location.

Note: this command doesn't work well and needs an ida user's love and care.

https://github.com/rerrorctf/ret/blob/main/commands/ida.go

### docker 🐋

```
usage: ret docker [ip] [port]
```

Creates a Dockerfile from a template.

https://github.com/rerrorctf/ret/blob/main/commands/docker.go

### libc 🗽

```
usage: ret libc [tag]
```

Creates and runs a container based on the given tag.

By default will use ubuntu:latest as the tag if none is provided.

In a temp directory a Dockerfile and script will be created and ran.

The script will build, run, stop and remove the container.

When the container is running libc.so.6 will be copied from the container.

After the container is destroyed the file is copied to the cwd and added with ret.

https://github.com/rerrorctf/ret/blob/main/commands/libc.go

### check ✅

```
usage: ret check
```

Check your environment for ctf readiness by checking if various pieces of commonly used software are installed.

If something is not installed `ret` tries to give you a link to help you install it quickly.

https://github.com/rerrorctf/ret/blob/main/commands/check.go

### syscall 📞

```
usage: ret syscall [(x86/32)/(x64/64)] [regex-pattern]
```

Greps syscall headers for x86 and x64 linux.

For x86 linux we use:
`/usr/include/x86_64-linux-gnu/asm/unistd_32.h`

For x64 linux we use:
`/usr/include/x86_64-linux-gnu/asm/unistd_64.h`

For example:

`syscall x64 " 0"`

`syscall x64 write`

`syscall 32 read`

`syscall x86 10[0-9]`

https://github.com/rerrorctf/ret/blob/main/commands/syscall.go

### abi 🤝

```
usage: ret abi [(x86/32)/(x64/64)] [linux/windows]
```

Prints reference details about the abi for the given platform.

https://github.com/rerrorctf/ret/blob/main/commands/abi.go

### chat 📢

```
usage: ret chat message
```

Sends a message to discord via a webhook in `~/.config/ret` called `chatwebhookurl`.

See https://github.com/rerrorctf/ret/blob/main/README.md#configret for more information.

https://github.com/rerrorctf/ret/blob/main/commands/chat.go

### gist 🐙

```
usage: ret gist file [-]
```

Create a private gist from a file.

Optionally you can read from stdin by specifying `-` after the file param. In this case file will be used only as the name.

Requires `~/.config/ret` to have a valid `gisttoken`.

https://github.com/settings/tokens?type=beta

https://docs.github.com/en/rest/gists/gists?apiVersion=2022-11-28#create-a-gist

https://github.com/rerrorctf/ret/blob/main/commands/gist.go


### writeup 📝

```
usage: ret writeup
```

Create a writeup template for a task in a file called `writeup.md`.

https://github.com/rerrorctf/ret/blob/main/commands/writeup.go

### cheatsheet 📚

```
usage: ret cheatsheet
```

Prints a list of cheatsheets for quick reference.

https://github.com/rerrorctf/ret/blob/main/commands/cheatsheet.go

### gpt 🧠

```
usage: ret gpt
```

https://github.com/rerrorctf/ret/blob/main/commands/gpt.go

## ~/.config/ret

`ret` will parse `~/.config/ret`.

While I aim to keep this readme in sync; for the current structure of the config file please consult https://github.com/rerrorctf/ret/blob/main/data/config.go#L3.

The data in the config must be in the json format. You can include zero or more of the following in your config:

- `ghidrainstallpath`
  - This is the location where you have installed ghidra, e.g. `/opt/ghidra` is what I use, so that `ret ghidra` knows where to find `ghidraRun`.
  - The current default value is `/opt/ghidra` as per https://github.com/rerrorctf/ret/blob/main/config/config.go#L12

- `ghidraprojectpath`
  - This is what you would like the ghidra folder, created by `ret`, to be called within the `.ret` folder to be called e.g. `./.ret/ghidra`.
  - The current default value is `./.ret/ghidra` as per https://github.com/rerrorctf/ret/blob/main/config/config.go#L13

- `idainstallpath`
  - This is the location where you have installed ghidra, e.g. `/opt/ida`, so that `ret ida` knows where to find ida.
  - The current default value is `/opt/ida` as per https://github.com/rerrorctf/ret/blob/main/config/config.go#L14

- `idaprojectpath`
  - This is what you would like the ida folder, created by `ret`, to be called within the `.ret` folder to be called e.g. `./.ret/ida`.
  - The current default value is `./.ret/ida` as per https://github.com/rerrorctf/ret/blob/main/config/config.go#L15

- `pwnscriptname`
  - This is what you would like the script created by `ret pwn` to be called.
  - The default is `go.py` and is chosen to be short and not clash with any common imports as per https://github.com/rerrorctf/ret/blob/main/config/config.go#L25

- `pwnscripttemplate`
  - Path to a template to that can be used to override the default behaviour of pwn.

- `flagformat`
  - This is the regular expression that matches the flag format for the ctf you are currently playing.
  - The default is `flag{.+}`.

- `wizardprecommand`
  - This will be executed by the `wizard` before they do any of their own magic.
  - It is passed to `bash -c`

- `wizardpostcommand`
  - This will be executed by the `wizard` after they have worked their own magic.
  - It is passed to `bash -c`

- `chatusername`
  - This username will be used when sending with the chat command

- `chatwebhookurl`
  - This will be used to send chat message to discord.

- `gisttoken`
  - A github gist token with read/write gist permissions is required to use the gist command.
  - https://github.com/settings/tokens?type=beta
  - https://docs.github.com/en/rest/gists/gists?apiVersion=2022-11-28#create-a-gist

## The .ret Directory Structure

Certain commands, such as `add` and `status` will use a hidden directory structure.

This is technically configurable via https://github.com/rerrorctf/ret/blob/main/config/config.go#L5 but this is not exposed to the user config. In other words you can change this be changing the source code and building your own version if you wish. If there is a strong desire to change this I would consider adding it to the user config.

You can delete this directory if you like or make changes as you see fit but just be aware that the tool makes certain assumptions about the contents.

This directory is structured as follows:

- `.ret/files`
  - This directory contains files and metadata about files added to the task by the `add` command
  - For each file added a subdirectory of files is created that is named using the SHA2-256 hex digest of the file content
    - e.g. `.ret/files/7ebfc53f17925af4340d4218aafd16ba39b5afa8b6ac1f7adc3dd92952a2a237`
    - Inside of the folder created for each file
      - There is a copy of the file that was added

- `.ret/ghidra`
  - This directory is created to store the ghidra project created if you use the `ghidra` command
  - Note that you can change this with `~/.config/ret` as above

- `.ret/ida`
  - This directory is created to store the ida project created if you use the `ida` command
  - Note that you can change this with `~/.config/ret` as above
