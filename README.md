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

The data in the config must be in the json format. You can include zero or more of the following in your config:

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

You can list all the commands by using `-h`, `--help`, `help` or simply providing no arguments:

```
$ rctf help
```

You can get help for a command by giving `help` as an argument to the command:

```
$ rctf command help
```

### init

```
usage: rctf init [flag-format]
```

Initializes the current working directory for a task.

This information is stored in the `rctf-tasks.json` file in the hidden `.rctf` directory.

Note that the flag format is treated as a regular expression. For example `flag{.+}` would be suitable for a ctf with flags like `flag{example}`.

https://github.com/rerrorctf/rctf/blob/main/commands/init.go

### add

```
usage: rctf add file1 [file2 file3...]
```

This command adds one or more files to the task.

This involves taking a copy of the file and performing some basic analysis on the file.

Added files can be viewed with the `status` command.

This command deduplicates files by comparing a file content's SHA2-256 hash with the hash of files previously added.

Added files are stored in in the hidden directory `.rctf/files` inside a subfolder that is named using the SHA2-256 hex digest of the file content.

Added files are subject to being automatically ingested by the commands `ghidra` and `ida`.

https://github.com/rerrorctf/rctf/blob/main/commands/add.go

### status

```
usage: rctf status
```

Prints information about the task including any added files.

Print more detailed information with the `-v` flag.

https://github.com/rerrorctf/rctf/blob/main/commands/status.go

### pwn

```
usage: rctf pwn [ip] [port]
```

Creates a pwntools script and Dockerfile from a template.

https://github.com/rerrorctf/rctf/blob/main/commands/pwn.go

### ghidra

```
usage: rctf ghidra
```

Creates a ghidra project in the hidden directory `.rctf/ghidra`.

Imports and analyzes all added files.

Opens ghidra.

Make sure ghidra is installed (or symlinked) at `/opt/ghidra` or use the config file to adjust the default ghidra installation location.

https://github.com/rerrorctf/rctf/blob/main/commands/ghidra.go

### ida

```
usage: rctf ida
```

Imports all added files.

Opens ida.

Make sure ida is installed (or symlinked) at `/opt/ida` or use the config file to adjust the default ida installation location.

https://github.com/rerrorctf/rctf/blob/main/commands/ida.go

### syscall

```
usage: rctf syscall [(x86/32)/(x64/64)] [regex-pattern]
```

Greps syscall headers for x86 and x64 linux.

For x86 linux we use `/usr/include/x86_64-linux-gnu/asm/unistd_32.h`.

For x64 linux we use `/usr/include/x86_64-linux-gnu/asm/unistd_64.h`.

For example:

`syscall x64 " 0"`
`syscall x64 write`
`syscall 32 read`
`syscall x86 10[0-9]`

https://github.com/rerrorctf/rctf/blob/main/commands/syscall.go

### writeup

```
usage: rctf writeup
```

Create a writeup template for a task in a file called `writeup.md`.

https://github.com/rerrorctf/rctf/blob/main/commands/writeup.go

### check

```
usage: rctf check
```

Check your environment for ctf readiness by checking if various pieces of commonly used software are installed.

If something is not installed `rctf` tries to give you a link to help you install it quickly.

https://github.com/rerrorctf/rctf/blob/main/commands/check.go

### monitor

```
usage: rctf monitor [ip] [port] [interval-seconds]
```

Monitor for changes in the up/down status of a server address.

*Please* only point this at infrastructure associated with a ctf or that you own or have permission to interact with.

*Please* use this with caution as there is a fine line between monitoring and spamming the server to the detriment of all involved.

The default interval between tcp opens is 60 seconds.

As such whilst you can change the interval there is a minimum of 10 seconds hardcoded.

This command optionally makes use of a discord webhook which you can specify in `~/.config/rctf` with the key `"monitorwebhook"`. See the config section of this readme for more details.

https://github.com/rerrorctf/rctf/blob/main/commands/monitor.go

### cheatsheet

```
usage: rctf cheatsheet
```

Prints a list of cheatsheets for quick reference.

https://github.com/rerrorctf/rctf/blob/main/commands/cheatsheet.go

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
