# ret

<img src="https://github.com/rerrorctf/ret/assets/93072266/5a998dbb-5730-4b10-9636-45e35e9fe77e" alt="rounding error ctf team logo" width="400"/>

This tool helps you solve ctf tasks by automating workflow and basic analysis and providing useful utilities.

## Installation

You can get the latest binary from https://github.com/rerrorctf/ret/releases.

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

This will produce the `ret` binary. This single file is all you need to use `ret`.

There is also a `build.sh` that I use to create the binaries that get uploaded to github.

```
$ ./build.sh
```

## Commands

You can list all the commands by using `-h`, `--help`, `help` or simply providing no arguments:

```
$ ret help
```

You can get help for a command by giving `help` as an argument to the command:

```
$ ret command help
```

### abi 🤝

```
ret abi [architecture] [os]
```

Prints reference details about the abi for the given platform.

- **architecture**: Specify `x86/32` or `x64/64`.
- **os**: Specify `linux` or `windows`.

For more detailed information on calling conventions, refer to the [Agner Fog's Calling Conventions PDF](https://www.agner.org/optimize/calling_conventions.pdf).

https://github.com/rerrorctf/ret/blob/main/commands/abi.go

### add 📥

```
ret add file1 [file2 file3...]
```

This command will:
1. Analyze each file to determine its type.
2. Generate a SHA-256 hash for each file.
3. Added files are stored in in the hidden directory `.ret/files` inside a subfolder that is named using the SHA2-256 hex digest of the file content.
4. Save metadata about the file in a JSON file.
5. Searches for patterns within the file content.

https://github.com/rerrorctf/ret/blob/main/commands/add.go

### chat 📢

```
ret chat message
```

Sends a message to discord via a webhook in `~/.config/ret` called `chatwebhookurl`.

https://github.com/rerrorctf/ret/blob/main/commands/chat.go

### cheatsheet 📚

```
ret cheatsheet
```

Prints a list of cheatsheets for quick reference.

https://github.com/rerrorctf/ret/blob/main/commands/cheatsheet.go

### check ✅

```
ret check
```

Check your environment for ctf readiness by checking if various pieces of commonly used software are installed.

If something is not installed `ret` tries to give you a link to help you install it quickly.

https://github.com/rerrorctf/ret/blob/main/commands/check.go

### chef 🔪

```
ret chef [-] [text]
```

The `chef` command allows you to open CyberChef with a specified input directly from the command line.

CyberChef is a web-based tool for performing various encoding, decoding, and data transformation operations.

See https://gchq.github.io/CyberChef for more information.

Use - to read from stdin.

https://github.com/rerrorctf/ret/blob/main/commands/chef.go

### ctf 🚩

```
ret ctf [flag]
```

Records the provided flag as the solution for the current task.

If no flag is provided will report the currently recorded flag if any exists.

Note that if you set the flag for the current task the `writeup` command will automatically include it for you.

https://github.com/rerrorctf/ret/blob/main/commands/ctf.go

### decompress 🤏

```
ret decompress file1 [file2 file3...]
```

Decompresses files by first checking if they have a suitable extension and then a suitable magic.

Supports .zip, .gzip, .xz, .tar and .7z.

Note that we check the extension to avoid decompressing things like .apk files.

https://github.com/rerrorctf/ret/blob/main/commands/decompress.go

### docker 🐋

```
ret docker [ip] [port]
```

Creates a Dockerfile from a template.

This is potentially useful for pwning locally.

https://github.com/rerrorctf/ret/blob/main/commands/docker.go

### format 🔍

```
ret format [regex]
```

Prints the current flag format regex or updates it if an argument is supplied.

This creates or rewrites the contents `~/.config/ret`.

Note that if don't set the flag for the current task the `writeup` command will automatically include the format regex for you as a placeholder.

https://github.com/rerrorctf/ret/blob/main/commands/format.go

### ghidra 🦖

```
ret ghidra [file1 file2...]
```

The `Ghidra` command in this package is designed to ingest files and open them with ghidra, a software reverse engineering tool.

- Ensures the ghidra project directory exists.
- Optionally add one or more files.
- Analyzes all added files and opens the ghidra project.

Make sure ghidra is installed (or symlinked) at `/opt/ghidra` or use the config file to adjust the default ghidra installation location.

https://github.com/rerrorctf/ret/blob/main/commands/ghidra.go

### gist 🐙

```
ret gist file [-]
```

Create a private gist from a file.

Optionally you can read from stdin by specifying `-` after the file param. In this case file will be used only as the name.

Requires `~/.config/ret` to have a valid `gisttoken`.

See your tokens here https://github.com/settings/tokens?type=beta.

Read about creating gists programatically here https://docs.github.com/en/rest/gists/gists?apiVersion=2022-11-28#create-a-gist.

https://github.com/rerrorctf/ret/blob/main/commands/gist.go

### gpt 🧠

```
ret gpt question
```

Pose a question to ChatGPT with ret's ctf specific prompt.

Optionally you can read from stdin by specifying `-` as the first param.

```
$ ret gpt how do i pwn?
$ cat go.py | ret gpt - how do i make this pwn better?
```

https://github.com/rerrorctf/ret/blob/main/commands/gpt.go

### ida 💃

```
ret ida [file1 file2...]
```

Optionally adds one or more new files.

Imports all added files.

Opens ida.

Make sure ida is installed (or symlinked) at `/opt/ida` or use the config file to adjust the default ida installation location.

https://github.com/rerrorctf/ret/blob/main/commands/ida.go

### libc 🗽

```
ret libc [tag]
```

Creates and runs a Docker container based on the given tag.

By default will use ubuntu:latest as the tag if none is provided.

A Dockerfile and a script will be created and then run in a temp directory.

The script will build, run, stop and remove the container.

When the container is running `libc.so.6` will be copied from the container.

After the container is destroyed the file is added with ret.

https://github.com/rerrorctf/ret/blob/main/commands/libc.go

### proxy 📡

```
ret proxy [list/create]
```

This command manages SSH proxies.

1. **Listing Proxies**:
   - Command: `ret proxy list`
   - Description: Lists all currently active SSH proxies that are using local port forwarding (`ssh -L`). It parses the output of `ps aux` to find relevant SSH processes and displays their details, including the local port, remote IP, remote port, and process ID.

2. **Creating Proxies**:
   - Command: `ret proxy create local-port remote-ip remote-port [ssh-ip]`
   - Description: Creates a new SSH proxy with local port forwarding. It requires the local port, remote IP, and remote port as arguments. Optionally, an SSH IP can be specified. The command uses the current user's credentials to establish the SSH connection.

https://github.com/rerrorctf/ret/blob/main/commands/proxy.go

### pwn 🐚

```
ret pwn [ip] [port]
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

### sage 🌿

```
ret sage
```

Just runs:

```bash
$ sudo docker pull sagemath/sagemath
$ sudo docker run -it sagemath/sagemath:latest
```

See https://hub.docker.com/r/sagemath/sagemath for more information.

https://github.com/rerrorctf/ret/blob/main/commands/sage.go

### status 👀

```
ret status
```

Prints information about the task including any added files.

https://github.com/rerrorctf/ret/blob/main/commands/status.go

### syscall 📞

```
ret syscall [(x86/32)/(x64/64)] [regex-pattern]
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

### vps ☁️

```
ret vps [create/list/destroy]
```

Simply create and manage google cloud compute instances.

Requires the google cloud cli be installed. See https://cloud.google.com/sdk/docs/install for more information.

https://github.com/rerrorctf/ret/blob/main/commands/vps.go

### wizard 🧙

```
ret wizard [ip] [port]
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

### writeup 📝

```
ret writeup
```

Create a writeup template for a task in a file called `writeup.md`.

https://github.com/rerrorctf/ret/blob/main/commands/writeup.go

## ~/.config/ret

`ret` will parse `~/.config/ret`.

```json
{
  "ghidrainstallpath": "/opt/ghidra",
  "ghidraproject": "project",
  "idainstallpath": "/opt/ida",
  "pwnscriptname": "go.py",
  "pwnscripttemplate": "",
  "flagformat": "flag{.+}",
  "wizardprecommand": "",
  "wizardpostcommand": "",
  "username": "smiley",
  "chatwebhookurl": "",
  "gisttoken": "",
  "openaikey": "",
  "googlecloudproject": "",
  "googlecloudregion": "europe-west3-c",
  "googlecloudsshkey": ""
}
```
