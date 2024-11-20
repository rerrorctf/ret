# ret

<img src="https://github.com/rerrorctf/ret/assets/93072266/5a998dbb-5730-4b10-9636-45e35e9fe77e" alt="rounding error ctf team logo" width="400"/>

This tool helps you solve ctf tasks by automating workflow and basic analysis and providing useful utilities.

## Installation

You can get the latest binary from https://github.com/rerrorctf/ret/releases.

Here installation just means putting `ret` somewhere on your path. I like to make a symlink to it in `/usr/local/bin`.

```
$ sudo ln -s ./ret /usr/local/bin/ret
```

Other options are available and you may do whatever works best for you.

### Installing Dependencies (Optional)

some commands make opportunistic use of other tools and some won't work without them

you can use the `check` command to see what's currently installed

consider installing the missing dependencies mentioned by the `check` command to get access to the full functionality of ret

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

You can get help for a command by prefixing `help` to the command:

```
$ ret help command
```

---

### 🤝 <u>ab</u>i

```
$ ret abi [architecture=x64] [os=linux] 
```

view abi details with ret

output includes calling conventions, register volatility and more

for architecture specify one of `x86`, `32`, `x64`, `64` ~ the default is `x64`

for os specify one of `linux`, `windows` ~ the default is `linux`

for example:
```bash
$ ret abi x64 linux
$ ret abi 32 windows
```

for more detailed information on calling conventions refer to https://www.agner.org/optimize/calling_conventions.pdf

🔗 https://github.com/rerrorctf/ret/blob/main/commands/abi.go

---

### 📥 <u>ad</u>d

```
$ ret add file1 [file2 file3...] 
```

add one or more files to the current task with ret

performs the following steps:
1. analyze each file to determine if it is an elf or not by examing the file's magic bytes
2. generate a sha-2-256 hash for each file
3. added files are copied into the hidden directory `.ret/files` inside a subfolder that is named using the sha-2-256 hex digest of the file content
4. save metadata about the files, specifically their length, location and file type (i.e. elf or not), in the files json file in the hidden `.ret` directory
5. uses strings, with widths of 8, 16 and 32 bits per character, in combination with grep to search for flags according to the flag format
added files are subject to processing by other commands that operate on the set of added files

adding a file does not prevent changes from occuring to the source file nor does it detect them for you, like a version control system would

you can track several version of a file by adding each of them remembering that they are addressed according to the hash of their content

you can restore a specific version of a file by copying it from the subdirectory in which a copy of it was made when the file was added

🔗 https://github.com/rerrorctf/ret/blob/main/commands/add.go

---

### 😠 <u>an</u>gr

```
$ ret angr 
```

runs the angr docker with ret

mounts the current working directory as a volume

note that this command requires docker

effectively runs:
```bash
$ sudo docker pull angr/angr
$ sudo docker run -it -v $PWD:/home/angr/x angr/angr
```

see https://docs.angr.io/en/latest/getting-started/installing.html#installing-with-docker for more information

🔗 https://github.com/rerrorctf/ret/blob/main/commands/angr.go

---

### 🏁 <u>ca</u>pture

```
$ ret capture [flag] 
```

capture the flag with ret

supply no arguments to see the currently captured flag

note that captured flags are stored in hidden directory `.ret` and therefore scoped to the cwd

flags are stored in the `.ret/flag.json` file

🔗 https://github.com/rerrorctf/ret/blob/main/commands/capture.go

---

### 📢 <u>cha</u>t

```
$ ret --1 --2 --3 chat [-] [message1 message2 message3...] 
```

chat via a discord webhook with ret

use - to read from stdin

requires a valid webhook this is typically `"chatwebhookurl"` from `~/.config/ret` is a valid webhook

however the command supports up to 3 webhooks using `$ ret --1 chat`, `$ ret --2 chat` and `$ ret --3 chat`

if no numerical override is specified the `"chatwebhookurl"` webhook is used by default

webhooks 2 and 3 are set with `"chatwebhookurl2"` and `"chatwebhookurl3"` respectively

requires that `"username"` from `~/.config/ret` is set to valid string

when data is read from stdin, due to the use of the - argument, it will be sent as an embed with an accurate timestamp and a random color

color codes, such as the ones used by this tool, are stripped by this code prior to sending

for more information please see https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks

🔗 https://github.com/rerrorctf/ret/blob/main/commands/chat.go

---

### ✅ <u>chec</u>k

```
$ ret check 
```

check if ret's optional dependencies are installed

checks for the following:
1) docker
2) pwntools
3) ida
4) ghidra
5) pin
6) gcloud
7) 7z
8) pin

🔗 https://github.com/rerrorctf/ret/blob/main/commands/check.go

---

### 🔪 <u>chef</u>

```
$ ret chef [-] [text1 text2 text3...] 
```

open cyberchef with ret

use file - to read from stdin

for example:
```bash
$ echo "hello, world!" | base64 | ret chef -
$ ret chef aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==
```

generates a cyberchef url by appending your input, raw base64 encoded, to https://gchq.github.io/CyberChef/#input=

uses `open` to open the resulting url in your default browser

you can set `"chefurl"` in `~/.config/ret` to use another instance of cyberchef

if you provide a custom url it should be the equivalent of https://gchq.github.io/CyberChef/

🔗 https://github.com/rerrorctf/ret/blob/main/commands/chef.go

---

### 🚩 <u>ct</u>ftime

```
$ ret ctftime [url] 
```

set the current ctftime url with ret

the ctftime url is stored in `~/.config/ret` using the `"ctftimeurl"` field

the ctftime url will be used to aid in the generation of writeups with the `writeup` command

🔗 https://github.com/rerrorctf/ret/blob/main/commands/ctftime.go

---

### 🤏 <u>de</u>compress

```
$ ret decompress file1 [file2 file3...] 
```

decompress one or more files with ret

will first check if the file has a valid extension
valid extensions are `.gzip`, `.gz`, `.zip`, `.xz`, `.7z` and `.tar`

if the file has a valid extension decompress will then check if the file has a valid magic

if the file has a valid extension and magic it will be decompressed with 7z as if the following was executed:

`$ 7z e filename -y`

🔗 https://github.com/rerrorctf/ret/blob/main/commands/decompress.go

---

### 🐋 <u>do</u>cker

```
$ ret docker [ip] [port] 
```

create a dockerfile from a template with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/docker.go

---

### 🔍 <u>f</u>ormat

```
$ ret format [regex] 
```

set the current flag format regex with ret

the flag format is stored in `~/.config/ret` using the `"flagformat"` field

the flag format regex will be used to search for flags when adding files with the `add` command

🔗 https://github.com/rerrorctf/ret/blob/main/commands/format.go

---

### 🦖 <u>gh</u>idra

```
$ ret ghidra [file1 file2 file3...] 
```

ingests all added files then opens ghidra with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/ghidra.go

---

### 🐙 <u>gi</u>st

```
$ ret gist file1 [file2 file3...] 
```

make private gists with ret
specify the path of one or more files to upload

🔗 https://github.com/rerrorctf/ret/blob/main/commands/gist.go

---

### 💃 <u>id</u>a

```
$ ret ida file1 [file2 file3...] 
```

opens all added files then opens ida with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/ida.go

---

### 🔬 <u>in</u>scount

```
$ ret inscount 
```

create a pin script to count instructions from a template with ret

uses `"inscountpythonscriptname"` from `~/.config/ret` to name the file

this command assumes it can find a pin installation at /opt/pin

you can find pin install instructions here https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html

🔗 https://github.com/rerrorctf/ret/blob/main/commands/inscount.go

---

### 🗽 <u>l</u>ibc

```
$ ret libc [tag] 
```

get a version of libc by copying it from a docker container with ret
specify an image tag like "ubuntu:24.04" to get a specific version
without args this command will use the tag "ubuntu:latest"
the file will be copied to the cwd and added with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/libc.go

---

### 📝 <u>n</u>otes

```
$ ret notes [-] [note1 note2 note3...] 
```

take notes with ret
use - to read from stdin

🔗 https://github.com/rerrorctf/ret/blob/main/commands/notes.go

---

### 🐚 <u>p</u>wn

```
$ ret pwn [ip=127.0.0.1] [port=9001] 
```

create a pwntools script template with ret

the file this command creates is named using `"pwnscriptname"` from `~/.config/ret` and is `"go.py"` by default

this command attempts to guess the name of the main task binary using the list of added files and their types

you can specify the path of a custom template with `"pwnscripttemplate"`

this command will do the follow substitutions in custom templates:
1) `/%BINARY%/binary`
2) `/%IP%/ip`
3) `/%PORT%/port`

for example:
1) `"remote("%IP%", %PORT%)"` would become `"remote("127.0.0.1", 9001)"`
2) `"process("./%BINARY%")"` would become `"process("./task")"`

🔗 https://github.com/rerrorctf/ret/blob/main/commands/pwn.go

---

### 📃 <u>r</u>eadme

```
$ ret readme 
```

make the readme with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/readme.go

---

### 🌿 <u>sa</u>ge

```
$ ret sage 
```

open sage with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/sage.go

---

### 🌐 <u>sh</u>are

```
$ ret share 
```

share task progress with ret


🔗 https://github.com/rerrorctf/ret/blob/main/commands/share.go

---

### 👀 <u>st</u>atus

```
$ ret status 
```

displays the status for the current task with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/status.go

---

### 📞 <u>sy</u>scall

```
$ ret syscall [(x86/32)/(x64/64)] [regex] 
```

check syscalls by regex with ret

  uses: 
    x86: /usr/include/x86_64-linux-gnu/asm/unistd_32.h
    x64: /usr/include/x86_64-linux-gnu/asm/unistd_64.h

  examples: 
    syscall x64 " 0"
    syscall x64 write
    syscall 32 read
    syscall x86 10[0-9]


🔗 https://github.com/rerrorctf/ret/blob/main/commands/syscall.go

---

### 🧙 <u>wi</u>zard

```
$ ret wizard [ip=127.0.0.1] [port=9001] 
```

do magic with ret

wizard is here to help! they simply run a few common commands suitable for a typical workflow

the workflow is quite well suited for typical rev and pwn tasks and may be useful for tasks in other categories too

sometimes the wizard makes mistakes! be sure to check its work by carefully reviewing the detailed output

steps the wizard performs:
1) executes the `"wizardprecommand"` string with `"bash -c"` from `~/.config/ret`
2) searches for interesting files within the current directory. this is typically the task handout .zip file
3) ensures that the hidden `.ret` directory skeleton exists
4) decompresses, using the `decompress` command, any interesting files that it can
5) adds any interesting files using the `add` command. this includes those found by decompression and ignores the compressed archives themselves files
6) shows the added files using the `status` command
7) invokes `pwn` for you
8) if you provided an `ip` or an `ip` and a `port` wizard will pass these to `pwn` command
9) executes the `"wizardpostcommand"` string with `"bash -c"` from `~/.config/ret`

🔗 https://github.com/rerrorctf/ret/blob/main/commands/wizard.go

---

### 📝 <u>wr</u>iteup

```
$ ret writeup 
```

create a markdown writeup using a template with ret

the writeup will saved in a file called `writeup.md`

if a file called `writeup.md` already exists the command will abort

1. uses the `"ctftimeurl"` to insert a url at the top of the writeup
2. imports all notes taken with the `notes` command into the description area
3. creates a space for a python script and then imports the script created by `pwn` if one exists
4. imports the flag captured with the `capture` command if one exists or the regex specfied with `format` if one does not
5. uses the `"username"` from `~/.config/ret` to attribute to this writeup to you
6. inserts a date stamp for today's date using yyyy/mm/dd format

🔗 https://github.com/rerrorctf/ret/blob/main/commands/writeup.go

---

## ~/.config/ret

`ret` will parse `~/.config/ret`:

```json
{
  "ghidrainstallpath": "",
  "ghidraproject": "",
  "idainstallpath": "",
  "pwnscriptname": "",
  "pwnscripttemplate": "",
  "inscountpythonscriptname": "",
  "flagformat": "",
  "wizardprecommand": "",
  "wizardpostcommand": "",
  "username": "",
  "chatwebhookurl": "",
  "chatwebhookurl2": "",
  "chatwebhookurl3": "",
  "gisttoken": "",
  "googlecloudproject": "",
  "googlecloudregion": "",
  "googlecloudsshkey": "",
  "chefurl": "",
  "ctftimeurl": ""
}
```
