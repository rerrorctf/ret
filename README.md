# ret

This tool helps you solve ctf tasks by automating workflow and basic analysis and providing useful utilities.

<img src="https://github.com/rerrorctf/ret/assets/93072266/5a998dbb-5730-4b10-9636-45e35e9fe77e" alt="rounding error ctf team logo" width="150"/>

## Installation

You can get the latest binary from https://github.com/rerrorctf/ret/releases.

### Compiling (Optional)

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

for architecture specify one of `x86`, `32`, `x64`, `64`, `arm64`, `aapcs64` ~ the default is `x64`

for os specify one of `linux`, `windows`, `mac` ~ the default is `linux`

for example:
```bash
$ ret abi x64 linux
$ ret abi 32 windows
$ ret abi arm64 mac
```

🔗 https://github.com/rerrorctf/ret/blob/main/commands/abi.go

---

### 📥 <u>ad</u>d

```
$ ret add file1 [file2 file3...] 
```

add one or more files to the current task with ret

performs the following steps:
1. analyze each file to determine if it is an elf or not by examining the file's magic bytes
2. generate a sha-2-256 hash for each file
3. added files are copied into the hidden directory `.ret/files` inside a subfolder that is named using the sha-2-256 hex digest of the file content
4. save metadata about the files, specifically their length, location and file type (i.e. elf or not), in the files json file in the hidden `.ret` directory
5. uses strings, with widths of 8, 16 and 32 bits per character, in combination with grep to search for flags
added files are subject to processing by other commands that operate on the set of added files

adding a file does not prevent changes from occurring to the source file nor does it detect them for you, like a version control system would

you can track several version of a file by adding each of them remembering that they are addressed according to the hash of their content

you can restore a specific version of a file by copying it from the subdirectory in which a copy of it was made when the file was added

🔗 https://github.com/rerrorctf/ret/blob/main/commands/add.go

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

requires a valid webhook this is typically `"chatwebhookurl"` from `~/.config/ret`

however the command supports up to 3 webhooks using `$ ret --1 chat`, `$ ret --2 chat` and `$ ret --3 chat`

if no numerical override is specified the `"chatwebhookurl"` webhook is used by default

webhooks 2 and 3 are set with `"chatwebhookurl2"` and `"chatwebhookurl3"` respectively

requires that `"username"` from `~/.config/ret` is set to valid string

when data is read from stdin, due to the use of the - argument, it will be sent as an embed with an accurate timestamp and a random color

color codes, such as the ones used by this tool, are stripped by this code prior to sending

for more information please see https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks

🔗 https://github.com/rerrorctf/ret/blob/main/commands/chat.go

---

### 🔪 <u>che</u>f

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

you can set `"chefurl"` in `~/.config/ret` to use another instance of cyberchef

if you provide a custom url it should be the equivalent of https://gchq.github.io/CyberChef/

🔗 https://github.com/rerrorctf/ret/blob/main/commands/chef.go

---

### 🚩 <u>ct</u>ftime

```
$ ret ctftime [url] 
```

adds a ctftime url with ret

the ctftime urls are stored in `~/.config/ret` using the `"ctftimeurls"` field

the command will use the ctftime.org api to fetch details about all the currently set ctftime urls and then display them

the ctf's title, start time and finish time will be displayed along with an indication of the time to the start or finish depending on the context

for more details please see https://ctftime.org/api/

the ctftime urls will be used to aid in the generation of writeups with the `writeup` command

🔗 https://github.com/rerrorctf/ret/blob/main/commands/ctftime.go

---

### 🐋 <u>d</u>ocker

```
$ ret docker [ip] [port] 
```

create a dockerfile from a template with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/docker.go

---

### 🪓 <u>f</u>actor

```
$ ret factor [--n] 
```

factor integers with ret

values can be supplied as either base 10 or base 16 strings and the base will be inferred automatically

for example FEED01234 will be treated as a base 16 string and 123456789 will be treated as a base 10 string

you can supply values the most common prefixes i.e. n= -n= --n= 

multiple values can be supplied as a list or with multiple argument prefixes e.g. -n=1,2,3 or -n=1 -n=2 -n=3

this command opportunistically makes use of the following tools to perform factorization:

 - gmp-ecm
 - pari-gp

for example:
```bash
$ ret factor -n=1807415580361109435231633835400969
$ ret factor -n=0x591ccab6e6a72f019cf942f99f09
$ ret factor -n=147879229115615272273161474028448405953
```

🔗 https://github.com/rerrorctf/ret/blob/main/commands/factor.go

---

### 🦖 <u>gh</u>idra

```
$ ret ghidra [file1 file2 file3...] 
```

adds files specified as arguments to this command, creates a ghidra project within the hidden .ret subdirectory, analyzes all added files then opens ghidra with ret

requires that https://ghidra-sre.org/ is installed

this command uses two configurable references to a typical ghidra installation both of which come from `~/.config/ret`

1) `"ghidrarun"` who's default value is ghidra
bash should be able to use this name to find ghidraRun on your path
this is typically located at /opt/ghidra/ghidraRun

2) `"ghidraanalyzeheadless"` who's default value is ghidra-analyzeHeadless
bash should be able to use this name to find analyzeHeadless on your path
this is typically located at /opt/ghidra/support/analyzeHeadless

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

### 💃 <u>i</u>da

```
$ ret ida file1 [file2 file3...] 
```

opens all added files then opens ida with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/ida.go

---

### ✏️ <u>n</u>otes

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

### 📃 <u>re</u>adme

```
$ ret readme 
```

make the readme with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/readme.go

---

### 🚮 <u>rm</u>ctf

```
$ ret rmctf [url] 
```

remove a ctf with ret

the ctftime url will be removed from the list, if it exists in the list, that is stored in `~/.config/ret` in the `"ctftimeurls"`

you can also manually remove ctftime urls from this list by directly editing `~/.config/ret`

🔗 https://github.com/rerrorctf/ret/blob/main/commands/rmctf.go

---

### 🔐 <u>rs</u>a

```
$ ret rsa [--p] [--q] [--e] [--d] [--n] [--c] 
```

solve simple rsa tasks with ret

this command works by applying strategies to the given parameters that look for plaintext that consists of entirely ascii printable bytes

as a result it is well suited to finding flags for ctf tasks but not as a general purpose integer factorization tool

arguments can be supplied as either base 10 or base 16 strings and the base will be inferred automatically

for example FEED01234 will be treated as a base 16 string and 123456789 will be treated as a base 10 string

you can supply arguments the most common prefixes i.e. x= -x= --x= where x is one of {p, q, e, d, n, c}

multiple values can be supplied as a list or with multiple argument prefixes e.g. -n=1,2,3 or -n=1 -n=2 -n=3

this command opportunistically makes use of the following tools to perform compute intensive factorization:

 - gmp-ecm
 - pari-gp

note: this command is essentially a work in progress as strategies are added over time

for example:
```bash
$ ret rsa -n=1807415580361109435231633835400969 -e=65537 -c=1503532357945764445345675481376484
$ ret rsa -n=0x591ccab6e6a72f019cf942f99f09 -e=0x10001 -c=0x4a213f10d6c08b78ff5c0562e6e4
$ ret rsa -n=147879229115615272273161474028448405953 -e=3 -c=11160123069268350498833916853402276143
```

🔗 https://github.com/rerrorctf/ret/blob/main/commands/rsa.go

---

### 🌐 <u>sh</u>are

```
$ ret share 
```

share task progress with ret

if you have captured a flag with the `capture` command this will be sent using the `chat` command

if you have a valid `"gisttoken"` this command will also make a gist and include the url in the chat message

the gist will attempt to include the following files:

1. the pwn script, which uses `"pwnscriptname"`, and is typically generated with the `pwn` command
2. the notes, which are saved in the .ret/notes.json file, and are typically populated with the `notes` command
3. the flag, which is saved in the .ret/flag.json file, and is typically set with the `capture` command

🔗 https://github.com/rerrorctf/ret/blob/main/commands/share.go

---

### 👀 <u>st</u>atus

```
$ ret status 
```

displays the status for the current task with ret

🔗 https://github.com/rerrorctf/ret/blob/main/commands/status.go

---

### 📝 <u>w</u>riteup

```
$ ret writeup 
```

create a markdown writeup using a template with ret

the writeup will be saved in a file called `writeup.md`

if a file called `writeup.md` already exists the command will abort
there is a small window for a time-of-check/time-of-use race here - you have been warned!

1. uses the first url from `"ctftimeurls"` to insert a url at the top of the writeup. inserts the rest as comments if there are more than one
2. imports all notes taken with the `notes` command into the description area
3. creates a space for a python script and then imports the script created by `pwn` if it exists
4. imports the flag captured with the `capture` command if it exists
5. uses the `"username"` from `~/.config/ret` to attribute to this writeup to you
6. inserts a date stamp for today's date using yyyy/mm/dd format

🔗 https://github.com/rerrorctf/ret/blob/main/commands/writeup.go

---

## ~/.config/ret

`ret` will parse `~/.config/ret`:

```json
{
  "ghidrarun": "",
  "ghidraanalyzeheadless": "",
  "ghidraproject": "",
  "idainstallpath": "",
  "pwnscriptname": "",
  "pwnscripttemplate": "",
  "username": "",
  "chatwebhookurl": "",
  "chatwebhookurl2": "",
  "chatwebhookurl3": "",
  "gisttoken": "",
  "chefurl": "",
  "ctftimeurls": []
}
```
