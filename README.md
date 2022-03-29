# Implement a 'lsof'-like Program

### Introduction
**lsof** is a tool to list open files. It can be used to list all the files opened by processes running in the system.

### Program Arguments
* **-c REGEX**: A regular expression (REGEX) filter to filter command line. For example, `-c sh` would match `bash`, `zsh`, and `share`.
* **-t TYPE** : A TYPE filter. Valid TYPE includes `REG`, `CHR`, `DIR`, `FIFO`, `SOCK`, and `unknown`. TYPEs other than the listed would be considered invalid. For invalid types, it will print out an error message `Invalid TYPE option.` in a single line and terminate the program.
* **-f REGEX**: A regular expression (REGEX) filter for filtering filenames.

### Explanation
The program will print out including `COMMAND`, `PID`, `USER`, `FD`, `TYPE`, `NODE`, and `NAME`. The meaning of each field (column) is explaining below.
* **COMMAND**:
    * The excutable filename of a running process.
* **PID**:
    * Process ID of a running process.
    * Only handle opened process level, which means does not handle opened files at thread level.
* **USER**:
    * The username who runs the process.
    * Show username instead of UID.
* **FD**: The file descripter. The value shown in this field can be one of the following cases.
    * `cwd`: The current working directory, which is read from `/proc/[pid]/cwd`.
    * `rtd`: The root directory, which is read from `/proc/[pid]/root`.
    * `txt`: The program file of this process, which is read from `/proc/[pid]/exe`.
    * `mem`: The memory mapping information, which can be read from `/proc/[pid]/maps`.
        * If `/proc/[pid]/maps` is not accessible, the program will not show any information about mapped files.
        * A memory-mapped file have multiple segments or be mapped multiple times. However, the program only outputs the first one for duplicated files, i.e., files having the same i-node or filename.
        * The program does not handle mapped memory segments. For example, `[heap]` or anonymously mapped memory segments. Those memory segments should have an i-node number of zero.
    * `DEL`: Indicate a memory-mapped file has been deleted. The program will show this value if there is a "(deleted)" mark right after the filename in memory maps.
    * `[0-9]+[rwu]`: The file descriptor and opened mode.
        * The numbers show the file descriptor number of the opened file.
        * The mode "r" means the file is opened for reading.
        * The mode "w" means the file is opened for writing.
        * The mode "u" means the file is opened for reading and writing.
    * `NOFD`: If `/proc/[pid]/fd` is not accessible. In this case, the values for `TYPE` and `NODE` fields will be left empty.
* **TYPE**: The type of the opened file. The value shown in `TYPE` can be one of the following cases.
    * `DIR`: A directory. `cwd` and `rtd` are also classified as this type.
    * `REG`: A regular file.
    * `CHR`: A character special file. For example, `/dev/null`.
    * `FIFO`: A pipe or a file with "p" type, For example, `pipe:[138394]` or `/run/systemd/inhibit/11.ref`.
    * `SOCK`: A socket. For example, `socket:[136975]`.
    * `unknown`: Any other unlisted types. Alternatively, if a file has been deleted or is not accessible (Permission denied), this column will show `unknown`.
* **NODE**:
    * The i-node number of the file.
    * It will be blank or empty if and only if `/proc/[pid]/fd` is not accesible.
* **NAME**:
    * Show the opened filename if it is a typical file or directory.
    * Show `pipe:[i-node number]` if it is a symbolic file to a pipe.
    * Show `socket:[i-node number]` if it is a symbolic file to a socket.
    * Append `(Permission denied)` if the access to `/proc/[pid]/fd` or `/proc/[pid]/(cwd|root|exe)` is failed due to permission denied.
    * If the filename which is read from `/proc` file system contains a `(deleted)`, the program will remove it from the filename before printing it out.

### Execution
```console
$ make
$ ./lsof [-c REGEX -t TYPE -f REGEX]
```