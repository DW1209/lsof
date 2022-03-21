#include <pwd.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <bits/stdc++.h>

#define BUFFER_SIZE 1024

using namespace std;

struct pid_info_type {
    pid_t pid;
    char path[PATH_MAX];
    char cmdline[BUFFER_SIZE];
    char username[BUFFER_SIZE];
};

// Record inodes and filenames to prevent printing the same on screen.
set<pair<pid_t, string> > records;

void print_header(){
    printf("%-9s %8s %11s %7s %9s %11s %9s\n", 
        "COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME"
    );
}

void print_type(string fd, struct pid_info_type *info, const char filter_type, const string filter_word){
    ssize_t link_destination_size; char link_destination[PATH_MAX];
    string path = string(info->path) + fd, type;

// Change the variable fd and type according to the argument fd.
    if (fd == "root") fd = "rtd";
    else if (fd == "exe") fd = "txt";

    if (fd == "cwd" || fd == "rtd") type = "DIR";
    else if (fd == "txt") type = "REG";

// Read the link from the path /proc/pid/{cwd, root, exe} and check the permission.
    if ((link_destination_size = readlink(path.c_str(), link_destination, sizeof(link_destination) - 1)) < 0){

// Ignore it if it was not suitable to the require.
        if (filter_type == 't'){
            if (filter_word != "unknown") return;
        } else if (filter_type == 'f'){
            string str(link_destination); smatch match; regex expression(filter_word);
            if (!regex_search(str, match, expression)) return;
        }

// Check the errno and according to it to print the scentence on screen.
        if (strcmp(strerror(errno), "Permission denied") == 0){
            printf("%-9s %8d %11s %7s %9s %11s %s (%s)\n", 
                info->cmdline, info->pid, info->username, fd.c_str(), "unknown", "", path.c_str(), strerror(errno)
            );
        } else if (strcmp(strerror(errno), "No such file or directory") == 0){
            printf("%-9s %8d %11s %7s %9s %11s %s\n", 
                info->cmdline, info->pid, info->username, fd.c_str(), "unknown", "", path.c_str()
            );
        } else {
            snprintf(link_destination, sizeof(link_destination), "%s (readlink: %s)\n", path.c_str(), strerror(errno));
        }
    } else {
        link_destination[link_destination_size] = '\0';
        int index = string(link_destination).rfind("deleted");

        struct stat file_stat; long int inode;

// Find the inode of the link file.
        if (stat(link_destination, &file_stat) == 0){
            inode = file_stat.st_ino;
        }

// Ignore it if it was not suitable to the require.
        if (filter_type == 't'){
            if (type != filter_word) return;
        } else if (filter_type == 'f'){
            string str(link_destination); smatch match; regex expression(filter_word);
            if (!regex_search(str, match, expression)) return;
        }

// Redefine the filename if there was "deleted" word after it. Finally, print it on screen.
        if (index != string::npos){
            string filename = string(link_destination).substr(0, index - 2);

            printf("%-9s %8d %11s %7s %9s %11ld %9s\n", 
                info->cmdline, info->pid, info->username, fd.c_str(), type.c_str(), inode, filename.c_str()
            );

            records.insert(make_pair(info->pid, filename));
        } else {
            printf("%-9s %8d %11s %7s %9s %11ld %9s\n", 
                info->cmdline, info->pid, info->username, fd.c_str(), type.c_str(), inode, link_destination
            );

            records.insert(make_pair(info->pid, string(link_destination)));
        }
    }

    return;
}

void print_map(struct pid_info_type *info, const char filter_type, const string filter_word){
    ifstream maps; string offset, inode, file, line;

// Ignore it if it was not suitable to the require.
    if (filter_type == 't'){
        if (filter_word != "REG") return;
    }

// Open the file /proc/pid/maps and check the permission.
    string path = string(info->path) + "maps"; maps.open(path);

    if (maps.fail()){
        if (strcmp(strerror(errno), "Permission denied") == 0) return;
        else perror("fopen error");
    } else { 
        while (getline(maps, line)){
            stringstream ss(line); string word; vector<string> strs;

            while (ss >> word){
                strs.push_back(word);
            }

// Ignore it if the line is not enough size to allocate the variable.
            if (strs.size() < 6) continue;
            offset = strs[2]; inode = strs[4]; file = strs[5];

// Ignore it if it was not suitable to the require.
            if (filter_type == 'f'){
                string str(file); smatch match; regex expression(filter_word);
                if (!regex_search(str, match, expression)) return;
            }

// Ignore it if the inode is 0 or the filename has been printed on screen.
            if (inode == "0" || records.count(make_pair(info->pid, file)) == 1) continue;

            int index = file.rfind("deleted");

            if (index != string::npos){
                string filename = file.substr(0, index - 2);

                printf("%-9s %8d %11s %7s %9s %11s %9s\n",
                    info->cmdline, info->pid, info->username, "DEL", "REG", inode.c_str(), filename.c_str()
                );

                records.insert(make_pair(info->pid, filename));
            } else {
                printf("%-9s %8d %11s %7s %9s %11s %9s\n",
                    info->cmdline, info->pid, info->username, "mem", "REG", inode.c_str(), file.c_str()
                );

                records.insert(make_pair(info->pid, file));
            }

            strs.clear();
        }
    }

    maps.close(); return;
}

void print_fd(struct pid_info_type *info, const char filter_type, const string filter_word){
// Open the file /proc/pid/fd/ and check the permission.
    string path = string(info->path) + "fd/"; DIR *dir = opendir(path.c_str());

    if (dir == NULL){
// Ignore it if it was not suitable to the require.
        if (filter_type == 't'){
            return;
        } else if (filter_type == 'f'){
            string str(path); smatch match; regex expression(filter_word);
            if (!regex_search(str, match, expression)) return;
        }

        if (strcmp(strerror(errno), "Permission denied") == 0){
            printf("%-9s %8d %11s %7s %9s %11s %s (%s)\n", 
                info->cmdline, info->pid, info->username, "NOFD", 
                "", "", path.substr(0, path.size() - 1).c_str(), strerror(errno)
            );
        } else {
            perror("opendir error");
        }
    } else {
        struct dirent *de;
        
        while ((de = readdir(dir)) != NULL){
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0){
                continue;
            } else {
// Read the link from the path /proc/pid/fd/descriptor.
                ssize_t link_destination_size; char link_destination[PATH_MAX];
                string descriptor = de->d_name, current_path = path + string(descriptor);
                
                if ((link_destination_size = readlink(current_path.c_str(), link_destination, sizeof(link_destination) - 1)) < 0){
                    perror("readlink error");
                } else {
                    link_destination[link_destination_size] = '\0';

                    struct stat link_stat, file_stat; long int inode; 
                    string type, fds; bool read = false, write = false;

// Use lstat function to get inode and the RW mode of the file /proc/pid/fd/descriptor.
                    if (lstat(current_path.c_str(), &link_stat) == 0){
                        switch (link_stat.st_mode & S_IREAD){
                            case S_IREAD: read = true;  break;
                            default:      read = false; break;
                        }
                        
                        switch (link_stat.st_mode & S_IWRITE){
                            case S_IWRITE: write = true;  break;
                            default:       write = false; break;
                        }

                        if (read && write) fds = descriptor + "u";
                        else if (read && !write) fds = descriptor + "r";
                        else if (!read && write) fds = descriptor + "w";
                    } else {
                        perror("lstat error");
                    }

// Use stat function to get the type of the file /proc/pid/fd/descriptor->link.
                    if (stat(link_destination, &file_stat) == 0){
                        inode = file_stat.st_ino;

                        switch (file_stat.st_mode & S_IFMT){
                            case S_IFCHR:  type = "CHR";     break;
                            case S_IFDIR:  type = "DIR";     break;
                            case S_IFREG:  type = "REG";     break;
                            case S_IFIFO:  type = "FIFO";    break;
                            case S_IFSOCK: type = "SOCK";    break;
                            default:       type = "unknown"; break;
                        }
                    } else {
// Use stat function to get inode and the RW mode of the file /proc/pid/fd/descriptor.
                        stat(current_path.c_str(), &link_stat); inode = link_stat.st_ino;
                        string filename = string(link_destination); int index = filename.find("deleted");

                        switch (link_stat.st_mode & S_IFMT){
                            case S_IFCHR:  type = "CHR";     break;
                            case S_IFDIR:  type = "DIR";     break;
                            case S_IFREG:  type = "REG";     break;
                            case S_IFIFO:  type = "FIFO";    break;
                            case S_IFSOCK: type = "SOCK";    break;
                            default:       type = "unknown"; break; 
                        }

// Redefine the filename if there was "deleted" word after it.
                        if (index != string::npos){
                            filename = filename.substr(0, index - 2);
                            strncpy(link_destination, filename.c_str(), sizeof(link_destination));
                        }
                    }

// Ignore it if it was not suitable to the require.
                    if (filter_type == 't'){
                        if (type != filter_word) continue;
                    } else if (filter_type == 'f'){
                        string str(link_destination); smatch match; regex expression(filter_word);
                        if (!regex_search(str, match, expression)) continue;
                    }

// Print it on screen.
                    printf("%-9s %8d %11s %7s %9s %11ld %9s\n", 
                        info->cmdline, info->pid, info->username, fds.c_str(), type.c_str(), inode, link_destination
                    );
                }
            }        
        }
    }

    return;
}

void list_information(const pid_t pid, const char &filter_type, const string filter_word){
    struct pid_info_type info; struct stat pid_stat; info.pid = pid;
    snprintf(info.path, sizeof(info.path), "/proc/%d/", pid);

// Use stat function to get the uid of the directory /proc/pid, and use getpwuid function to get the username.
    if (stat(info.path, &pid_stat) == 0){
        struct passwd *pw = getpwuid(pid_stat.st_uid);

        if (pw != NULL){
            strncpy(info.username, pw->pw_name, sizeof(info.username));
        } else {
            snprintf(info.username, sizeof(info.username), "%d", (int) pid_stat.st_uid);
            perror("getpwuid error");
        }
    } else {
        strncpy(info.username, "unknown", sizeof(info.username));
    }

// Open the file /proc/pid/comm to get the command.
    char cmdline[PATH_MAX]; string path = string(info.path) + "comm";
    int fd = open(path.c_str(), O_RDONLY);

    if (fd < 0) return;
    
    int number = read(fd, cmdline, sizeof(cmdline) - 1);
    cmdline[number - 1] = '\0'; close(fd);

// Check the command! if it was not suitable to the require, then ignore it.
    if (filter_type == 'c'){
        string str(cmdline); smatch match; regex expression(filter_word);
        if (!regex_search(str, match, expression)) return;
    }

    strncpy(info.cmdline, cmdline, sizeof(info.cmdline));

// Check no argument and argument with -c and -f.
    print_type("cwd", &info, filter_type, filter_word); 
    print_type("root", &info, filter_type, filter_word);
    print_type("exe", &info, filter_type, filter_word); 
    print_map(&info, filter_type, filter_word);
    print_fd(&info, filter_type, filter_word);

    return;
}

int main(int argc, char *argv[]){
    bool command_filter = false, type_filter = false, filename_filter = false;
    string select_command, select_type, select_filename;

// Check if there was an argument during executing it.
    if (argc != 1){
        if (strcmp(argv[1], "-c") == 0){
            command_filter = true; select_command = string(argv[2]);
        } else if (strcmp(argv[1], "-t") == 0){
            type_filter = true; select_type = string(argv[2]);

            if (select_type != "REG" && select_type != "CHR" && select_type != "DIR" && 
                select_type != "FIFO" && select_type != "SOCK" && select_type != "unknown"){
                    cout << "Invalid TYPE option." << endl; exit(-1);
            }
        } else if (strcmp(argv[1], "-f") == 0){
            filename_filter = true; select_filename = string(argv[2]);
        } else {
            cout << "Invalid argument" << endl; exit(-1);
        }
    }

// Open the directory /proc and print the header.
    DIR *dir = opendir("/proc");

    if (dir == NULL){
        cout << "Couldn't open /proc" << endl; exit(-1);
    }

    struct dirent *d; char *remain = NULL;
    print_header();

    while ((d = readdir(dir)) != NULL){
        if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
            continue;
        
        long int pid = strtol(d->d_name, &remain, 10);

// Check whether the name of the directory was number or not, and did things according to the argument.
        if (*remain == '\0'){
            if (command_filter) list_information(pid, 'c', select_command);
            else if (type_filter) list_information(pid, 't', select_type);
            else if (filename_filter) list_information(pid, 'f', select_filename);
            else list_information(pid, 'n', "");
        }
    }

    closedir(dir); return 0;
}
