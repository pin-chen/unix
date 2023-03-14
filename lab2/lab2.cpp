#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <fstream>

using namespace std;

string magic;
int x = 1;
void listdir(const char *name, int indent)
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(name)))
        return;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char path[1024];
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
            //cerr << path << "/" << entry->d_name << '\n';
            //printf("%*s[%s]\n", indent, "", entry->d_name);
            listdir(path, indent + 2);
        } else {
            string path = string(name) + "/" + string(entry->d_name);
            string x;
            ifstream in(path, ios::binary);
            in >> x;
            if(x == magic){
                cout << path << '\n';
                exit(0);
            }
            //cerr << name << "/" << entry->d_name << "\n";
            //printf("%*s- %s\n", indent, "", entry->d_name);
        }
    }
    closedir(dir);
}


int main(int argc, char**argv){
    magic = string(argv[2]);
    
    listdir(argv[1], 0);
    cerr << "Magic: " << magic << '\n';
    //cout << ".\n";
    return 0;
}
/*


    while(1){
        string s;
        cin >> s;
        cout << s;
    }


 if(x == 1){
                cout << name << "/" << entry->d_name << "\n";
                x = 2;
            }
*/