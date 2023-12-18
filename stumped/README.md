# PWN: Stumped
solver: [N04M1st3r](https://github.com/N04M1st3r)  
writeup-writer: [L3d](https://github.com/imL3d)  

**Description:**
> Michael's computer science project shows the structure of tar files. It is using the tree command on the backend, and something just doesn't seem right...

**files (copy):** [app.py](files/app.py)  
**screenshot:** [homepage](images/stumpedhome.png)

In this challenge we receive a site (and it's code) that runs the unix [tree](https://linux.die.net/man/1/tree) command on an uploaded tar archive. We need to exploit this site and get user access.

## Solution 🌳
When uploading a tar archive to the site to extract, we can write to anywhere on our system via carefully naming our folders. For example, if we have an archive with the path in it: `../../../folder1/file1.txt` we can write into a folder called `folder1` that is 3 directories above us. This is due to INSERT EXPLOIT.  
Our first attempt of breaching this machine was to try and override some important file, in order to get and RCE or expose this machine to the internet. This was incredibly difficult since we didn't really have any information whatsoever on where this code was running from, or what with what privileges - so we abandoned the idea.  
  
After messing around a bit more with the site we noticed something about the text on it - it was powered via the `tree` command on version `1.8.0` - could it be that the version of tree is outdated and we can somehow exploit this???  
So, the search for the source code of this version began (or at least the release notes). Finding the entire source code was surprisingly difficult, but we managed to find it at the end -  [the source code](https://salsa.debian.org/debian/tree-packaging).  
  
 Looking at the changelog of the version that followed `1.8.0`:
 ```
  - -R option now recursively calls the emit_tree() function rather than using
 system() to re-call tree.  Also removes a TODO.
 ```
 BINGO! the `-R` option uses `system`, and we can exploit that to inject our OWN bash code.  
 This can be easily seen when looking at the code from the old version: 
 ```C
hcmd = xmalloc(sizeof(char) * (49 + strlen(host) + strlen(d) + strlen((*dir)->name)) + 10 + (2*strlen(path)));
sprintf(hcmd,"tree -n -H \"%s%s/%s\" -L %d -R -o \"%s/00Tree.html\" \"%s\"\n", host,d+1,(*dir)->name,Level+1,path,path);
system(hcmd);
``` 
  
In order to exploit this we need to name one of our inside folders in the archive in a special way, to include the code that we want to run on the server (we went with a python reverse shell in this case):  
INSERT EXPLOIT  
We we upload the tar archive with this folder we get a reverse shell, and then quickly after the flag🚩:
```
$ cat flag.txt
flag{n0t_5tump3d_4nym0r3!}
```
---
This was a creative challenge that reminded us about updating our versions and not letting strangers upload tar archives into our servers.  
Also props to  [N04M1st3r](https://github.com/N04M1st3r) for having the motivation to pull this one off ;)
  
![isitpwn.gif](images/isitpwn.gif)