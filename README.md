# keymesh
share your ssh key with as many servers as you'd like. written in golang

I'm in the process of merging this project into the send repo as a lot of the code is the same. I Just keep running into issues along the way :)

```
$ keymesh 

store contents of key.pub in remote .ssh/authorized_keys

usage:

arguments:
-u    user name
-s    supress stdout
-k    specify key path
-p    ssh port
-m    multiple hosts: -m "host1 host2 host3"
-f    read hosts from file separated by new line
-t    command timeout in seconds (default is 120)
-l    logfile name (default is keymesh.log)
-o    execute in order instead of asynchronously
```
