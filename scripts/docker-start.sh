#!/bin/bash -e

# debugger need priviledges including, ptrace, etc.
count=`docker ps -a | grep debugger.env | wc -l` 

if [ $count -eq 0 ]
then
    docker run -it                                                              \
    -v `pwd -P`:/root/debugger101/godbg                                         \
    --name debugger.env --cap-add ALL                                           \
    --rm debugger.env                                                           \
    /bin/bash
else
    docker exec -it debugger.env /bin/bash
fi
