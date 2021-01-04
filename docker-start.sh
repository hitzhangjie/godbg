#!/bin/bash -e

# debugger need priviledges including, ptrace, etc.
docker run -it                                                              \
-v `pwd -P`:/root/debugger101/godbg                                         \
--name debugger.env --cap-add ALL                                           \
--rm debugger.env                                                           \
/bin/bash
