FROM hitzhangjie/debugger101:latest

#vscode doesn't support old OS and gopls extensions, 
#so use debugger101:latest (centos stream9+go1.22.4)
# to replace linux101:go1.19.
#
#FROM hitzhangjie/linux101:go1.19"

USER root

ENV	GOPROXY=https://goproxy.cn,direct

RUN yum install -y libdwarf-tools.x86_64 		  && \
	yum install -y binutils.x86_64

RUN git clone https://github.com/cli/cli /tmp.cli && \
	cd /tmp.cli/cmd/gh							  && \	
	git checkout v2.0.0							  && \
	go install -v

RUN mkdir /root/workspaces

WORKDIR /root/workspaces/godbg
