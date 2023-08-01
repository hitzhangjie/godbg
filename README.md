# 项目说明

该项目是与 debugger101/golang-debugger-book 配套的一个完整调试器实现示例，读者可结合书中内容，配合着这里的示例代码加深理解。

# 实验环境

该项目中提供了Dockerfile、docker.sh，您可以执行脚本docker.sh快速启动一个docker容器，并在容器中进行测试。

由于本项目是学习型目的，非工程型产品dlv、gdb的替代品，所以我们统一环境掌握相关知识是首要目标，请大家反馈问题之前务必确认是在实验环境展开的实验。

该调试器示例，重在介绍如何开发调试器，而非强调功能的完备性，其大致要包含的功能如下：

![todolist](todolist.PNG)

# 大致实现

下面介绍下，该调试器示例的大致实现方式：

- 首先，基于cobra、cobra-prompt搭建了一个go语言符号级调试器的大体框架；
- 容易扩展新功能，后续实现只需添加cmd及处理逻辑即可，大家可以在cmd/下根据命令名来查找对应实现逻辑；

## 命令管理

调试器启动时有多种启动方式，比如godbg exec <prog>, godbg attach <pid>，godbg core <coredump>, godbg debug <project>等，因此其涉及到一些命令管理的逻辑。

技术选型：flags风格的命令管理框架，支持常见类型的选项设置、支持圈定必须参数、参数继承、支持命令help信息、支持命令自动补全，甚至还支持子命令。相比自己重新实现一个而言使用cobra更符合大部分开发者的"选择"
，比较有助于大家将精力花在调试器逻辑本身，而非琐碎的命令管理上。而且也能节省我们后续开发中投入的时间。

## 交互命令

调试器启动之后，还需要支持丰富的交互命令，以方便开发人员对程序进行调试，如list查看源代码、disass反汇编、breakpoint设置断点、clear清除断点、ptype打印类型信息、print打印变量值、bt打印堆栈等等。

不同的交互命令，也是有不同的参数的，所以还是涉及到命令的管理。

我们可以自己维护help及别名h、描述信息、处理函数的相关逻辑。比如类似dlv的处理方式，但是这个方式并不很优雅。

前面我们分析了cobra命令管理框架的好处，但是对于这里的交互命令，虽然cobra也可以管理，但是还是需要用点技巧。我理解，主要是使用场景的区别吧。godbg刚启动时用户有大把试错的机会，输入错误看到cobra提示信息，用户可以重新输入。但是一旦当调试会话启动之后ma，用户还是应该将注意力集中在调试本身，调试器应该尽可能地辅助用户输入更精确的命令、选项信息，使调试过程更流畅。这就涉及到动态提示了。

go-prompt是一个不错的交互输入管理框架，能够支持比较好的动态补全能力，还不错。但是我们更希望能使得godbg不管是命令还是交互命令都有一样的使用体验。如果我们能将go-prompt和cobra结合起来，那就比较完美了，刚好有人做过这方面的工作，参考cobra-prompt。

我们基于cobra来管理godbg <cmd>的cmd部分，对于调试器启动之后的交互指令的管理，我们使用cobra-prompt来管理。

> 特此说明：由于cobra-prompt对调试干扰有点大，我们使用liner进行了替代。

## 测试方式

为了避免环境的多样性带来的复杂性，我们使用统一的docker镜像对调试器实现进行测试，因此请读者们先自行安装docker。

1. 执行脚本 `docker-build.sh` 构建用于测试的docker image；
2. 执行脚本 `docker-start.sh` 启动测试用的容器；

容器启动之后会自动将当前工程目录作为容器内的工作目录，我们可以在这里进行编译、测试等相关的操作。同时镜像中也已经配置好了常用的工具链（vim、go、dlv等），也方便我们对代码进行修改、编译测试、调试等操作。

ps: 项目也提供了 `.devcontainer+dockerfile`，如果您使用 vscode 进行开发，那么也可以直接选择 `reopen in devcontainer`。

## 联系方式

如果您有任何建议，请提Issues，或邮件联系 hit.zhangjie@gmail.com，标题中注明来意GoDebugger交流。

希望该书及相关示例，能顺利完成，也算是我磨练心性、自我提高的一种方式，如果能对大家确实起到帮助的作用那是再好不过了。

如果喜欢本项目，别忘了 Star 一下对作者予以支持 :)
