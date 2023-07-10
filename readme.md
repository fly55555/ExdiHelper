# ExdiHelper #
## 这是什么? ##
###  ###
##### 为了方便使用Exdi调试而写的插件 #####
##### 微软提供了一种特殊的内核调试方式[Exdi](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/debugger/configuring-the-exdi-debugger-transport) #####
##### 这让我们可以把其他平台提供的调试接口(GDB or other)转换成Exdi的调试接口以便于Windbg调试 #####
####### 可以看微软的项目 [ExdiGdbSrv](https://github.com/microsoft/WinDbg-Samples/tree/master/Exdi/exdigdbsrv) 或者我fork后修改过(针对Vmware虚拟机修复了一些内容)的项目[MyExdiGdbSrv](https://github.com/fly55555/ExdiGdbSrv) #####
##### 这个插件的功能仅仅是修复了Exdi调试模式下，Windbg调试核心的一些问题 ###
##### 修复内容1：对于win8及以上的系统KdDebuggerDataBlock并没有解密导致调试核心很多功能无法使用 #####
##### 修复内容2：kdexts扩展提供的!pte功能由于Exdi下模式下默认使用了错误的PteBase需要修正 #####
## 如何使用? ##
##### 你只需要编译这个项目，把生成的Dll文件复制到windbg目录 #####
##### 在Exdi连接成功，并且确认符号已经正常加载后 #####
##### 键入命令 #####
##### .load exdihelper #####
##### !rox #####
##### 之后，大部分功能都将正常使用 #####
##### 对于Windbg+Exdi+Gdb+Vmware调试，我强烈建议你使用我修改后的项目 [MyExdiGdbSrv](https://github.com/fly55555/ExdiGdbSrv) #####
##### 在这个项目里我修复了更多的内容，可以让你的调试体验更加美好 #####