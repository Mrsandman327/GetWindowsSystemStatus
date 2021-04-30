# GetWindowsSystemStatus
> 获取系统CPU，内存使用率，磁盘读写速度，网速。磁盘，网卡等等系统信息
> 欢迎增加功能和修改bug
> ```c++
> void		SystemInit(DWORD object = SYSSTATE_CPU_USAGE);							//系统初始化(初始化多个项目时使用或运算连接)
> void		SystemUnInit();															        //释放资源
> double		GetSystemNetDownloadRate();												//获取网络下载速度
> double		GetSystemNetUploadRate();												//获取网络上传速度
> double		GetSystemDiskReadRate();												//获取当前磁盘读速率
> double		GetSystemDiskWriteRate();												//获取当前磁盘写速率
> double		GetSystemCpuCurrentUsage();												//系统CPU使用率
> 
> void		GetSystemDiskStatus(std::vector<EACHDISKSTATUS> &vectorDisk);           //获取各个磁盘使用状态
> void		GetSystemDiskStatus(ULONGLONG& AllDiskTotal, ULONGLONG& AllDiskFree);	//获取系统总得磁盘使用状态
> void		GetSystemCurrentDiskStatus(ULONGLONG& TatolMB, ULONGLONG& FreeCaller);	//获取当前磁盘使用状态
> double		GetSystemCurrentDiskUsage();											//获取当前磁盘使用率
> 
> BOOL		GetPhysicalMemoryState(ULONGLONG& totalPhysMem, ULONGLONG& physMemUsed);//获取物理内存状态
> double		GetTotalPhysicalMemory();												//获取可用内存大小
> double		GetTotalPhysicalMemoryFree();											//获取空闲内存
> double		GetTotalPhysicalMemoryUsed();											//获取已使用内存大小
> double		GetPhysicalMemoryUsage();												//获取内存使用率
> 
> void		GetNetCardInfo(std::vector<NETCARDINFO> &vectorNetCard);				//获取网卡信息
> void		GetOsInfo(std::string &osinfo);                                         //获取操作系统信息 
> void		GetCpuInfo(std::string &CPUinfo);										//获取CPU硬件信息 	
> void		GetCPUid(std::string &CPUid);											//获取CPUid
> 
> BOOL		GetHDSerial(std::string &HDSerial);										//获取硬盘物理序列号（需要管理员权限）
