# 现有 Custom Prompt 样例

从 `mesh_server_entry_functions.json` 和 `xmesh_server_entry_functions.json` 提取的完整样例，按6类函数分组。

## 1. 消息分发函数

### meshServerMsgProc (函数指针数组分发)
```
这是mesh_server层的核心消息分发函数，采用表驱动分发(函数指针数组astMsgProcApi)。请分析：(1)数组中是否有消息类型重复 (2)未匹配的消息是否都走到meshServerDefaultMsgProc (3)每个分支处理完毕后IPC消息缓冲区是否被正确释放(DDM_LinkBaseDlinkMsgFree)
```

### meshServerMainMsgProc (嵌套分发)
```
mesh_server请求消息的顶层入口，提取消息类型后调用meshServerMsgProc，之后释放消息并记录诊断信息。请检查：(1)消息释放是否在所有路径上(包括MsgProc内部异常)都执行 (2)诊断信息记录是否在释放后(避免use-after-free)
```

### xmeshServerMsgProc (switch/case分发)
```
这是xmesh_server层的核心消息分发函数。它根据消息类型(如XMESH_C2S_MSG_BIND_REQUEST等)将消息路由到对应的处理函数。请分析switch/case分支是否覆盖了所有消息类型、是否有未处理的case、以及DDM_XdlinkMsgFree(pucMsg)是否在所有路径上都被调用。注意：此函数本身不管理资源生命周期，资源由各子handler管理。
```

## 2. 资源分配函数

### meshServerPortApplyProc (位图分配)
```
处理MESH_BASE_PUBLIC_MSG_PORT_APPLY。分配端口号资源(通过DDM_BitMapGetFree等位图操作)。端口资源在meshServerPortReleaseProc(主动释放)和连接故障时被回收。这是跨handler的资源生命周期，端口号不在本函数释放，请不要报告为泄漏。请重点关注：(1)位图分配失败时的处理 (2)端口号耗尽时的处理 (3)端口分配后如果响应发送失败是否正确回滚位图
```

### meshServerUcmStreamIntraBindMsgProc (hash表+DDM_ALLOC)
```
处理MESH_UCM_CTL_MSG_US_BIND_C2S。分配UCM绑定信息(DDM_ALLOC)，挂载在server的绑定hash表上。绑定资源在关闭流程中被释放。这是跨handler生命周期，请不要报告绑定信息为泄漏。请重点关注：(1)重复绑定的处理 (2)错误路径回滚 (3)hash表操作的rwlock保护 (4)绑定信息中是否正确记录了dlink上下文(用于故障清理)
```

### meshServerUcmStreamIntraConnMsgProc (多资源分配:conn+fd+shm)
```
处理MESH_UCM_CTL_MSG_US_CONN_C2S。分配UCM连接信息(DDM_ALLOC)，可能分配共享内存映射区(mmap/munmap)和文件描述符。连接资源在meshServerIntraCloseConnProc(正常关闭)和故障处理中被释放。这是跨handler生命周期，conn/fd/shm资源不在本函数释放，请不要报告为泄漏。请重点关注：(1)共享内存映射失败时已分配的conn是否被正确释放 (2)fd分配成功但后续步骤失败时fd是否被MESH_CLOSE_FD关闭 (3)错误路径的完整回滚 (4)rwlock保护范围
```

### meshServerMcmIntraMemberAddMsgProc (位图+链表+DDM_ALLOC)
```
处理MESH_MCM_CTL_MSG_MEMBER_ADD_C2S。通过meshServerMcmCreateMemberInfo/DDM_ALLOC分配MCM成员信息，挂载在MCM组的成员列表上，可能还分配位图槽位(DDM_BitMapSet)。成员资源在meshServerMcmIntraMemberDelMsgProc(主动删除)和MCM组销毁时被批量释放。这是跨handler生命周期，请不要报告为泄漏。请重点关注：(1)成员已存在时的重复添加处理 (2)MCM组不存在时的处理 (3)位图槽位分配与成员挂载的原子性(一个成功另一个失败时的回滚) (4)stMemberLock与stGroupLock的加锁顺序(避免死锁)
```

### xmeshServerBindProc (hash表+引用计数)
```
处理XMESH_C2S_MSG_BIND_REQUEST。此函数分配bind_info资源(通过xmeshCreateBindInfo/DDM_ALLOC)，该资源挂载在全局hash表g_stServerInfo上，在xmeshServerCloseProc(正常关闭)和xmeshServerFaultProc(连接故障)中被释放。这是一个跨handler的资源生命周期：bind资源的释放不在本函数内，请不要将hash表中的bind_info报告为内存泄漏。请重点关注：(1)错误路径上DDM_ALLOC后的DDM_FREE是否完整 (2)hash表操作是否在mutex保护下 (3)发送响应失败时的回滚是否完整
```

### xmeshServerListenProc (引用计数uiConnCnt)
```
处理XMESH_C2S_MSG_LISTEN_REQUEST。此函数分配listen_info资源(通过xmeshCreateListenInfo/DDM_ALLOC)，该资源挂载在全局hash表上，在xmeshServerCloseProc(正常关闭)和xmeshServerFaultProc(故障)中被释放。listen_info还维护连接计数(uiConnCnt)，连接建立时递增、关闭时递减。这是跨handler的资源：listen_info及其引用计数由多个handler协作管理，请不要报告为泄漏。请重点关注：(1)错误路径的资源回滚 (2)uiConnCnt的增减是否在所有路径上配对 (3)mutex保护范围
```

## 3. 资源释放函数

### meshServerPortReleaseProc
```
处理MESH_BASE_PUBLIC_MSG_PORT_FREE。释放端口号资源(通过DDM_BitMapUnSet)。这是meshServerPortApplyProc的配对释放handler。请重点关注：(1)释放不存在的端口号时的处理 (2)重复释放(双重释放位图)的防护 (3)位图操作是否在锁保护下
```

### meshServerIntraCloseConnProc (多资源释放:conn+fd+shm)
```
处理MESH_UCM_CTL_MSG_US_CLOSE_C2S。释放UCM连接信息(DDM_FREE)、关闭文件描述符(MESH_CLOSE_FD/DDM_Close_s)、解除共享内存映射(munmap)。这是meshServerUcmStreamIntraConnMsgProc中分配资源的配对释放handler。请重点关注：(1)连接不存在时的处理 (2)共享内存映射区是否正确解除(munmap) (3)fd是否正确关闭(避免fd泄漏) (4)从hash表移除后是否有悬挂指针 (5)关闭流程中的锁保护
```

### meshServerMcmIntraMemberDelMsgProc (链表+位图+DDM_FREE)
```
处理MESH_MCM_CTL_MSG_MEMBER_DEL_C2S。从MCM组的成员列表移除成员、释放位图槽位(DDM_BitMapUnSet)、释放成员信息(DDM_FREE)。这是meshServerMcmIntraMemberAddMsgProc的配对释放handler。请重点关注：(1)成员不存在时的处理 (2)位图槽位释放(DDM_BitMapUnSet)与DDM_FREE的顺序(先释放位图再释放内存，避免释放后访问) (3)链表移除操作的指针更新是否正确 (4)加锁顺序与AddMsgProc一致(避免死锁)
```

### xmeshServerCloseProc (多资源类型批量释放)
```
处理XMESH_C2S_MSG_CLOSE_REQUEST和XMESH_C2S_MSG_CLOSE_NOTIFY。这是多个资源生命周期的释放端：释放conn_info(DDM_FREE)、递减listen_info的uiConnCnt、释放bind_info(DDM_FREE)。此函数是xmeshServerBindProc/xmeshServerListenProc/xmeshServerConnProc中分配资源的配对释放handler。请重点关注：(1)conn释放时是否正确递减了uiConnCnt (2)bind_info释放后是否有悬挂指针 (3)mutex保护下批量hash表遍历删除的安全性 (4)close请求和close notify两种场景下的资源释放是否都正确
```

## 4. 故障兜底函数

### xmeshServerFaultProc
```
这是故障安全网函数，当xdlink连接断开时被调用。它遍历全局hash表中属于该dlink的所有资源(bind/listen/conn/mcm/member)并批量释放。这是所有资源生命周期的最终兜底释放路径，正常情况下资源应已在CloseProc中释放。请重点关注：(1)遍历hash表时是否遗漏了某种资源类型 (2)conn释放时是否正确递减了listen_info的uiConnCnt (3)批量释放过程中mutex保护是否充分 (4)MCM组中成员的释放是否完整(是否存在只释放了组但遗漏了成员的情况)
```

## 5. 只读查询函数

### meshServerGetProcessInfoProc
```
获取进程信息，只读操作。请检查返回数据的正确性和IPC消息构造。
```

### xmeshServerGetProcessInfoProc
```
处理XMESH_C2S_MSG_GET_PROCESS_INFO_REQUEST。此函数只读取统计信息并发送响应，不涉及跨handler资源管理。请检查：(1)响应消息构造是否正确 (2)DDM_XdlinkMsgAlloc失败时的处理
```

## 6. 初始化/销毁函数

### xmeshServerResInit
```
xmesh_server资源初始化函数。初始化全局mutex、hash表等。请检查：(1)pthread_mutex_init失败时的处理 (2)hash表初始化是否完整
```

### xmeshServerResFinit
```
xmesh_server资源销毁函数。销毁全局mutex、遍历hash表释放所有残留资源。请检查：(1)pthread_mutex_destroy前是否确保无线程持有锁 (2)hash表遍历释放是否遗漏资源 (3)残留资源的释放顺序是否安全
```

---

## 7. 条件参数路径选择函数

### xmeshMcmSocketFree（客户端，泄漏发生点）
```
释放xmesh组播socket资源。此函数在关闭MCM通道时调用xmeshMcmCloseRequest向中心端发送关闭请求，中心端根据bIsMember参数决定摘除哪类节点：bIsMember=TRUE时摘除成员节点(CleanMemberInfoByKey)，bIsMember=FALSE时摘除MCM组节点(CleanMcmInfoByKey)。本函数可能释放的MCM通道有两种角色：创建者(WRITER，ucXdrtType==XDRT_CHAN_WRITER)和成员(READER，ucXdrtType==XDRT_CHAN_READER)，必须根据角色传递正确的bIsMember值。请重点关注：(1)xmeshMcmCloseRequest的bIsMember参数是否根据ucXdrtType区分了WRITER和READER角色 (2)如果硬编码为VOS_FALSE，READER角色关闭时中心端会走CleanMcmInfoByKey而非CleanMemberInfoByKey，导致成员节点永远不被摘除而泄漏 (3)创建组播组(xmeshMcmSetMcastAddr)时ucXdrtType被设为XDRT_CHAN_WRITER，加入组播组时ucXdrtType被设为XDRT_CHAN_READER，请验证所有关闭路径都正确映射了角色到bIsMember
```

### xmeshServerMcmCloseProc（中心端，条件分支处理）
```
处理XMESH_C2S_MSG_MCM_CLOSE_REQUEST。中心端根据ucIsMcmber字段选择不同的资源摘除路径：ucIsMcmber=TRUE时调用xmeshServerCleanMemberInfoByKey摘除成员节点，ucIsMcmber=FALSE时调用xmeshServerCleanMcmInfoByKey摘除MCM组节点。这是两种不同资源的条件摘除，路径选择完全依赖客户端传递的bIsMember参数。请重点关注：(1)两条摘除路径是否都正确执行了DDM_ListRemove+DDM_FREE (2)如果客户端传错bIsMember值(如READER关闭时传FALSE)，会导致成员节点不被摘除而泄漏——请反向验证：调用xmeshMcmCloseRequest的所有客户端代码是否都根据角色正确传递了bIsMember (3)MCM组关闭时(ucIsMcmber=FALSE)是否正确通知了所有成员退出(xmeshServerNotifyMemberMcmQuit)
```
