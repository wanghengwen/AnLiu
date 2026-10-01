# AnLiu 开发与测试进展

本文件记录本仓库的开发进度、测试结果和待解决的问题，按时间倒序追加。设计与修订理由见 [DESIGN.md](DESIGN.md)，性能数据见 [performance.md](performance.md)。

## 记录规则

- 每条记录写明日期、代码版本（提交号）、测试条件和结论；数据要能复现：说明场景、参数、种子数或轮数。
- 本仓库公开：不写主机地址、账号、密钥、内网拓扑等信息。测试环境按"Linux 服务端 / macOS 客户端、限速 X Mbit、RTT Y ms"这样描述即可。
- 结论区分"已验证"和"观察到、待确认"；同一问题至少复现 3 次再修复，修复先做针对性测试再全面回归。

---

## 2026-10-01

- 仓库建立，代码基于线上版本 1（24 位序号、29 位流号、半关闭、大窗口开销优化，见 DESIGN 13.33）。
- `bench/realnet.c`：TCP 对照组用到的 `TCP_INFO` / `TCP_CONGESTION` 只在 Linux 下编译，macOS 上只输出发送字节数。realnet 现在可以在 macOS（Apple Silicon，clang）上编译运行；Linux 行为不变。
