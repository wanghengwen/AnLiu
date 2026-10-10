# 测试

本文件说明 AnLiu 的测试用例怎样组织、版本回归怎样做、结果怎样判定。用例本身放在 [testcases/](testcases/) 目录，分四类：

- 单元测试；
- 仿真（单机，虚拟时间）；
- 实网测试；
- 版本回归的组合方式。

每个用例都有编号、步骤和**可判定的通过规则**。这些用例既给脚本用，也给大模型代理照着文字执行：代理读这些文件、执行命令、按规则判定，再写出报告。

相关文档：

- 测试结果的历史：[PROGRESS.md](PROGRESS.md)；
- 性能数据：[PERFORMANCE.md](PERFORMANCE.md)；
- 对比数据：[COMPARISON.md](COMPARISON.md)；
- 实网工具：[tools/realnet/README.md](../tools/realnet/README.md)。

## 目录

| 文件 | 编号 | 内容 | 执行 |
|---|---|---|---|
| [testcases/01-unit.md](testcases/01-unit.md) | UT、AT、DG、FZ、SAN | `test.c`、攻击测试、诊断核算、模糊测试、Sanitizer 构建 | `ctest`；FZ 由代理执行 |
| [testcases/02-sim.md](testcases/02-sim.md) | SM | 媒体仿真门槛、新旧版本成对仿真、多种子单元测试 | 脚本，按本文件判定 |
| [testcases/03-realnet.md](testcases/03-realnet.md) | RN | 实网用例的环境与参数：主机与路径、出口容量、变体部署、有效轮次、批次脚本 | |
| [testcases/RN-*.md](testcases/) | RN | 实网测试，每个用例一个文件 | 代理 |
| [testcases/00-template.md](testcases/00-template.md) | | 新增代理用例的模板 | |

## 版本回归

`anliu.c` 有改动时，按下面三步做版本回归，把新版本（候选）与上一个经过实网验证的版本（基线）比较。

**第一步：单机，约 1 小时。**

- UT / AT / DG / SAN 全部通过；
- SM-01 通过；
- SM-03 的失败只出现在已知不稳定的检查上；
- 改动涉及拥塞控制、FEC 或重传时，加做 SM-02。

**第二步：实网部署与冒烟（RN-01）。**

**第三步：实网成对对照，可以并行。**

| 用例 | 内容 | 默认回归 |
|---|---|---|
| RN-02 | 低 RTT 路径加 tc 时延 +100 / +200 ms，关闭 FEC，媒体 | 做 |
| RN-03 | 广域网路径，关闭 FEC，媒体，SRT 作参考 | 做 |
| RN-04 | 流的打开与关闭 | 改动涉及流、关闭、sid 或线上格式时做 |
| RN-05 | 2 Mbit 瓶颈，编码器闭环，关闭 FEC | 改动涉及拥塞控制或码率接口时做 |
| RN-06 | 开启自动 FEC 的媒体 | 只在改动 FEC 时做（2026-10-06 起性能测试只覆盖关闭 FEC） |

## 运行

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j && (cd build && ctest --output-on-failure)
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DANLIU_ENABLE_SANITIZERS=ON && cmake --build build-asan -j && (cd build-asan && ctest --output-on-failure)
```

实网用例需要 `ANL_REALNET_HOSTS`（主机表）与 `ANL_REALNET_WORK`（本批次的工作目录）。详见 [testcases/03-realnet.md](testcases/03-realnet.md)。

## 判定

- **脚本与 `ctest`**：退出码为 0，并且没有 `FAIL` 行，即为通过。
- **代理用例**（`02-sim.md` 中标为"代理"的用例、`RN-*.md`、FZ）：按文件中的"通过规则"逐条判定，全部满足才算通过。
- **成对对照的差值**：一律写成"候选 − 基线"。
  - 只有均值超过限值，并且 95% 区间不含 0，才判为回归。
  - 均值超过限值、但区间含 0 的，记为"待确认"：在同一场景加种子重跑一次，再判定。

## 代理执行规则

1. **仓库与文档里不写主机地址、账号、密钥。**
   - 主机只用主机表里的名字。
   - 实网工具会在 `ANL_REALNET_WORK` 下写 `events.jsonl`，里面含地址；工作目录要放在仓库之外，`events.jsonl` 不提交。
   - `HANDOVER.md`、`review.md`、`designv2.md` 不提交。
2. **前置条件不满足时判为"阻塞"，不判为"失败"。** 例如主机连不上（`ssh -o ConnectTimeout=10` 失败）、构建失败、tc 不可用，写明原因后继续做下一个用例。
3. **成对的两个版本必须在同一路径上同时运行。**
   - 换路径或换时间段得到的差异，不能归因于版本。
   - 重复的轮次要交换两个版本的端口或启动顺序：五元组不同可能被分到不同路由，一些路径的基准 RTT 相差可达 26 ms。
4. **控制带宽预算。**
   - 每台主机上同时运行的轮次，限速合计不超过该主机的 `cap_kbps − 5000`（单位 kbit/s）。
   - 发送端与接收端都要计入。
5. **丢包与时延统一由 tc 在发送端实现**（`multi_tc.py`），不在应用里丢包。
   - `cmp_round.py` 与 `churn_round.py` 总是这样；`multi_round.py` 要加 `--tc-loss`（任务文件里 `"tc_loss": true`），否则它默认在应用的接收侧随机丢包。
   - 丢包率取 3 / 5 / 7 / 10%，重点是 3% 与 5%（用两个种子）；完整回归加 15%，不超过 15%。
6. **无效轮次**（进程退出码非 0、运行时长不完整、tc 计数为 0、日志校验失败）**不计入结果。**
   - 同一场景重跑一次；仍无效的，写明原因。
   - 有效轮次少于计划的 80% 时，该用例判为"阻塞"。
7. **不要放宽断言或通过规则。**
   - 结果不满足规则时，先按规则 3 排除测试方法的原因，再报告。
   - 需要修改规则的，在报告中说明理由，由维护者决定。
8. **报告用中文**：一张表，列为"编号 / 结果（通过、失败、阻塞、待确认）/ 实测值 / 证据"。证据是日志原文或分析脚本的输出行。表后列出失败与阻塞的原因。
9. **代理用例通过后**，把文件头的 `last_run` 更新为日期、结果、两个版本的提交号和关键数值。基准有明显变化时，同时更新"基准"一节，并说明原因。
10. **提交与推送只在维护者要求时进行。**
    - 提交说明里不加任何协作者署名行。
    - 不经同意不推送（`git push`）。

## 维护

- 新增代理用例：复制 [testcases/00-template.md](testcases/00-template.md)，在 `testcases/` 下新建"编号-简短英文名.md"（例如 `RN-07-xxx.md`），编号不复用。
- 修改测试工具（`bench/`、`tools/realnet/`）时，同时修改引用它的用例的步骤。
- 新的前缀要在本文"目录"一节中登记。
