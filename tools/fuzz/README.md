# 模糊测试：持有 PSK 的对端

`fuzz_peer.c` 是 libFuzzer 目标，针对"对端持有 PSK"的威胁模型（[SECURITY_AUDIT.md](../../docs/SECURITY_AUDIT.md) 第 4 节）。持有 PSK 的一方能让任意明文通过认证，它能触达的就是解析器 `anl_input_plain`：数据报头和全部段类型。目标把输入直接交给它，等同于认证通过之后 `siv_open` 交给解析器的内容。

- 每个输入在一个新连接上运行（服务端，自己开了一个可靠流和一个带 FEC 的半可靠流，对端还可以再开），发现的问题只凭输入本身即可复现；
- 输入是一串数据报，每个是 2 字节小端长度加相应字节。conv 和版本位被改成正确值，使段被解析；ts、pn 保持模糊值；
- 除了 ASan / UBSan，每个数据报之后检查两个不变量：默认流仍在；每个流缓存的分片不超过窗口。违反时 abort，与内存错误一样报告。

## 构建与运行

需要 Clang 和它的 libFuzzer / sanitizer 运行时（Ubuntu：`libclang-rt-18-dev`）。

```
cmake -B build-fuzz -DCMAKE_C_COMPILER=clang -DANLIU_BUILD_FUZZERS=ON
cmake --build build-fuzz --target anl_fuzz_peer anl_fuzz_seeds
mkdir -p corpus && build-fuzz/anl_fuzz_seeds corpus
build-fuzz/anl_fuzz_peer -max_total_time=1800 -jobs=4 -workers=4 corpus
```

`anl_fuzz_seeds` 运行一次真实的客户端到服务端媒体交换，把客户端发出的明文（带流参数的 DATA、ACK、PARITY、FWD、CLOSE 等）写成种子；每个种子以开流的前两个数据报开头，再接一段后续数据报。CTest 中的 `anliu.fuzz_peer_smoke` 只做 2 万次的确定性短跑。

发现的输入（`crash-*`）可直接复现：`build-fuzz/anl_fuzz_peer crash-<hash>`。
