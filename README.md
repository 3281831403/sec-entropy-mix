换了一台机器之后生成的令牌居然和上一台完全一样，因为熵源失败时悄悄用了固定种子：多个熵源必须全部参与混合，任意一个熵源失败都不得把输出降级为固定值；每次输出必须携带健康状态标记；在可复现模式下，相同输入与相同种子必须得到相同结果；混合结果长度必须达到策略要求；重复的熵源不得重复计数；批量混合时各请求必须相互独立。不变量：熵源失败时输出不可预测且必须标记为不健康；混入新的熵源必然改变输出。

接口
----

模块导出 collect、dedupe_sources、mix、health、check_length、reproducible、validate_config、mix_batch 八个函数。

熵源用字典描述，字段为 id、data、ok。collect 返回 samples、status、count、collected、failed、entropy_bits；status 为按熵源 id 映射的状态。混合结果字段为 label、hex、length、healthy、status、sources_used、entropy_bits、sources；length 的单位是字节，hex 是小写十六进制。status 取 healthy、degraded、unavailable；sources 记录每个熵源的状态，取 ok、failed。reproducible 返回与 mix 相同的字段，并额外包含 seed。mix_batch 返回 results 与 count，results 中每个元素与 mix 的结果结构相同。

配置字典的字段为 sources、health_marker、min_bytes。配置校验返回问题代码列表，代码包括 single_source、missing_health_marker、insufficient_length。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

