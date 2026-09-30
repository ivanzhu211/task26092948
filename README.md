# urlthreat

本地 URL 威胁判定库，由上层直接调用，规则持久化到 SQLite。

## 用法

```python
from urlthreat import Rule, ThreatDB

with ThreatDB("rules.sqlite") as db:
    # 批量导入；同 ID 重导为完整替换
    db.import_rules([
        Rule("A", "https://*.example.test/a", 40, frozenset({"跟踪"})),
        Rule("B", "https://x.example.test/a/b", 85, frozenset({"钓鱼"})),
    ])

    result = db.judge("HTTPS://X.EXAMPLE.TEST.:443/a/%62/../b/c?q=/ab#f")
    # result.ids        -> 全部命中规则 ID
    # result.risk       -> 命中规则中的最高风险分（无命中为 0）
    # result.categories -> 命中规则的类别并集（无命中为空集合）
```

## 匹配语义

- 仅支持 HTTP/HTTPS 与 ASCII 域名；协议、主机忽略大小写，去掉主机末尾一个点。
- 省略端口等价于默认端口（HTTP 80 / HTTPS 443），协议与端口必须相同。
- 规则主机以 `*.` 开头时匹配该域名的任意深度子域，但不匹配域名自身。
- 用户信息、查询、片段不参与匹配；空路径视为根路径。
- 路径区分大小写；百分号编码仅解码 ASCII 字母数字及 `-._~`，其余保留并将
  十六进制字母大写，不重复解码；随后消除 `.` / `..` 段（`..` 不越过根），
  连续斜杠保留，编码斜杠不成为路径分隔符。
- 路径相等即匹配；否则目标须以规则路径开头，且规则路径以 `/` 结尾或目标
  紧接字符为 `/`；根路径匹配该主机下所有路径。
- 返回全部命中，不按规则具体程度互相覆盖。

## 测试

```bash
python3 -m pytest tests/            # 全部（含规模测试）
python3 -m pytest tests/ --ignore=tests/test_scale.py  # 仅单元测试
```

规模测试：50 万条规则（25 万条共享同一主机），1 万次判定总耗时 < 10 秒，
进程峰值内存 < 512 MiB。
