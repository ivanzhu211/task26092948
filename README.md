# urlthreat — 本地 URL 威胁判定库

离线判断浏览目标是否涉及跟踪、钓鱼或数据采集。纯 Python + SQLite，无外部服务依赖。

## 用法

```python
from urlthreat import ThreatDB

with ThreatDB("rules.db") as db:
    db.import_rules([
        {"id": "A", "url": "https://*.example.test/a", "risk": 40, "categories": {"跟踪"}},
        {"id": "B", "url": "https://x.example.test/a/b", "risk": 85, "categories": {"钓鱼"}},
    ])
    v = db.judge("HTTPS://X.EXAMPLE.TEST.:443/a/%62/../b/c?q=/ab#f")
    # v.matched_ids == ("A", "B"), v.max_risk == 85, v.categories == {"跟踪", "钓鱼"}
```

- `import_rules`：批量导入，`id`/`url`/`risk`(0-100)/`categories`（"跟踪"/"钓鱼"/"采集"）。
  同 ID 重导为完整替换；规则持久化到 SQLite，关闭重开结果不变。
- `judge(url)`：返回全部命中 ID、最高风险分与类别并集；无命中返回 0 分与空集合。

## 匹配语义

- 仅 HTTP/HTTPS 与 ASCII 域名；协议、主机忽略大小写，主机去末尾一个点；
  省略端口等价于 80/443；空路径视为根路径；用户信息、查询、片段不参与匹配。
- 规则主机可以 `*.` 开头，匹配该域任意深度子域（不含域名自身）；其他主机精确匹配。
- 路径区分大小写；百分号编码仅解码 ASCII 字母数字及 `-._~`，其余保留并大写十六进制，
  不重复解码；消除 `.`/`..` 段（不越过根），保留连续斜杠与末尾目录斜杠。
- 路径相等即命中；否则目标须以规则路径开头，且规则路径以 `/` 结尾或目标下一字符为 `/`。

## 结构

- `urlthreat/normalize.py` — URL 解析与规范化
- `urlthreat/store.py` — SQLite 规则持久化
- `urlthreat/matcher.py` — 内存索引与匹配
- `urlthreat/engine.py` — `ThreatDB` 入口

## 测试

```sh
python3 -m unittest discover tests
```

含验收用例与规模测试（50 万规则，1 万次判定 <10s，峰值内存 <512MiB；
本机实测约 0.07s / 255MiB）。
