# 每日用量快照与昨日用量设计

## 目标

服务每天北京时间 `23:00` 为全部账号各查询一次 Packy 累计用量，把当日边界快照和计算出的每日用量保存到 SQLite。`/my` 页面在每个账号中显示“昨日用量”，公开排行榜不暴露每日数据。

## 已确认行为

- 统计边界固定为 `Asia/Shanghai` 时区每天 `23:00`。
- 日期 `D` 的每日用量通常为 `D 23:00` 累计用量减去 `D-1 23:00` 累计用量。
- 每个账号、每个统计日期最多执行一次自动查询，不自动重试。
- 全部账号按顺序逐个查询，单个账号失败不阻塞后续账号。
- 计划采集直接获取边界数据，不把最多 5 分钟的普通页面缓存当成正式快照；若同一账号已有正在进行的上游查询，可以复用该查询，避免并发重复请求。
- 服务不运行高频后台刷新，只保留每天一次的计划采集。
- `/my` 显示北京时间昨日对应的每日用量；数据不足或采集失败时显示 `—`。
- 历史数据无法回填，从部署后的第一次成功边界采集开始积累。

## 方案取舍

采用每日边界快照，而不是在每次页面查询时被动记录。被动记录无法保证整天无人访问时仍有数据，也无法稳定划分每日区间。也不保存每次查询的事件流水，避免无必要的数据增长。

每天一次边界采集会增加“账号数 × 1”的每日上游请求。现有页面请求缓存和排行榜整点刷新策略保持不变。

## 数据库迁移

数据库版本从 `3` 升到 `4`，新增 `daily_usage_snapshots` 表，不修改现有表：

```sql
CREATE TABLE daily_usage_snapshots (
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  usage_date TEXT NOT NULL,
  cumulative_used REAL,
  daily_used REAL,
  quota_period_start INTEGER,
  capture_succeeded INTEGER NOT NULL CHECK (capture_succeeded IN (0, 1)),
  calculation_status TEXT NOT NULL,
  scheduled_at INTEGER NOT NULL,
  captured_at INTEGER,
  delayed INTEGER NOT NULL DEFAULT 0 CHECK (delayed IN (0, 1)),
  PRIMARY KEY (account_id, usage_date)
);
CREATE INDEX daily_usage_snapshots_date_idx
  ON daily_usage_snapshots(usage_date, account_id);
```

字段含义：

- `usage_date`：该次边界快照所属的北京时间日期，格式为 `YYYY-MM-DD`。
- `cumulative_used`：Packy 返回的累计已用金额；查询失败时为空。
- `daily_used`：依据本次和上次边界快照计算出的每日用量；无法可靠计算时为空。
- `quota_period_start`：用于识别月度额度周期切换。
- `capture_succeeded`：本次计划查询是否成功。
- `calculation_status`：`pending`、`complete`、`missing_previous`、`capture_failed` 或 `reset_adjusted`。
- `scheduled_at`：该统计日期计划执行的 `23:00` Unix 时间。
- `captured_at`：实际查询结束时间。
- `delayed`：是否为服务在当日 `23:00` 后启动时执行的延迟采集。

采集前先用 `INSERT OR IGNORE` 写入 `pending` 占位，只有成功插入占位的执行者才能访问上游。主键因此既是幂等约束，也是每日查询权的唯一声明，保证同一账号同一统计日期不会重复自动查询或覆盖既有正式结果。查询结束后再更新占位行；进程若在查询期间退出，遗留的 `pending` 行在下次启动时直接标记为 `capture_failed`，不再次访问上游。删除账号时由外键级联删除其每日历史。

## 每日用量计算

某账号在统计日期 `D` 查询成功后读取日期 `D-1` 的快照：

1. 两次采集均成功、额度周期相同且累计值未下降：`daily_used = current - previous`，状态为 `complete`。
2. 本次成功但没有上次成功快照：`daily_used = NULL`，状态为 `missing_previous`。
3. 本次查询失败：累计值和每日用量均为空，状态为 `capture_failed`。
4. 额度周期发生变化或累计值下降：`daily_used = current`，状态为 `reset_adjusted`，避免负数。

金额继续沿用现有换算和六位小数精度。接口与页面显示时使用现有货币格式化规则。

`reset_adjusted` 表示新额度周期从重置点到当日 `23:00` 的累计用量。由于每天只允许一次查询，它不能包含重置前最后一个边界小时内的消费；数据库保留状态以明确这一限制，不把结果伪装成普通完整差值。

## 调度与重启

服务启动时计算下一次北京时间 `23:00`，只设置一个长定时器；一轮完成后再计算下一次时间，不使用固定 24 小时间隔，避免夏令时或系统时间变化造成漂移。

- 启动时间早于当日 `23:00`：等待当日边界。
- 启动时间晚于当日 `23:00`：立即执行当日采集轮次并标记 `delayed=1`；已有记录的账号直接跳过，只查询当日尚无占位的账号，完成后当天不再执行第二轮。
- 启动时间早于当日 `23:00` 但上一日缺失：不补查上一日，避免同一自然日增加两轮自动请求；缺失日保持不可计算。
- 多次触发或并发调用复用同一轮任务。数据库主键和采集前存在性检查共同保证幂等。
- 应用关闭时清理定时器，避免测试或优雅停机残留任务。

每日采集遍历全部已登记账号，不限于加入排行榜的账号。账号之间沿用现有逐个请求的间隔；某账号超时或失败后写入失败记录并继续下一个账号。

## 私有接口

`GET /api/me` 为每个当前会话可见账号增加：

```json
{
  "yesterdayUsed": 12.345678,
  "yesterdayUsageStatus": "complete"
}
```

服务端按请求时的北京时间计算昨日日期，只返回该日期的记录。无记录、采集失败或缺少前一日边界时，`yesterdayUsed` 为 `null`。`reset_adjusted` 可以返回非空金额，并通过状态保留其含义。

这些字段只加入受 Cookie 会话保护的 `/api/me`。`/api/leaderboard` 保持现有最小公开字段，不增加每日用量、账号 ID 或历史记录。

## 页面表现

`/my` 的账号指标区调整为四项：

1. 已用金额
2. 昨日用量
3. 剩余额度
4. 总额度

桌面端四列并排，手机端两列两行。“昨日用量”有有效数值时按 USD 金额显示；为 `null` 时显示 `—`。不新增说明卡片、弹窗或公开历史页面。

## 异常与安全

- 上游查询失败只影响对应账号，不终止整轮采集。
- 查询失败不自动重试，满足每账号每日最多一次计划查询。
- 只保存用量数字、周期和时间，不复制 Key、IP、Cookie 或会话信息。
- 每日数据通过账号外键关联，私有接口继续执行会话账号过滤。
- 数据库迁移在事务中执行；发现高于版本 `4` 的数据库继续拒绝启动。
- 部署前同时备份 `data/` 和 `secrets/master.key`，不覆盖 NAS 的 `compose.yaml`、`data/`、`secrets/` 或 Cloudflare 配置。

## 测试

测试至少覆盖：

- 版本 `3` 数据库无损迁移到版本 `4`。
- 北京时间下一次 `23:00` 的计算，包括边界前后。
- 每个账号每个统计日期最多一次自动查询。
- 全账号顺序采集，单账号失败后继续。
- 普通差值、缺少前日、查询失败和周期重置四种计算状态。
- 服务在当日 `23:00` 后启动的单次延迟采集，以及不补查更早日期。
- 重启和并发触发不会重复写入或重复请求。
- `/api/me` 只返回当前会话账号的昨日用量。
- 公共排行榜响应不包含每日用量字段。
- `/my` 桌面四列、手机两列布局，空值显示 `—`。

## 部署与验证

实现通过测试后提交并推送 GitHub。NAS 先创建带时间戳的完整备份，再同步代码并重建 `packy-usage` 容器。验证数据库版本、每日表结构、容器健康、公网 `/my` 与 `/leaderboard`，并确认 `packyapi-cloudflared` 保持运行。
