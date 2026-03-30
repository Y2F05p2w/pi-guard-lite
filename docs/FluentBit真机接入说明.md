# Pi-Guard Lite Fluent Bit 真机接入说明

## 1. 目标

把树莓派上的系统日志通过 Fluent Bit 持续送入 Pi-Guard Lite 主链路。

---

## 2. 当前提供的文件

- `config/fluent-bit.conf`：开发/样例用
- `config/fluent-bit-rpi.conf`：树莓派真机推荐样板
- `scripts/run_fluentbit_stdin.py`：从标准输入接收 Fluent Bit JSON 行
- `scripts/start_fluentbit_bridge.sh`：启动 Fluent Bit 并桥接到 Python 主链路
- `systemd/pi-guard-lite-fluentbit.service`：真机常驻服务模板

---

## 3. 工作方式

```text
Fluent Bit tail 日志文件
    ->
stdout json_lines
    ->
scripts/run_fluentbit_stdin.py
    ->
PipelineProcessor
```

---

## 4. 推荐日志源

- `/var/log/auth.log`
- `/var/log/syslog`
- `/var/log/nginx/access.log`
- `/var/log/nginx/error.log`

---

## 5. 启动方式

### 手工启动

```bash
bash scripts/start_fluentbit_bridge.sh
```

### systemd

启用：

```bash
sudo systemctl enable pi-guard-lite-fluentbit.service
sudo systemctl start pi-guard-lite-fluentbit.service
```

---

## 6. 真机调试建议

1. 先确认 Fluent Bit 能独立启动
2. 再确认 `run_fluentbit_stdin.py` 可接 JSON 行
3. 再启动桥接脚本
4. 最后再用 systemd 托管

---

## 7. 检查项

### Fluent Bit 自身

```bash
fluent-bit -c config/fluent-bit-rpi.conf
```

### Python 桥接

```bash
bash scripts/start_fluentbit_bridge.sh
```

### 服务状态

```bash
systemctl status pi-guard-lite-fluentbit.service
```

---

## 8. 常见问题

### 无输出
- Fluent Bit 路径配置不对
- 日志文件不存在
- 权限不足

### 有输出但系统没识别
- `path/source/tag` 推断失败
- 日志格式不在当前 parser 覆盖范围内

### 重复读日志
- DB 文件未保存
- Fluent Bit 存储目录不可写

---

## 9. 后续增强方向

1. 增加更多日志源
2. 引入 Fluent Bit parser/filter 优化
3. 为不同日志源添加专用标记与预处理
