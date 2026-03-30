# Pi-Guard Lite

轻量单节点树莓派智能防御系统。

## 当前已落地内容

- 项目目录骨架
- FastAPI 最小服务
- SQLite 初始化脚本
- 配置文件模板
- systemd 服务模板
- 开发状态文档
- 开发规范文档

## 本地运行

```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

访问：

- `http://127.0.0.1:8080/`
- `http://127.0.0.1:8080/health`
- `http://127.0.0.1:8080/events/view`
- `http://127.0.0.1:8080/policies/view`
- `http://127.0.0.1:8080/blocklist/view`
- `http://127.0.0.1:8080/probes/view`
- `http://127.0.0.1:8080/manual/view`
- `http://127.0.0.1:8080/ml/status`

## 样例流水线测试

```powershell
python scripts\process_suricata_file.py tests\samples\suricata_eve.jsonl
python scripts\process_suricata_file.py tests\samples\suricata_eve.jsonl --apply-policy --run-probe
python scripts\run_pipeline_service.py --source suricata --file tests\samples\suricata_eve.jsonl --mode existing
python scripts\run_pipeline_service.py --source auth.log --file tests\samples\auth.log --mode existing --no-policy --no-probe
python scripts\create_demo_models.py
python scripts\release_expired_blocks.py
python -m unittest tests\test_suricata_pipeline.py
python -m unittest tests\test_policy_and_probe.py
python -m unittest tests\test_system_pipeline.py
python -m unittest tests\test_system_parser_extended.py
python -m unittest tests\test_policy_service.py
python -m unittest tests\test_baseline.py
python -m unittest tests\test_ml_engine.py
```

## 目录说明

```text
app/         应用代码
config/      配置文件
data/        SQLite 和原始数据
docs/        项目文档
logs/        运行日志
models/      模型文件
scripts/     初始化和辅助脚本
systemd/     Web 与流水线服务文件
templates/   页面模板
tests/       测试
```
"# pi-guard-lite" 
