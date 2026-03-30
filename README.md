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
- `http://127.0.0.1:8080/models/view`
- `http://127.0.0.1:8080/ml/status`

文档：

- `docs/部署说明.md`
- `docs/FluentBit真机接入说明.md`
- `docs/部署前检查说明.md`
- `docs/使用说明.md`
- `docs/模型训练与调优说明.md`
- `docs/通知管理说明.md`
- `docs/排障说明.md`
- `docs/场景测试说明.md`
- `docs/联动设备调试清单.md`
- `docs/稳定性测试说明.md`
- `docs/误伤与回滚测试说明.md`
- `docs/真机联调验收说明.md`
- `docs/树莓派运行检查说明.md`
- `docs/树莓派上线手册.md`

## 样例流水线测试

```powershell
python scripts\process_suricata_file.py tests\samples\suricata_eve.jsonl
python scripts\process_suricata_file.py tests\samples\suricata_eve.jsonl --apply-policy --run-probe
python scripts\run_pipeline_service.py --source suricata --file tests\samples\suricata_eve.jsonl --mode existing
python scripts\run_pipeline_service.py --source auth.log --file tests\samples\auth.log --mode existing --no-policy --no-probe
Get-Content tests\samples\fluentbit_syslog.jsonl | python scripts\run_fluentbit_stdin.py --no-policy --no-probe
python scripts\create_demo_models.py
python scripts\train_models.py tests\samples\training_features.csv --out-dir models\trained --register --version sample-v1
python scripts\import_model.py anomaly models\anomaly_model.pkl --version demo-anomaly
python scripts\check_executor.py --test-ip 203.0.113.200 --ttl 60
bash scripts/bootstrap_rpi.sh
bash scripts/install_systemd.sh
bash scripts/status.sh
bash scripts/install_fluentbit_rpi.sh
bash scripts/verify_rpi_services.sh
python scripts\preflight_check.py
python scripts\check_fluentbit_bridge.py
python scripts\collect_runtime_report.py
bash scripts/start_fluentbit_bridge.sh
python scripts\release_expired_blocks.py
python scripts\run_scenario_tests.py
python scripts\run_false_positive_check.py
python scripts\run_stability_check.py --iterations 10
python -m unittest tests\test_suricata_pipeline.py
python -m unittest tests\test_policy_and_probe.py
python -m unittest tests\test_system_pipeline.py
python -m unittest tests\test_system_parser_extended.py
python -m unittest tests\test_policy_service.py
python -m unittest tests\test_baseline.py
python -m unittest tests\test_ml_engine.py
python -m unittest tests\test_model_manager.py
python -m unittest tests\test_notifier.py
python -m unittest tests\test_fluentbit_input.py
python -m unittest tests\test_risk_scoring_weights.py
python -m unittest tests\test_pipeline_integration.py
python -m unittest tests\test_training_pipeline.py
python -m unittest tests\test_scenario_runner.py
python -m unittest tests\test_false_positive_check.py
python -m unittest tests\test_stability_runner.py
python -m unittest tests\test_preflight.py
python -m unittest tests\test_runtime_checks.py
```

## 目录说明

```text
app/         应用代码
config/      配置文件
data/        SQLite 和原始数据
docs/        项目文档
logs/        运行日志
models/      模型文件
scripts/     初始化、运维和辅助脚本
systemd/     Web、流水线、定时任务服务文件
templates/   页面模板
tests/       测试
```
"# pi-guard-lite" 
