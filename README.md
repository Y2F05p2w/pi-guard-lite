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

## 目录说明

```text
app/         应用代码
config/      配置文件
data/        SQLite 和原始数据
docs/        项目文档
logs/        运行日志
models/      模型文件
scripts/     初始化和辅助脚本
systemd/     服务文件
templates/   页面模板
tests/       测试
```
"# pi-guard-lite" 
