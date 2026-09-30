# 代码开发

统一的本地代码开发目录，使用 Git 做版本管理（纯本地、离线，不上传）。

## 约定
- 每个项目一个独立子文件夹。
- 提交前确认 `.gitignore` 已忽略打包产物、虚拟环境和大文件。
- 一个能正常运行的版本完成后再提交（commit），写清楚改了什么。

## 常用命令
```powershell
git status                 # 查看当前改动
git add .                  # 暂存全部改动
git commit -m "说明"        # 提交一个版本
git log --oneline          # 查看历史版本
git checkout -- .          # 撤销未提交的改动
```
