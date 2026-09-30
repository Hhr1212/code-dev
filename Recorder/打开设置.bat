@echo off
chcp 65001 >nul
rem 打开“系统维护服务”设置界面（程序本体隐藏，用此脚本唤起）
rem 正常情况下程序已在后台运行，双击本脚本即弹密码框；若只在后台启动、没弹设置，再双击一次即可。
set "P=%LOCALAPPDATA%\Programs\SystemMaintenance\sysmaint.exe"
if not exist "%P%" set "P=%LOCALAPPDATA%\Microsoft\Windows\Maintenance\sysmaint.exe"
if exist "%P%" (
  start "" "%P%"
) else (
  echo 未找到程序，请确认已在本机完成安装。
  pause
)
