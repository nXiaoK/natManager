#!/bin/bash

# 定义变量
APP_DIR="/root/natManager-main"
FLAG_FILE="$APP_DIR/public_access.flag"
SQLITE_DB="$APP_DIR/nat_rules.db"
LOG_FILE="/tmp/natmanager_start.log"

# 记录启动信息
echo "启动NAT Manager服务于 $(date)" > $LOG_FILE

# 检查标记文件
if [ ! -f "$FLAG_FILE" ]; then
    echo "检测到标记文件不存在，尝试移除防火墙限制规则..." >> $LOG_FILE
    
    # 移除防火墙DROP规则（先检查规则是否存在）
    if sudo iptables -C INPUT -p tcp --dport 5000 -j DROP 2>/dev/null; then
        sudo iptables -D INPUT -p tcp --dport 5000 -j DROP 2>/dev/null
        echo "已删除端口5000的DROP规则" >> $LOG_FILE
    else
        echo "端口5000的DROP规则不存在，无需删除" >> $LOG_FILE
    fi
    
    # 保存防火墙规则
    sudo sh -c 'iptables-save > /etc/iptables/rules.v4' 2>/dev/null
    
    # 显示当前规则
    echo "当前防火墙规则:" >> $LOG_FILE
    sudo iptables -L INPUT -n | grep 5000 >> $LOG_FILE
    
    # 如果sqlite3命令存在，更新数据库配置
    if command -v sqlite3 &> /dev/null && [ -f "$SQLITE_DB" ]; then
        echo "更新数据库配置..." >> $LOG_FILE
        sqlite3 "$SQLITE_DB" "UPDATE system_config SET allow_public_access=1, last_modified=datetime('now');" 2>>$LOG_FILE
        echo "数据库配置已更新" >> $LOG_FILE
    else
        echo "无法更新数据库：sqlite3命令不存在或数据库文件不存在" >> $LOG_FILE
    fi
else
    echo "标记文件存在，保持当前防火墙设置" >> $LOG_FILE
fi

# 启动gunicorn
cd $APP_DIR
echo "启动gunicorn..." >> $LOG_FILE
exec /root/natManager-main/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app 