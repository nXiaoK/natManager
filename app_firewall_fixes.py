# 以下是修复后的check_and_clear_firewall函数
def check_and_clear_firewall():
    flag_exists = os.path.exists(access_flag_file)
    
    # 创建启动日志
    with open('/tmp/natmanager_startup.log', 'a') as f:
        f.write(f"NAT Manager 启动检查于 {datetime.datetime.now()}\n")
        f.write(f"限制文件存在: {'是' if flag_exists else '否'}\n")
    
    # 如果标记文件不存在，清理防火墙规则
    if not flag_exists:
        with open('/tmp/natmanager_startup.log', 'a') as f:
            f.write("未检测到访问限制标记文件，尝试移除防火墙限制规则...\n")
        
        try:
            # 检查并移除DROP规则
            check_cmd = "sudo iptables -C INPUT -p tcp --dport 5000 -j DROP 2>/dev/null"
            if os.system(check_cmd) == 0:  # 返回0表示规则存在
                os.system("sudo iptables -D INPUT -p tcp --dport 5000 -j DROP")
                with open('/tmp/natmanager_startup.log', 'a') as f:
                    f.write("已删除端口5000的DROP规则\n")
            else:
                with open('/tmp/natmanager_startup.log', 'a') as f:
                    f.write("端口5000的DROP规则不存在，无需删除\n")
            
            os.system("sudo sh -c 'iptables-save > /etc/iptables/rules.v4'")
            
            # 更新数据库配置
            with app.app_context():
                try:
                    config = SystemConfig.query.first()
                    if config and not config.allow_public_access:
                        config.allow_public_access = True
                        config.last_modified = datetime.datetime.now()
                        db.session.commit()
                        with open('/tmp/natmanager_startup.log', 'a') as f:
                            f.write("已更新数据库配置为允许公网访问\n")
                except Exception as e:
                    with open('/tmp/natmanager_startup.log', 'a') as f:
                        f.write(f"更新数据库配置出错: {str(e)}\n")
        
        except Exception as e:
            with open('/tmp/natmanager_startup.log', 'a') as f:
                f.write(f"移除防火墙规则时出错: {str(e)}\n")

# 以下是修复后的cleanup_on_exit函数
def cleanup_on_exit():
    with open('/tmp/natmanager_exit.log', 'w') as f:
        f.write(f"应用退出于 {datetime.datetime.now()}\n")
        f.write("检查防火墙规则状态\n")
        
        # 检查标记文件和当前防火墙规则
        flag_exists = os.path.exists(access_flag_file)
        f.write(f"标记文件存在: {'是' if flag_exists else '否'}\n")
        
        if not flag_exists:
            # 检查并清除防火墙规则
            check_cmd = "sudo iptables -C INPUT -p tcp --dport 5000 -j DROP 2>/dev/null"
            if os.system(check_cmd) == 0:  # 返回0表示规则存在
                os.system("sudo iptables -D INPUT -p tcp --dport 5000 -j DROP 2>/dev/null")
                f.write("已删除端口5000的DROP规则\n")
            else:
                f.write("端口5000的DROP规则不存在，无需删除\n")
            
            os.system("sudo sh -c 'iptables-save > /etc/iptables/rules.v4' 2>/dev/null")
            f.write("防火墙规则已保存\n")

# 以下是修复后的settings路由中处理防火墙规则的部分

# 允许公网访问部分：
try:
    print("允许公网访问 - 清除防火墙DROP规则")
    # 检查并移除DROP规则
    check_cmd = "sudo iptables -C INPUT -p tcp --dport 5000 -j DROP 2>/dev/null"
    if os.system(check_cmd) == 0:  # 返回0表示规则存在
        os.system("sudo iptables -D INPUT -p tcp --dport 5000 -j DROP")
        with open('/tmp/natmanager_startup.log', 'a') as f2:
            f2.write("已删除端口5000的DROP规则\n")
    else:
        with open('/tmp/natmanager_startup.log', 'a') as f2:
            f2.write("端口5000的DROP规则不存在，无需删除\n")
    
    os.system("sudo sh -c 'iptables-save > /etc/iptables/rules.v4'")
    flash('已允许公网访问！防火墙规则已更新。', 'success')

# 禁止公网访问部分：
try:
    print("禁止公网访问 - 添加防火墙DROP规则")
    # 添加本地和局域网访问规则
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    # 确保本地访问规则存在（先检查是否存在再删除）
    check_cmd_local = "sudo iptables -C INPUT -p tcp --dport 5000 -s 127.0.0.1 -j ACCEPT 2>/dev/null"
    if os.system(check_cmd_local) == 0:
        os.system("sudo iptables -D INPUT -p tcp --dport 5000 -s 127.0.0.1 -j ACCEPT")
    os.system("sudo iptables -I INPUT 1 -p tcp --dport 5000 -s 127.0.0.1 -j ACCEPT")
    
    # 确保局域网访问规则存在（先检查是否存在再删除）
    if local_ip and local_ip != '127.0.0.1':
        network_prefix = '.'.join(local_ip.split('.')[:3]) + '.0/24'
        check_cmd_lan = f"sudo iptables -C INPUT -p tcp --dport 5000 -s {network_prefix} -j ACCEPT 2>/dev/null"
        if os.system(check_cmd_lan) == 0:
            os.system(f"sudo iptables -D INPUT -p tcp --dport 5000 -s {network_prefix} -j ACCEPT")
        os.system(f"sudo iptables -I INPUT 2 -p tcp --dport 5000 -s {network_prefix} -j ACCEPT")
    
    # 添加DROP规则（先检查是否存在再删除）
    check_cmd_drop = "sudo iptables -C INPUT -p tcp --dport 5000 -j DROP 2>/dev/null"
    if os.system(check_cmd_drop) == 0:
        os.system("sudo iptables -D INPUT -p tcp --dport 5000 -j DROP")
    os.system("sudo iptables -A INPUT -p tcp --dport 5000 -j DROP") 