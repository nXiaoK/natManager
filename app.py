from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
import subprocess
import re
from flask_sqlalchemy import SQLAlchemy
import ipaddress
app = Flask(__name__)
app.secret_key = 'fyvKab$*u7L0pn0'  # 请替换为您的实际密钥



#net.ipv6.conf.all.forwarding=1 # 在 /etc/sysctl.conf 中添加
#sudo sysctl -p #应用配置
# sudo modprobe ip6table_nat  #加载必要的内核模块：确保 ip6table_nat 模块已加载。



# 配置数据库
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nat_rules.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class NatRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    protocol = db.Column(db.String(10), default='tcp')
    dport = db.Column(db.String(10), nullable=False)
    to_ip = db.Column(db.String(39), nullable=False)  # IPv6 地址可能更长
    to_port = db.Column(db.String(10), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    ip_version = db.Column(db.Integer, default=4)  # 新增字段，默认值为 4

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500
# 定义用户类
class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.username = 'admin'
        self.password = 'password'

    def get_id(self):
        return self.id

# 用户加载回调
@login_manager.user_loader
def load_user(user_id):
    if user_id == '1':
        return User(id='1')
    return None

# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin':
            user = User(id='1')
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='用户名或密码错误')
    return render_template('login.html')

# 登出路由
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    rules = NatRule.query.all()
    return render_template('index.html', rules=rules)
# 获取当前 NAT 转发规则
def get_nat_rules(ip_version=4):
    if ip_version == 4:
        iptables_cmd = 'iptables'
    else:
        iptables_cmd = 'ip6tables'

    result = subprocess.check_output(['sudo', iptables_cmd, '-t', 'nat', '-L', 'PREROUTING', '-n', '-v', '--line-numbers'])
    rules = parse_iptables_output(result.decode('utf-8'))
    return rules

# 解析 iptables 输出
def parse_iptables_output(output):
    lines = output.strip().split('\n')
    rules = []
    for line in lines[2:]:  # 跳过前两行标题
        if not line.strip():
            continue  # 跳过空行
        parts = line.split()
        if len(parts) >= 11:
            rule = {
                'num': parts[0],
                'pkts': parts[1],
                'bytes': parts[2],
                'target': parts[3],
                'prot': parts[4],
                'opt': parts[5],
                'in': parts[6],
                'out': parts[7],
                'source': parts[8],
                'destination': parts[9],
                'options': parts[10:]
            }
            # 提取 dpt 和 to-destination
            dpt = ''
            to_destination = ''
            for item in rule['options']:
                if item.startswith('dpt:'):
                    dpt = item.split(':', 1)[1]
                elif item.startswith('to:'):
                    to_destination = item.split(':', 1)[1]
            rule['dpt'] = dpt
            rule['to'] = to_destination
            rules.append(rule)
    return rules


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_rule():
    if request.method == 'POST':
        ip_version = int(request.form['ip_version'])
        protocol = request.form['protocol']
        dport = request.form['dport']
        to_ip = request.form['to_ip']
        to_port = request.form['to_port']
        enabled = 'enabled' in request.form  # 获取启用状态

        # 输入验证
        if not dport.isdigit() or not to_port.isdigit():
            flash('端口号必须是数字！', 'danger')
            return redirect(url_for('add_rule'))
        if ip_version not in (4, 6):
            flash('无效的 IP 版本！', 'danger')
            return redirect(url_for('add_rule'))
       # 验证 IP 地址格式
        try:
            if ip_version == 4:
                ipaddress.IPv4Address(to_ip)
            elif ip_version == 6:
                ipaddress.IPv6Address(to_ip)
            else:
                raise ValueError("无效的 IP 版本")
        except ipaddress.AddressValueError:
            flash('目标 IP 格式不正确！', 'danger')
            return redirect(url_for('add_rule'))
        except ValueError as ve:
            flash(str(ve), 'danger')
            return redirect(url_for('add_rule'))

        # 创建规则对象
        rule = NatRule(
            ip_version=ip_version,
            protocol=protocol,
            dport=dport,
            to_ip=to_ip,
            to_port=to_port,
            enabled=enabled
        )
        db.session.add(rule)
        db.session.commit()

        # 如果启用，则添加到 iptables/ip6tables
        if rule.enabled:
            add_rule_to_iptables(rule)

        flash('规则添加成功！', 'success')
        return redirect(url_for('index'))
    return render_template('add.html')

@app.route('/delete/<int:id>')
@login_required
def delete_rule(id):
    rule = NatRule.query.get_or_404(id)

    # 从 iptables/ip6tables 中删除规则
    if rule.enabled:
        delete_rule_from_iptables(rule)

    # 从数据库中删除记录
    db.session.delete(rule)
    db.session.commit()

    flash('规则删除成功！', 'success')
    return redirect(url_for('index'))

@app.route('/modify/<int:id>', methods=['GET', 'POST'])
@login_required
def modify_rule(id):
    rule = NatRule.query.get_or_404(id)
    if request.method == 'POST':
        ip_version = int(request.form['ip_version'])
        protocol = request.form['protocol']
        dport = request.form['dport']
        to_ip = request.form['to_ip']
        to_port = request.form['to_port']
        enabled = 'enabled' in request.form  # 获取启用状态

        # 输入验证
        if not dport.isdigit() or not to_port.isdigit():
            flash('端口号必须是数字！', 'danger')
            return redirect(url_for('modify_rule', id=id))
        if ip_version not in (4, 6):
            flash('无效的 IP 版本！', 'danger')
            return redirect(url_for('add_rule'))
        # 验证 IP 地址格式
        try:
            if ip_version == 4:
                ipaddress.IPv4Address(to_ip)
            elif ip_version == 6:
                ipaddress.IPv6Address(to_ip)
            else:
                raise ValueError("无效的 IP 版本")
        except ipaddress.AddressValueError:
            flash('目标 IP 格式不正确！', 'danger')
            return redirect(url_for('modify_rule', id=id))
        except ValueError as ve:
            flash(str(ve), 'danger')
            return redirect(url_for('modify_rule', id=id))

        # 如果规则已启用，且参数发生变化，则从 iptables/ip6tables 中删除旧规则
        if rule.enabled:
            delete_rule_from_iptables(rule)

        # 更新规则
        rule.ip_version = ip_version
        rule.protocol = protocol
        rule.dport = dport
        rule.to_ip = to_ip
        rule.to_port = to_port
        rule.enabled = enabled
        db.session.commit()

        # 如果启用，则添加新规则到 iptables/ip6tables
        if rule.enabled:
            add_rule_to_iptables(rule)

        flash('规则修改成功！', 'success')
        return redirect(url_for('index'))
    return render_template('modify.html', rule=rule)
#启用和停用规则
@app.route('/toggle/<int:id>')
@login_required
def toggle_rule(id):
    rule = NatRule.query.get_or_404(id)
    if rule.enabled:
        # 从 iptables/ip6tables 中删除规则
        delete_rule_from_iptables(rule)
        rule.enabled = False
    else:
        # 添加规则到 iptables/ip6tables
        add_rule_to_iptables(rule)
        rule.enabled = True
    db.session.commit()
    flash('规则状态已更新！', 'success')
    return redirect(url_for('index'))
# 实现添加和删除 iptables 规则的函数
def add_rule_to_iptables(rule):
    if rule.ip_version == 4:
        iptables_cmd = 'iptables'
    else:
        iptables_cmd = 'ip6tables'

    cmd = [
        'sudo', iptables_cmd, '-t', 'nat', '-A', 'PREROUTING',
        '-p', rule.protocol, '--dport', rule.dport,
        '-j', 'DNAT', '--to-destination', f'{rule.to_ip}:{rule.to_port}'
    ]
    subprocess.call(cmd)
    subprocess.call(['sudo', iptables_cmd + '-save', '-f', f'/etc/iptables/rules.v{rule.ip_version}'])

def delete_rule_from_iptables(rule):
    if rule.ip_version == 4:
        iptables_cmd = 'iptables'
    else:
        iptables_cmd = 'ip6tables'

    cmd = [
        'sudo', iptables_cmd, '-t', 'nat', '-D', 'PREROUTING',
        '-p', rule.protocol, '--dport', rule.dport,
        '-j', 'DNAT', '--to-destination', f'{rule.to_ip}:{rule.to_port}'
    ]
    subprocess.call(cmd)
    subprocess.call(['sudo', iptables_cmd + '-save', '-f', f'/etc/iptables/rules.v{rule.ip_version}'])

# def sync_rules():
#     # 清空当前的 iptables 规则
#     subprocess.call(['sudo', 'iptables', '-t', 'nat', '-F', 'PREROUTING'])
#     # 添加启用的规则
#     enabled_rules = NatRule.query.filter_by(enabled=True).all()
#     for rule in enabled_rules:
#         add_rule_to_iptables(rule)


def sync_rules():
    # 检查数据库中是否已有规则
    rule_count = NatRule.query.count()
    if rule_count == 0:
        # 数据库为空，第一次启动
        # 获取当前 iptables 和 ip6tables 规则
        iptables_rules = get_nat_rules(ip_version=4)
        ip6tables_rules = get_nat_rules(ip_version=6)

        # 处理 iptables 规则
        for ipt_rule in iptables_rules:
            # 同之前的方法，解析并存入数据库
            # 设置 ip_version=4
            save_rule_to_db(ipt_rule, ip_version=4)

        # 处理 ip6tables 规则
        for ipt_rule in ip6tables_rules:
            # 同之前的方法，解析并存入数据库
            # 设置 ip_version=6
            save_rule_to_db(ipt_rule, ip_version=6)

        db.session.commit()
    else:
        # 非第一次启动
        # 清空当前的 iptables 和 ip6tables 规则
        subprocess.call(['sudo', 'iptables', '-t', 'nat', '-F', 'PREROUTING'])
        subprocess.call(['sudo', 'ip6tables', '-t', 'nat', '-F', 'PREROUTING'])
        # 添加启用的规则
        enabled_rules = NatRule.query.filter_by(enabled=True).all()
        for rule in enabled_rules:
            add_rule_to_iptables(rule)
def save_rule_to_db(ipt_rule, ip_version):
    protocol = ipt_rule.get('prot', 'tcp').lower()
    dport = ipt_rule.get('dpt', '')
    to_ip_port = ipt_rule.get('to', '')
    if not dport or not to_ip_port:
        return  # 跳过无法解析的规则

    if ':' in to_ip_port:
        to_ip, to_port = to_ip_port.rsplit(':', 1)
    else:
        to_ip = to_ip_port
        to_port = ''  # 或者设置为默认值

    # 创建 NatRule 对象
    rule = NatRule(
        ip_version=ip_version,
        protocol=protocol,
        dport=dport,
        to_ip=to_ip,
        to_port=to_port,
        enabled=True  # 现有的规则默认为启用状态
    )
    db.session.add(rule)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        sync_rules()
    app.run(host='0.0.0.0', port=5000)