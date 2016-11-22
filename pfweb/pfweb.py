import pf
import socket
import platform, subprocess, time
from datetime import timedelta

from flask import Flask, render_template, redirect, url_for, request
import flask_login

from config import Config
from constants import *

# Get config settings
settings = Config()
settings.get_settings()

# Setup Flask
app = Flask(__name__)
app.secret_key = settings.secret_key

# Setup Login Manager extension
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

# Load packet filter to be used in views
packetfilter = pf.PacketFilter()

class BadRequestError(Exception):
    """HTTP 400"""

class User(flask_login.UserMixin):
    """Flask Login User Class"""

@login_manager.user_loader
def user_loader(username):
    """Flask Login User Loader"""

    if username != settings.username:
        return None

    user = User()
    user.id = username
    return user

@login_manager.unauthorized_handler
def unauthorized_handler():
    """Redirect to the login page when not authenticated"""
    return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    """Show login page and authenticate user"""

    # Initialize alert message
    message = None

    # Process form fields
    if request.method == 'POST':
        # Process user login
        if request.form.get('login.submitted'):
            username = request.form.get('username')
            if username == settings.username and settings.hash_password(request.form.get('password')) == settings.password:
                user = User()
                user.id = username
                flask_login.login_user(user)
                return redirect(url_for('dash'))
            else:
                message = "Bad username or password"

    if settings.username == None or settings.password == None:
        # Show error about no initial user. Should never actually happen
        message = "Initial user not yet created"
        return render_template('login.html', no_login=True, message=message)
    
    return render_template('login.html', message=message)

@app.route('/logout')
def logout():
    """Logout user and redirect to home"""

    flask_login.logout_user()
    return redirect(url_for('dash'))

@app.route("/")
@flask_login.login_required
def dash():
    """Show home dashboard"""

    # Get uptime
    uptime_seconds = int(subprocess.check_output(["/sbin/sysctl", "-n", "kern.boottime"]))
    uptime_delta = timedelta(seconds=(int(time.time()) - uptime_seconds))

    # Place info in a dict
    sys_info = {
        'hostname': socket.getfqdn(),
        'os': "{} {} ({})".format(platform.system(), platform.release(), platform.machine()),
        'uptime': str(uptime_delta),
        'current_time': time.strftime("%a, %b %d %Y %H:%M:%S %Z", time.localtime())
    }

    # Interfaces to skip for stats
    skip_ifaces = ['all', 'carp', 'egress', 'enc', 'enc0', 'lo', 'lo0', 'pflog', 'pflog0']
    # Type of stats to use
    stats = ['Rules', 'States', 'Packets In', 'Packets Out', 'Bytes In', 'Bytes Out']
    # Initialize the structures to hold the data
    if_stats = dict()
    if_info = list()

    # Start the table string for stats
    ifstats_output = "<thead><tr><th style='width: 120px;'></th>";

    # Go through each interface
    for iface in packetfilter.get_ifaces():
        if iface.name not in skip_ifaces:
            # Add up all the packet and bytes
            packets_in = iface.packets["in"][pf.PF_PASS][0] + iface.packets["in"][pf.PF_DROP][0] + iface.packets["in"][pf.PF_PASS][1] + iface.packets["in"][pf.PF_DROP][1]
            packets_out = iface.packets["out"][pf.PF_PASS][0] + iface.packets["out"][pf.PF_DROP][0] + iface.packets["out"][pf.PF_PASS][1] + iface.packets["out"][pf.PF_DROP][1]
            bytes_in = iface.bytes["in"][pf.PF_PASS][0] + iface.bytes["in"][pf.PF_DROP][0] + iface.bytes["in"][pf.PF_PASS][1] + iface.bytes["in"][pf.PF_DROP][1]
            bytes_out = iface.bytes["out"][pf.PF_PASS][0] + iface.bytes["out"][pf.PF_DROP][0] + iface.bytes["out"][pf.PF_PASS][1] + iface.bytes["out"][pf.PF_DROP][1]
            
            # Store each into a dict
            if_stats[iface.name] = {
                'name': iface.name,
                'Rules': iface.rules,
                'States': iface.states,
                'Packets In': packets_in,
                'Packets Out': packets_out,
                'Bytes In': sizeof_fmt(bytes_in),
                'Bytes Out': sizeof_fmt(bytes_out)
            }

            # Add interface header to table
            ifstats_output += "<th>{}</th>".format(iface.name)

            # Gather interface info from ifconfig and split into array of lines
            ifconfig = subprocess.check_output(["/sbin/ifconfig", str(iface.name)]).splitlines()
            # Initialize dict for interface info. Sets used on IPs so only shows uniques
            if_info_dict = {
                'ipv4': set(), 
                'ipv6': set(),
                'media': None, 
                'status': None,
                'name': iface.name
            }
            # Run through each line of ifconfig output
            for line in ifconfig:
                # Remove first tab and split line into fields of words
                line = line.replace('\t', '', 1).split(" ")
                if line[0] == 'inet':
                    # IPv4 addresses
                    if_info_dict['ipv4'].add(line[1])
                elif line[0] == 'inet6' and not line[1].startswith('fe80') and line[4] != 'deprecated':
                    # IPv6 addresses. Skip local and deprecated IPs
                    if_info_dict['ipv6'].add(line[1])
                elif line[0] == 'media:':
                    # Get speed and duplex
                    if_info_dict['media'] = "{} {}".format(line[3].strip("("), line[4].strip(")"))
                elif line[0] == 'status:':
                    # Show whether interface is up or down
                    if line[1] == 'active':
                        if_info_dict['status'] = True
                    else:
                        if_info_dict['status'] = False

            # Add info to overall list
            if_info.append(if_info_dict)

    # Continue to body in stats table
    ifstats_output += "</tr></thead><tbody>"
    for s in stats:
        # Add stat header in new row
        ifstats_output += "<tr><th>{}</th>".format(s)
        # Run through each interface and add their stats
        for iface in sorted(if_stats):
            ifstats_output += "<td>{}</td>".format(if_stats[iface][s])
        ifstats_output += "</tr>"

    ifstats_output += "</tbody>"

    return render_template('dash.html', sys_info=sys_info, if_stats=ifstats_output, if_info=if_info, logged_in=flask_login.current_user.get_id(), hometab='active')

@app.route("/firewall/rules", methods=['GET', 'POST'])
@flask_login.login_required
def rules():
    """Gather pf rules and show rules page"""

    # Remove rules
    if request.method == 'POST':
        if request.form['delete_rules'] == "true":
            # Create list of rules to remove
            remove_list = list()
            for item, value in request.form.iteritems():
                if item[:5] == 'rule_':
                    remove_list.append(int(value))
            
            # Remove each rule with the higher IDs first
            ruleset = packetfilter.get_ruleset()
            for value in sorted(remove_list, reverse=True):
                ruleset.remove(value)
            # Load edited ruleset
            packetfilter.load_ruleset(ruleset)
        return redirect(url_for('rules'), code=302)

    rules = get_rules(packetfilter)
    return render_template('rules.html', logged_in=flask_login.current_user.get_id(), fw_tab='active', rules=rules, port_ops=PFWEB_PORT_OPS)

@app.route("/firewall/rules/remove/<int:rule_id>")
@flask_login.login_required
def remove_rule(rule_id):
    """Remove a single rule"""
    ruleset = packetfilter.get_ruleset()
    ruleset.remove(rule_id)
    packetfilter.load_ruleset(ruleset)
    return redirect(url_for('rules'), code=302)

@app.route("/firewall/rules/edit/<int:rule_id>", methods=['GET', 'POST'])
@app.route("/firewall/rules/edit", methods=['GET', 'POST'])
@flask_login.login_required
def edit_rule(rule_id=None):
    """Edit a single rule"""

    # Save edit or new rule
    if request.method == 'POST':
        # Get all form items into simple dict
        fields = dict()
        for item, val in request.form.iteritems():
            fields[item] = val

        # Parse sure input into pf.PFRule object
        rule = translate_rule(packetfilter, id=rule_id, **fields)

        if not isinstance(rule, pf.PFRule):
            raise BadRequestError(rule)

        ruleset = packetfilter.get_ruleset()
        if rule_id or rule_id == 0:
            ruleset.remove(rule_id)
            ruleset.insert(rule_id, rule)
        else:
            ruleset.append(rule)

        packetfilter.load_ruleset(ruleset)
    
        # redirect to rules page
        return redirect(url_for('rules'), code=302)

    # Load existing or create new rule
    if rule_id or rule_id == 0:
        # Load the current ruleset and parse existing rule
        ruleset = packetfilter.get_ruleset()
        rule = get_rule(ruleset.rules[rule_id])
        # Set the ID
        rule['id'] = rule_id
    else:
        # Create new blank rule
        blank_rule = pf.PFRule()
        # Direction is in by default
        blank_rule.direction = pf.PF_IN
        # Use IPv4 by default
        blank_rule.af = socket.AF_INET
        # Enable keep_state by default
        blank_rule.keep_state = pf.PF_STATE_NORMAL
        rule = get_rule(blank_rule)

    tables = get_tables(packetfilter)

    return render_template('edit_rule.html', logged_in=flask_login.current_user.get_id(), fw_tab='active',
        rule=rule, tables=tables, ifaces=get_ifaces(packetfilter), 
        icmp_types=PFWEB_ICMP_TYPES, icmp6_types=PFWEB_ICMP6_TYPES, port_ops=PFWEB_PORT_OPS)

@app.route("/firewall/tables", methods=['GET', 'POST'])
@app.route("/firewall/tables/remove/<table_name>")
@flask_login.login_required
def tables(table_name=None):
    """
    Show existing pf tables

    Removes tables when form is submitted
    """

    remove_error = list()
    # Remove multiple tables
    if request.method == 'POST':
        print request.form
        if 'delete_tables' in request.form and request.form['delete_tables'] == "true":
            # Create list of tables to remove
            remove_list = list()
            for t in packetfilter.get_tables():
                if 'table_' + t.name in request.form and request.form['table_' + t.name] == t.name:
                    if table_in_use(packetfilter, t.name):
                        remove_error.append(t.name)
                    else:
                        remove_list.append(t)

            if len(remove_error) == 0:
                packetfilter.del_tables(*remove_list)
                return redirect(url_for('tables'), code=302)
                
    tables = get_tables(packetfilter)
    return render_template('tables.html', logged_in=flask_login.current_user.get_id(), fw_tab='active', tables=tables, remove_error=remove_error)

@app.route("/firewall/tables/edit/<table_name>", methods=['GET', 'POST'])
@app.route("/firewall/tables/edit", methods=['GET', 'POST'])
@flask_login.login_required
def edit_table(table_name=None):
    """Edit a table"""

    # Save edit or new table
    if request.method == 'POST':
        table_addrs = translate_table(request.form)

        if not isinstance(table_addrs, list):
            raise BadRequestError(table)

        if table_name:
            packetfilter.set_addrs(table_name, *table_addrs)
        else:
            packetfilter.add_tables(pf.PFTable(request.form['name'], *table_addrs, flags=pf.PFR_TFLAG_PERSIST))

        return redirect(url_for('tables'), code=302)

    # Load existing or create new rule
    if table_name:
        # Load the current tableset and parse existing table
        tables = packetfilter.get_tables()
        for t in tables:
            if str(t.name) == str(table_name):
                table = get_table(t)
                break
        else:
            raise BadRequestError("No such table")
    else:
        # Create new blank table
        blank_table = pf.PFTable()
        table = get_table(blank_table)

    return render_template('edit_table.html', logged_in=flask_login.current_user.get_id(), fw_tab='active',
        table=table)

@app.errorhandler(BadRequestError)
@flask_login.login_required
def bad_request(error):
    """Show HTTP 400 page when BadRequestError is raised"""
    return render_template('error.html', msg=error.message), 400

def get_rules(pfilter):
    """Return list of rules for template"""
    web_rules = list()
    ruleset = pfilter.get_ruleset()
    count = 0
    
    # Parse each rule into human readable values
    for rule in ruleset.rules:
        #print rule
        new = get_rule(rule)

        new['id'] = count

        web_rules.append(new)
        count += 1
    return web_rules

def get_rule(rule):
    """Gather rule information into a data structure for rendering to a template"""
    new = dict()

    # Rule Action
    if rule.action == pf.PF_PASS:
        new['action'] = "pass"
    elif rule.action == pf.PF_DROP:
        block_return = rule.rule_flag & pf.PFRULE_RETURN
        if block_return:
            new['action'] = "reject"
        else:
            new['action'] = "block"
    else:
        new['action'] = "else"

    # Direction
    if rule.direction == pf.PF_IN:
        new['direction'] = "in"
    elif rule.direction == pf.PF_OUT:
        new['direction'] = "out"
    elif rule.direction == pf.PF_INOUT:
        new['direction'] = "both"

    # Interface
    if rule.ifname:
        new['iface'] = rule.ifname
    else:
        new['iface'] = "All"

    # AF Protocol
    if rule.af == socket.AF_INET:
        new['af'] = "IPv4"
    elif rule.af == socket.AF_INET6:
        new['af'] = "IPv6"
    elif rule.af == socket.AF_UNSPEC:
        new['af'] = "*"

    # Layer 4 Protocol
    if rule.proto == socket.IPPROTO_UDP:
        new['proto'] = "UDP"
    elif rule.proto == socket.IPPROTO_TCP:
        new['proto'] = "TCP"
    elif rule.proto == socket.IPPROTO_ICMP:
        new['proto'] = "ICMP"
    elif rule.proto == socket.IPPROTO_ICMPV6:
        new['proto'] = "ICMPV6"
    else:
        new['proto'] = '*'

    # ICMP
    new['icmp_type'] = rule.type

    # Source
    (new['src_addr'], new['src_addr_type'], new['src_port_op'], new['src_port']) = get_addr_port(rule.src)

    # Destination
    (new['dst_addr'], new['dst_addr_type'], new['dst_port_op'], new['dst_port']) = get_addr_port(rule.dst)

    # Label
    new['label'] = rule.label

    # Log
    if rule.log == pf.PF_LOG:
        new['log'] = True
    else:
        new['log'] = False

    # Keep State
    if rule.keep_state == pf.PF_STATE_NORMAL:
        new['keep_state'] = True
    else:
        new['keep_state'] = False

    # Quick
    new['quick'] = rule.quick

    return new

def get_addr_port(rule_addr):
    """Return address and port information from a pf.PFRuleAddr object"""
    addr = ""
    addr_type = ""

    if rule_addr.addr.type == pf.PF_ADDR_ADDRMASK:
        # IPv4 or IPv6 Address
        if rule_addr.addr.addr is None:
            addr = "*"
            addr_type = 'any'
        else:
            # Convert mask to prefix length
            cidr = ntoc(rule_addr.addr.mask, rule_addr.addr.af)

            # Address in CIDR format
            if cidr == 32 or cidr == 128:
                addr = rule_addr.addr.addr
            else:
                addr = "{0.addr}/{1}".format(rule_addr.addr, cidr)
            addr_type = 'addrmask'
    elif rule_addr.addr.type == pf.PF_ADDR_RANGE:
        # Address range
        addr = "{0[0]} - {0[1]}".format(rule.src.addr)
        addr_type = 'range'
    elif rule_addr.addr.type == pf.PF_ADDR_TABLE:
        addr = rule_addr.addr.tblname
        addr_type = 'table'

    return (addr, addr_type, rule_addr.port.op, rule_addr.port.num)

def ntoc(mask, af):
    """Convert netmask to prefix bit length"""

    if af == socket.AF_INET6:
        # IPv6
        return sum([bin(int(x, 16)).count("1") for x in mask.split(":") if x])
    elif af == socket.AF_INET:
        # IPv4
        return sum([bin(int(x)).count("1") for x in mask.split(".")])
    else:
        # Just return the mask if AF is unknown
        return mask


def get_ifaces(pfilter):
    """Return all interfaces we care about"""
    skip_ifaces = ['carp', 'egress', 'enc', 'enc0', 'lo', 'pflog', 'pflog0']
    all_ifaces = list()
    for iface in pfilter.get_ifaces():
        if iface.name not in skip_ifaces:
            all_ifaces.append(iface.name)
    return all_ifaces

def translate_rule(pfilter, **fields):
    """Parse form fields into a pf.PFRule"""

    # Load existing or create new rule
    if fields['id'] or fields['id'] == 0:
        ruleset = pfilter.get_ruleset()
        rule = ruleset.rules[fields['id']]
    else:
        rule = pf.PFRule()

    # Set action attribute
    if fields['action'] == 'pass':
        rule.action = pf.PF_PASS
    elif fields['action'] == 'block':
        rule.action = pf.PF_DROP
        rule.rule_flag = pf.PFRULE_DROP | 0
    elif fields['action'] == 'reject':
        rule.action = pf.PF_DROP
        rule.rule_flag = pf.PFRULE_RETURN | 0
    else:
        return "Action is not recognized"

    # Set direction attribute
    if fields['direction'] == 'in':
        rule.direction = pf.PF_IN
    elif fields['direction'] == 'out':
        rule.direction = pf.PF_OUT
    elif fields['direction'] == 'both':
        rule.direction = pf.PF_INOUT
    else:
        return "Direction is not recognized"

    # Set interface attribute
    if fields['iface'] in get_ifaces(pfilter):
        rule.ifname = fields['iface']
    else:
        return "Unknown interface specified"

    # Set address family attribute
    if fields['af'] == '*':
        rule.af = socket.AF_UNSPEC
    elif fields['af'] == 'IPv4':
        rule.af = socket.AF_INET
    elif fields['af'] == 'IPv6':
        rule.af = socket.AF_INET6
    else:
        return "Unknown address family type"

    # Set protocol attribute
    if fields['proto'] == '*':
        rule.proto = socket.IPPROTO_IP
    elif fields['proto'] == 'TCP':
        rule.proto = socket.IPPROTO_TCP
    elif fields['proto'] == 'UDP':
        rule.proto = socket.IPPROTO_UDP
    elif fields['proto'] == 'ICMP' and fields['af'] == 'IPv4':
        rule.proto = socket.IPPROTO_ICMP
    elif fields['proto'] == 'ICMP' and fields['af'] == 'IPv6':
        rule.proto = socket.IPPROTO_ICMPV6
    else:
        return "Protocol is not supported"

    # ICMP Type
    if fields['proto'] == "ICMP":
        # Use ICMP or ICMP6 depending on AF
        if rule.af == socket.AF_INET:
            if int(fields['icmptype']) in PFWEB_ICMP_TYPES:
                rule.type = int(fields['icmptype']) + 1
            elif int(fields['icmptype']) == 0:
                rule.type = 0
            else:
                return "Invalid ICMP Type"
        elif rule.af == socket.AF_INET6:
            if int(fields['icmp6type']) in PFWEB_ICMP6_TYPES:
                rule.type = int(fields['icmp6type']) + 1
            elif int(fields['icmp6type']) == 0:
                rule.type = 0
            else:
                return "Invalid ICMP Type"
        else:
            return "Must specifiy IPv4 or IPv6 when using ICMP"

    # Source Address Rule
    rule.src = translate_addr_rule(fields['src_addr'], fields['src_addr_type'], fields['src_addr_table'], fields['src_port_op'], fields['src_port_from'], fields['src_port_to'], rule.proto, rule.af)
    # Destination Address Rule
    rule.dst = translate_addr_rule(fields['dst_addr'], fields['dst_addr_type'], fields['dst_addr_table'], fields['dst_port_op'], fields['dst_port_from'], fields['dst_port_to'], rule.proto, rule.af)

    # Log checkbox
    if 'log' in fields:
        rule.log = pf.PF_LOG
    else:
        rule.log = 0

    # Quick checkbox
    if 'quick' in fields:
        rule.quick = True
    else:
        rule.quick = False

    # Keep state checkbox
    if 'keep_state' in fields:
        rule.keep_state = pf.PF_STATE_NORMAL
    else:
        rule.keep_state = 0

    if 'label' in fields:
        rule.label = fields['label']

    return rule

def translate_addr_rule(addr, addr_type, addr_table, port_op, port_from, port_to, proto, af):
    """Parses fields given in the pfweb form to a pf.PFRuleAddr object"""
    pfaddr = False
    if addr_type == "addrmask" and af != socket.AF_UNSPEC:
        # Validate IP address
        addr_mask = addr.split("/")
        try:
            socket.inet_pton(af, addr_mask[0])
        except socket.error:
            raise BadRequestError("Invalid IP address")

        if len(addr_mask) == 2 and int(addr_mask[1]) and (int(addr_mask[1]) < 0 or int(addr_mask[1]) > 128):
            raise BadRequestError("Invalid CIDR prefix")

        pfaddr = pf.PFAddr(addr)
    elif addr_type == "table":
        # Set addr to a table
        pfaddr = pf.PFAddr("<" + str(addr_table) + ">")

    # Do not set if ANY or proto is ICMP
    port = False
    if int(port_op) != pf.PF_OP_NONE and proto != socket.IPPROTO_ICMP and proto != socket.IPPROTO_ICMPV6:
        # Confirm port op
        if int(port_op) not in PFWEB_PORT_OPS:
            return "Invalid port op"

        # port from
        pfport_from = 0
        try:
            # Confirm input is a number
            if port_from != '':
                pfport_from = int(port_from)
        except ValueError:
            return "Invalid port number"

        pfport_to = 0
        # Set range
        if int(port_op) == pf.PF_OP_RRG or int(port_op) == pf.PF_OP_IRG or int(port_op) == pf.PF_OP_XRG:
            # Port to
            try:
                if port_to != '':
                    pfport_to = int(port_to)
            except ValueError:
                return "Invalid port number"

        port = pf.PFPort((pfport_from, pfport_to), proto, int(port_op))

    # Create and set the PFRuleAddr
    rule_addr = pf.PFRuleAddr()
    if pfaddr:
        rule_addr.addr = pfaddr
    if port:
        rule_addr.port = port

    return rule_addr

def get_tables(pfilter):
    """Return a list of tables for rendering a template"""
    web_tables = list()
    tables = pfilter.get_tables()
    count = 0

    # Parse each table into dict for web UI
    for table in tables:
        new = get_table(table)

        new['id'] = count

        web_tables.append(new)
        count += 1

    return web_tables

def get_table(table):
    """Gather table information into a data structure for rendering to a template"""
    new = dict()

    new['name'] = table.name
    new['addrs'] = list()

    for addr in table.addrs:
        cidr = ntoc(addr.mask, addr.af)
        if cidr == 32 or cidr == 128:
            new['addrs'].append(addr.addr)
        else:
            new['addrs'].append("{}/{}".format(addr.addr, cidr))    
        
    return new

def translate_table(fields):
    """Parse form fields into a list addresses"""
    addrs = list()

    for f in sorted(fields):
        if f.startswith('addr') and fields[f]:
            addrs.append(fields[f])

    return addrs

def table_in_use(pfilter, table):
    """Return boolean if a table is in use by a rule"""
    for t in pfilter.get_tstats():
        if t.table.name == table:
            tstats = t
            break
    if tstats.refcnt['rules'] == 0 and tstats.refcnt['anchors'] == 0:
        return False
    else:
        return True

def sizeof_fmt(num, suffix='B'):
    """
    Convert bytes into a human readable format

    Straight rip from stackoverflow
    """
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, 'Yi', suffix)

if __name__ == "__main__":
    app.debug = False
    app.run(host='0.0.0.0', port=80)
