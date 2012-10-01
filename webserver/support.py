import honeyd
import urllib
import cgi
import sys
from htmltmpl import TemplateManager, TemplateProcessor

def quote(data):
    """Escapes a string so that it can safely be displayed
    in an HTML document"""
    escape_quotes = 1
    return cgi.escape(data, escape_quotes)

def parse_query(query):
    if not query:
        return None
    
    if query.has_key('delete_ip'):
        address = quote(query['delete_ip'])
        if honeyd.delete_template(address):
            message = 'Successfully removed %s from database' % address
        else:
            message = 'Address %s does not exist' % address
        return message
    if query.has_key('delete_connection'):
        arguments = urllib.unquote(query['delete_connection']).split(',')
        if len(arguments) != 5:
            return None
        name = quote('%s %s:%s - %s:%s' % tuple(arguments))
        if honeyd.delete_connection(*arguments):
            message = 'Successfully terminated connection %s.' % name
        else:
            message = 'Could not remove connection %s.' % name
        return message
    return None

def uptime():
    uptime = honeyd.uptime()
    seconds = uptime % 60
    uptime /= 60
    minutes = uptime % 60
    uptime /= 60
    hours = uptime % 24
    uptime /= 24
    days = uptime

    return "%d days %02d:%02d:%02d" % (days, hours, minutes, seconds)

def table_head(title, explanation):
    content = '''<div class="status">
<h1>%s</h1>
<p>%s</p>
''' % (title, explanation)

    return content

def table_end():
    return '''</table></div>\n'''

def config_table():
    config = honeyd.config()

    content = table_head("Honeyd Static Configuration",
                         "This table shows the configuration of Honeyd.")

    content += '''<table>
  <tr><td class="tableHeadingInside">Key</td>
      <td class="tableHeadingInside">Value</td>
</tr>'''

    for name in config.keys():
        content += '''<tr>
<td>%s</td><td>%s</td>
</tr>''' % (name, config[name])

    content += table_end()

    return content

def humanize(number, postfix):
    number = float(number)
    scale = 0
    while number > 1000:
        scale += 1
        number /= 1000

    symbol = 'B'
    if scale == 1:
        symbol = 'KB'
    elif scale == 2:
        symbol = 'MB'
    elif scale == 3:
        symbol = 'GB'
    elif scale == 4:
        symbol = 'TB'
    elif scale >= 5 :
        symbol = 'xx'

    return '%.2f %s%s' % (number, symbol, postfix)

def stats_table(root):
    raw_stats = honeyd.stats_network()

    stats = []

    # Convert the dictionary into something that the template manager
    # can understand.
    for key in raw_stats.keys():
        minute = humanize(raw_stats[key][0], '/s')
        hour = humanize(raw_stats[key][1], '/s')
        day = humanize(raw_stats[key][2], '/s')
            
        stats.append({ "name" : key,
                       "minute" : minute,
                       "hour" : hour,
                       "day" : day })

    template = TemplateManager().prepare(root +
                                         "/templates/status_stats.tmpl")
    tproc = TemplateProcessor(0)

    tproc.set("title", "Honeyd Statistics")
    tproc.set("explanation",("This table shows current statistics collected "
                             "by Honeyd."))
    tproc.set("Stats", stats)

    content = tproc.process(template)

    return content

def interface_table():
    interfaces = honeyd.interfaces()

    content = table_head("Interface&nbsp;Information",
                         "This table shows the interface that Honeyd has been configured to listen to.")

    content += '''<table>
<tr><td class="tableHeadingInside">Name</td>
      <td class="tableHeadingInside">Address</td>
      <td class="tableHeadingInside">MTU</td>
      <td class="tableHeadingInside">Link Address</td>
</tr>'''

    for inter in interfaces:
        content += '''<tr>
<td>%s</td><td>%s</td><td>%d</td><td>%s</td>
</tr>\n''' % (inter['name'], inter['address'], inter['mtu'], inter['link'])

    content += table_end()

    return content

def config_ips(root):
    ips = honeyd.config_ips()

    template = TemplateManager().prepare(root + "/templates/config_ip.tmpl")
    tproc = TemplateProcessor(0)

    tproc.set("title", "Bound IP addresses")
    tproc.set("explanation", "This table shows the IP addresses of the " +
                                "currently configured virtual honeypots.")
    tproc.set("Ips", ips)

    content = tproc.process(template)

    return content

def status_connections(root, which):
    connections = honeyd.status_connections(which.lower())

    if not len(connections):
        return "There are currently no active %s connections." % which.upper()

    for connection in connections:
        id = "%s,%s,%d,%s,%d" % (which.lower(),
                                   connection['src'], connection['sport'],
                                   connection['dst'], connection['dport'])
        connection['id'] = urllib.quote(id)

    template = TemplateManager().prepare(root +
                                         "/templates/status_connections.tmpl")
    tproc = TemplateProcessor(0)

    tproc.set("title", "Active %s Connections" % which.upper())
    tproc.set("explanation",
              "This table shows the currently active %s connections" % which.upper())
    tproc.set("Connections", connections)

    content = tproc.process(template)

    return content
