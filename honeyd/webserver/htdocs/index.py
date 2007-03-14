import honeyd
import time
import support
from htmltmpl import TemplateManager, TemplateProcessor

global counter

self.send_response(200)
self.send_header("Content-Type", "text/html")
self.send_nocache()
self.end_headers()

# Compile or load already precompiled template.
template = TemplateManager().prepare(self.root+"/templates/index.tmpl")
tproc = TemplateProcessor(0)

# Process commands given to us
message = support.parse_query(self.query)

# Set the title.
tproc.set("title", "Honeyd Administration Interface")

# Test
try:
    counter += 1
except:
    counter = 1

greeting = ("Welcome to the Honeyd Administration Interface."
            "You are visitor %d.<p>") % counter

content = support.interface_table()
content += "<p>" + support.stats_table(self.root) + "</p>\n"
content += "<p>" + support.status_connections(self.root, "tcp") + "</p>\n"
content += "<p>" + support.status_connections(self.root, "udp") + "</p>\n"

side_content = ("<div class=graphs>"
                "<img height=155 width=484 src=/graphs/traffic_hourly.gif><br>"
                "<img height=155 width=484 src=/graphs/traffic_daily.gif>"
                "</div>")

support.security_check(tproc)

if message:
    tproc.set("message", message)

tproc.set("greeting", greeting)
tproc.set("content", content)
tproc.set("side_content", side_content)
tproc.set("uptime", support.uptime())

# Print the processed template.
self.wfile.write(tproc.process(template))
