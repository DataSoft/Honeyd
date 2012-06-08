import time
import support
from htmltmpl import TemplateManager, TemplateProcessor

self.send_response(200)
self.send_header("Content-Type", "text/html")
self.send_nocache()
self.end_headers()

# Process commands given to us
message = support.parse_query(self.query)

# Compile or load already precompiled template.
template = TemplateManager().prepare(self.root+"/templates/index.tmpl")
tproc = TemplateProcessor(0)

# Set the title.
tproc.set("title", "Honeyd Configuration Interface")

content = "Welcome to the Honeyd Configuration Interface.<p>"
content += support.config_table()
content += "<p>"
content += support.config_ips(self.root)

if message:
    tproc.set("message", message)
tproc.set("content", content)
tproc.set("uptime", support.uptime())

# Print the processed template.
self.wfile.write(tproc.process(template))
