#!/usr/bin/env python
# -*- coding: utf-8 -*-

from coap_.memory import Memory

import asyncio
import aiocoap.resource as resource
import aiocoap

class CoAP(resource.Resource): 

    def __init__(self, data):

        self.data = data

        self.payload = """</qlink>,</qlink/ack>;title="Qlink-ACK Resource",</qlink/request>;title="Qlink-Request Resource",</qlink/searchgw>;title="SearchGW Resource",</qlink/success>;title="Qlink-Success Resource",</qlink/wlantest>;title="Qlink-WLAN Resource",</gw>,</gw/query>,</gw/query/DiagnotorConnection>;title="Connect To Diagnotor",</gw/query/apdevices>;title="Inform Data Resource",</gw/query/config>;title="config-properties Resource",</basic>,</basic/regist>;title="Qlink-Regist Resource",</basic/show>;title="Qlink-SHOW Resource",</device>,</device/command>,</device/command/control>;title="Device Control Resource",</device/command/data>;title="Control Data Resource",</device/inform>,</device/inform/boot>;title="Boot-Request Resource",</device/inform/bootstrap>;title="bootstrap-Request Resource",</device/inform/data>;obs;title="Inform Data Resource",</device/inform/heartbeat>;title="HeartBeat Resource",</device/inform/offline>;title="ChildDevice Offline Resource",</.well-known/core>""".encode('ascii')

    async def render_get(self, request):
        msg = aiocoap.Message(code = aiocoap.CONTENT, payload=self.payload)
        msg.opt.content_format = 40 # application/link-format
        return msg

    def run(self):
        root = resource.Site()
        root.add_resource(['.well-known', 'core'],resource.WKCResource(root.get_resources_as_linkheader))

        if(self.payload in self.geststatus):
            return self.response
        else:
            return self.error
