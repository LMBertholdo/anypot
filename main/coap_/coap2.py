#!/usr/bin/env python

import asyncio
import aiocoap.resource as resource
import aiocoap

import threading

class CoAP(resource.Resource):

    def __init__(self):
        self.payload = """</qlink>,</qlink/ack>;title="Qlink-ACK Resource",</qlink/request>;title="Qlink-Request Resource",</qlink/searchgw>;title="SearchGW Resource",</qlink/success>;title="Qlink-Success Resource",</qlink/wlantest>;title="Qlink-WLAN Resource",</gw>,</gw/query>,</gw/query/DiagnotorConnection>;title="Connect To Diagnotor",</gw/query/apdevices>;title="Inform Data Resource",</gw/query/config>;title="config-properties Resource",</basic>,</basic/regist>;title="Qlink-Regist Resource",</basic/show>;title="Qlink-SHOW Resource",</device>,</device/command>,</device/command/control>;title="Device Control Resource",</device/command/data>;title="Control Data Resource",</device/inform>,</device/inform/boot>;title="Boot-Request Resource",</device/inform/bootstrap>;title="bootstrap-Request Resource",</device/inform/data>;obs;title="Inform Data Resource",</device/inform/heartbeat>;title="HeartBeat Resource",</device/inform/offline>;title="ChildDevice Offline Resource",</.well-known/core>""".encode('ascii')

    async def render_get(self, request):
        try:
            msg = aiocoap.Message(code = aiocoap.CONTENT, payload=self.payload)
            msg.opt.content_format = 40 # application/link-format
            return msg

        except Exception as e:
            print('[coap2 render_get function]',e)

    def run(self):
        try:
            root = resource.Site()
            root.add_resource(['.well-known', 'core'],resource.WKCResource(root.get_resources_as_linkheader))

            if(self.payload in self.geststatus):
                return self.response
            else:
                return self.error

        except Exception as e:
            print('[coap2 run function]',e)

# para testar
def main(root, loop):
    try:
        asyncio.set_event_loop(loop)
        # precisa do bind para remover de todas as interfaces, mas o bind so esta funcionando para ipv6
        # localhost = 0:0:0:0:0:0:0:1 e todas interfaces :: ou 0:0:0:0:0:0:0:0
        asyncio.Task(aiocoap.Context.create_server_context(root, bind=('0:0:0:0:0:0:0:1', 5683) ))
        asyncio.get_event_loop().run_forever()

    except Exception as e:
        print('[coap2 main function]',e)

def dd():
    # Resource tree creation
    try:
        print('CoAP2 background Server UP')
        root = resource.Site()
        root.add_resource(['.well-known', 'core'], CoAP())

        loop = asyncio.new_event_loop()
        p = threading.Thread(target=main, args=(root, loop,))
        p.start()

    except Exception as e:
        print('[coap2 dd main function]',e)
