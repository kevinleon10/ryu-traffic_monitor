# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter
import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
import json

simple_switch_instance_name = 'simple_switch_api_app'
url = '/mactable/{dpid}'


class SimpleMonitor13(simple_switch_13.SimpleSwitch13):
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.switches = {}
        self.ev = None
        self.ev2 = None
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController,
                      {simple_switch_instance_name: self})

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        # body = ev.msg.body

        # self.logger.info('datapath         '
        #                  'in-port  eth-dst           '
        #                  'out-port packets  bytes')
        # self.logger.info('---------------- '
        #                  '-------- ----------------- '
        #                  '-------- -------- --------')
        # for stat in sorted([flow for flow in body if flow.priority == 1],
        #                    key=lambda flow: (flow.match['in_port'],
        #                                      flow.match['eth_dst'])):
        #     self.logger.info('%016x %8x %17s %8x %8d %8d',
        #                      ev.msg.datapath.id,
        #                      stat.match['in_port'], stat.match['eth_dst'],
        #                      stat.instructions[0].actions[0].port,
        #                      stat.packet_count, stat.byte_count)
        # self.logger.info('%s', json.dumps(ev.msg.to_jsondict(), ensure_ascii=True,
        #                                  indent=3, sort_keys=True))
        self.ev = ev

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        # body = ev.msg.body

        # self.logger.info('datapath         port     '
        #                  'rx-pkts  rx-bytes rx-error '
        #                  'tx-pkts  tx-bytes tx-error')
        # self.logger.info('---------------- -------- '
        #                  '-------- -------- -------- '
        #                  '-------- -------- --------')
        # for stat in sorted(body, key=attrgetter('port_no')):
        #     self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
        #                      ev.msg.datapath.id, stat.port_no,
        #                      stat.rx_packets, stat.rx_bytes, stat.rx_errors,
        #                      stat.tx_packets, stat.tx_bytes, stat.tx_errors)
        # self.logger.info('%s', json.dumps(ev.msg.to_jsondict(), ensure_ascii=True,
        #                                  indent=3, sort_keys=True))
        self.ev2 = ev

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super(SimpleMonitor13, self).switch_features_handler(ev)
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

    def set_mac_to_port(self, dpid, entry):
        mac_table = self.mac_to_port.setdefault(dpid, {})
        datapath = self.switches.get(dpid)

        entry_port = entry['port']
        entry_mac = entry['mac']

        if datapath is not None:
            parser = datapath.ofproto_parser
            if entry_port not in mac_table.values():

                for mac, port in mac_table.items():
                    # from known device to new device
                    actions = [parser.OFPActionOutput(entry_port)]
                    match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
                    self.add_flow(datapath, 1, match, actions)

                    # from new device to known device
                    actions = [parser.OFPActionOutput(port)]
                    match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
                    self.add_flow(datapath, 1, match, actions)

                mac_table.update({entry_mac: entry_port})
        return mac_table

    def drop_web_packets(self, values):
        datapath = self.ev.msg.datapath
        parser = datapath.ofproto_parser
        proto = datapath.ofproto
        ipv4_src = values['ipv4_src']
        ipv4_dst = values['ipv4_dst']
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_dst=ipv4_dst,
                                                ipv4_src=ipv4_src, tcp_dst=80)
        instruction = [
            parser.OFPInstructionActions(proto.OFPIT_CLEAR_ACTIONS, [])
        ]
        msg = parser.OFPFlowMod(datapath,
                                table_id=0,
                                priority=2,
                                command=proto.OFPFC_ADD,
                                match=match,
                                instructions=instruction
                                )
        datapath.send_msg(msg)

    def drop_dns_packets(self, values):
        datapath = self.ev.msg.datapath
        parser = datapath.ofproto_parser
        proto = datapath.ofproto
        ipv4_src = values['ipv4_src']
        ipv4_dst = values['ipv4_dst']
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=ipv4_dst,
                                ipv4_src=ipv4_src, udp_dst=53)
        instruction = [
            parser.OFPInstructionActions(proto.OFPIT_CLEAR_ACTIONS, [])
        ]
        msg = parser.OFPFlowMod(datapath,
                                table_id=0,
                                priority=2,
                                command=proto.OFPFC_ADD,
                                match=match,
                                instructions=instruction
                                )
        datapath.send_msg(msg)

    def drop_others_packets(self, values):
        datapath = self.ev.msg.datapath
        parser = datapath.ofproto_parser
        proto = datapath.ofproto
        eth_src = values['eth_src']
        eth_dst = values['eth_dst']
        match = parser.OFPMatch(eth_dst=eth_dst, eth_src=eth_src)
        instruction = [
            parser.OFPInstructionActions(proto.OFPIT_CLEAR_ACTIONS, [])
        ]
        msg = parser.OFPFlowMod(datapath,
                                table_id=0,
                                priority=3,
                                command=proto.OFPFC_ADD,
                                match=match,
                                instructions=instruction
                                )
        datapath.send_msg(msg)


class SimpleSwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[simple_switch_instance_name]

    @route('simpleswitch', url, methods=['GET'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

        if dpid not in simple_switch.mac_to_port:
            return Response(status=404)

        mac_table = simple_switch.mac_to_port.get(dpid, {})
        body = json.dumps(mac_table)
        return Response(content_type='application/json', body=body)

    @route('simpleswitch', '/flows',
           methods=['GET'])
    def flow(self, req, **kwargs):
        simple_switch = self.simple_switch_app
        if simple_switch.ev is not None:
            return Response(content_type='application/json',
                            body=json.dumps(simple_switch.ev.msg.to_jsondict(), ensure_ascii=True,
                                            indent=3, sort_keys=True))
        else:
            return Response(status=503)

    @route('simpleswitch', '/ports',
           methods=['GET'])
    def port(self, req, **kwargs):
        simple_switch = self.simple_switch_app
        if simple_switch.ev2 is not None:
            return Response(content_type='application/json',
                            body=json.dumps(simple_switch.ev2.msg.to_jsondict(), ensure_ascii=True,
                                            indent=3, sort_keys=True))
        else:
            return Response(status=503)

    @route('simpleswitch', '/web', methods=['PUT'])
    def drop_web(self, req, **kwargs):
        simple_switch = self.simple_switch_app
        try:
            values = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        try:
            simple_switch.drop_web_packets(values)
            return Response(status=200)
        except Exception as e:
            return Response(status=500)

    @route('simpleswitch', '/dns', methods=['PUT'])
    def drop_dns(self, req, **kwargs):
        simple_switch = self.simple_switch_app
        try:
            values = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        try:
            simple_switch.drop_dns_packets(values)
            return Response(status=200)
        except Exception as e:
            return Response(status=500)

    @route('simpleswitch', '/others', methods=['PUT'])
    def drop_others(self, req, **kwargs):
        simple_switch = self.simple_switch_app
        try:
            values = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        try:
            simple_switch.drop_others_packets(values)
            return Response(status=200)
        except Exception as e:
            return Response(status=500)

    @route('simpleswitch', url, methods=['PUT'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def put_mac_table(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        if dpid not in simple_switch.mac_to_port:
            return Response(status=404)

        try:
            mac_table = simple_switch.set_mac_to_port(dpid, new_entry)
            body = json.dumps(mac_table)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(status=500)
