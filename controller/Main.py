import sys
from builtins import print
from ryu import cfg
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
##########
import logging
import json
import ast
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib import ofctl_v1_4
from ryu.lib import ofctl_v1_5
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import WSGIApplication
from ryu.lib import hub
###########
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3

import random

from crypto.Cryptography import Cryptography
from sensor.Sensor import Sensor


class CommandNotFoundError(RyuException):
    message = 'No such command : %(cmd)s'


class PortNotFoundError(RyuException):
    message = 'No such port info: %(port_no)s'


LOG = logging.getLogger('ryu.app.ofctl_rest')

# supported ofctl versions in this restful app
supported_ofctl = {
    ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
    ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
    ofproto_v1_4.OFP_VERSION: ofctl_v1_4,
    ofproto_v1_5.OFP_VERSION: ofctl_v1_5,
}


def stats_method(method):
    def wrapper(self, req, dpid, *args, **kwargs):
        # Get datapath instance from DPSet
        try:
            dp = self.dpset.get(int(str(dpid), 0))
        except ValueError:
            LOG.exception('Invalid dpid: %s', dpid)
            return Response(status=400)
        if dp is None:
            LOG.error('No such Datapath: %s', dpid)
            return Response(status=404)

        # Get lib/ofctl_* module
        try:
            ofctl = supported_ofctl.get(dp.ofproto.OFP_VERSION)
        except KeyError:
            LOG.exception('Unsupported OF version: %s',
                          dp.ofproto.OFP_VERSION)
            return Response(status=501)

        # Invoke StatsController method
        try:
            ret = method(self, req, dp, ofctl, *args, **kwargs)
            return Response(content_type='application/json',
                            body=json.dumps(ret))
        except ValueError:
            LOG.exception('Invalid syntax: %s', req.body)
            return Response(status=400)
        except AttributeError:
            LOG.exception('Unsupported OF request in this version: %s',
                          dp.ofproto.OFP_VERSION)
            return Response(status=501)

    return wrapper


def command_method(method):
    def wrapper(self, req, *args, **kwargs):
        # Parse request json body
        try:
            if req.body:
                # We use ast.literal_eval() to parse request json body
                # instead of json.loads().
                # Because we need to parse binary format body
                # in send_experimenter().
                body = ast.literal_eval(req.body.decode('utf-8'))
            else:
                body = {}
        except SyntaxError:
            LOG.exception('Invalid syntax: %s', req.body)
            return Response(status=400)

        # Get datapath_id from request parameters
        dpid = body.get('dpid', None)
        if not dpid:
            try:
                dpid = kwargs.pop('dpid')
            except KeyError:
                LOG.exception('Cannot get dpid from request parameters')
                return Response(status=400)

        # Get datapath instance from DPSet
        try:
            dp = self.dpset.get(int(str(dpid), 0))
        except ValueError:
            LOG.exception('Invalid dpid: %s', dpid)
            return Response(status=400)
        if dp is None:
            LOG.error('No such Datapath: %s', dpid)
            return Response(status=404)

        # Get lib/ofctl_* module
        try:
            ofctl = supported_ofctl.get(dp.ofproto.OFP_VERSION)
        except KeyError:
            LOG.exception('Unsupported OF version: version=%s',
                          dp.ofproto.OFP_VERSION)
            return Response(status=501)

        # Invoke StatsController method
        try:
            method(self, req, dp, ofctl, body, *args, **kwargs)
            return Response(status=200)
        except ValueError:
            LOG.exception('Invalid syntax: %s', req.body)
            return Response(status=400)
        except AttributeError:
            LOG.exception('Unsupported OF request in this version: %s',
                          dp.ofproto.OFP_VERSION)
            return Response(status=501)
        except CommandNotFoundError as e:
            LOG.exception(e.message)
            return Response(status=404)
        except PortNotFoundError as e:
            LOG.exception(e.message)
            return Response(status=404)

    return wrapper


class StatsController(ControllerBase):
    list_ip_deny = {}
    def __init__(self, req, link, data, **config):
        super(StatsController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    def get_dpids(self, req, **_kwargs):
        dps = list(self.dpset.dps.keys())
        body = json.dumps(dps)
        return Response(content_type='application/json', body=body)

    @stats_method
    def get_desc_stats(self, req, dp, ofctl, **kwargs):
        return ofctl.get_desc_stats(dp, self.waiters)

    @stats_method
    def get_flow_desc(self, req, dp, ofctl, **kwargs):
        flow = req.json if req.body else {}
        return ofctl.get_flow_desc(dp, self.waiters, flow)

    @stats_method
    def get_flow_stats(self, req, dp, ofctl, **kwargs):
        flow = req.json if req.body else {}
        return ofctl.get_flow_stats(dp, self.waiters, flow)

    @stats_method
    def get_aggregate_flow_stats(self, req, dp, ofctl, **kwargs):
        flow = req.json if req.body else {}
        return ofctl.get_aggregate_flow_stats(dp, self.waiters, flow)

    @stats_method
    def get_table_stats(self, req, dp, ofctl, **kwargs):
        return ofctl.get_table_stats(dp, self.waiters)

    @stats_method
    def get_table_features(self, req, dp, ofctl, **kwargs):
        return ofctl.get_table_features(dp, self.waiters)

    @stats_method
    def get_port_stats(self, req, dp, ofctl, port=None, **kwargs):
        if port == "ALL":
            port = None

        return ofctl.get_port_stats(dp, self.waiters, port)

    @stats_method
    def get_queue_stats(self, req, dp, ofctl,
                        port=None, queue_id=None, **kwargs):
        if port == "ALL":
            port = None

        if queue_id == "ALL":
            queue_id = None

        return ofctl.get_queue_stats(dp, self.waiters, port, queue_id)

    @stats_method
    def get_queue_config(self, req, dp, ofctl, port=None, **kwargs):
        if port == "ALL":
            port = None

        return ofctl.get_queue_config(dp, self.waiters, port)

    @stats_method
    def get_queue_desc(self, req, dp, ofctl,
                       port=None, queue=None, **_kwargs):
        if port == "ALL":
            port = None

        if queue == "ALL":
            queue = None

        return ofctl.get_queue_desc(dp, self.waiters, port, queue)

    @stats_method
    def get_meter_features(self, req, dp, ofctl, **kwargs):
        return ofctl.get_meter_features(dp, self.waiters)

    @stats_method
    def get_meter_config(self, req, dp, ofctl, meter_id=None, **kwargs):
        if meter_id == "ALL":
            meter_id = None

        return ofctl.get_meter_config(dp, self.waiters, meter_id)

    @stats_method
    def get_meter_desc(self, req, dp, ofctl, meter_id=None, **kwargs):
        if meter_id == "ALL":
            meter_id = None

        return ofctl.get_meter_desc(dp, self.waiters, meter_id)

    @stats_method
    def get_meter_stats(self, req, dp, ofctl, meter_id=None, **kwargs):
        if meter_id == "ALL":
            meter_id = None

        return ofctl.get_meter_stats(dp, self.waiters, meter_id)

    @stats_method
    def get_group_features(self, req, dp, ofctl, **kwargs):
        return ofctl.get_group_features(dp, self.waiters)

    @stats_method
    def get_group_desc(self, req, dp, ofctl, group_id=None, **kwargs):
        if dp.ofproto.OFP_VERSION < ofproto_v1_5.OFP_VERSION:
            return ofctl.get_group_desc(dp, self.waiters)
        else:
            return ofctl.get_group_desc(dp, self.waiters, group_id)

    @stats_method
    def get_group_stats(self, req, dp, ofctl, group_id=None, **kwargs):
        if group_id == "ALL":
            group_id = None

        return ofctl.get_group_stats(dp, self.waiters, group_id)

    @stats_method
    def get_port_desc(self, req, dp, ofctl, port_no=None, **kwargs):
        if dp.ofproto.OFP_VERSION < ofproto_v1_5.OFP_VERSION:
            return ofctl.get_port_desc(dp, self.waiters)
        else:
            return ofctl.get_port_desc(dp, self.waiters, port_no)

    @stats_method
    def get_role(self, req, dp, ofctl, **kwargs):
        return ofctl.get_role(dp, self.waiters)

    @command_method
    def mod_flow_entry(self, req, dp, ofctl, flow, cmd, **kwargs):
        cmd_convert = {
            'add': dp.ofproto.OFPFC_ADD,
            'modify': dp.ofproto.OFPFC_MODIFY,
            'modify_strict': dp.ofproto.OFPFC_MODIFY_STRICT,
            'delete': dp.ofproto.OFPFC_DELETE,
            'delete_strict': dp.ofproto.OFPFC_DELETE_STRICT,
        }

        mod_cmd = cmd_convert.get(cmd, None)
        if mod_cmd is None:
            raise CommandNotFoundError(cmd=cmd)

        ofctl.mod_flow_entry(dp, flow, mod_cmd)

    @command_method
    def delete_flow_entry(self, req, dp, ofctl, flow, **kwargs):
        if ofproto_v1_0.OFP_VERSION == dp.ofproto.OFP_VERSION:
            flow = {}
        else:
            flow = {'table_id': dp.ofproto.OFPTT_ALL}

        ofctl.mod_flow_entry(dp, flow, dp.ofproto.OFPFC_DELETE)

    @command_method
    def mod_meter_entry(self, req, dp, ofctl, meter, cmd, **kwargs):
        cmd_convert = {
            'add': dp.ofproto.OFPMC_ADD,
            'modify': dp.ofproto.OFPMC_MODIFY,
            'delete': dp.ofproto.OFPMC_DELETE,
        }
        mod_cmd = cmd_convert.get(cmd, None)
        if mod_cmd is None:
            raise CommandNotFoundError(cmd=cmd)

        ofctl.mod_meter_entry(dp, meter, mod_cmd)

    @command_method
    def mod_group_entry(self, req, dp, ofctl, group, cmd, **kwargs):
        cmd_convert = {
            'add': dp.ofproto.OFPGC_ADD,
            'modify': dp.ofproto.OFPGC_MODIFY,
            'delete': dp.ofproto.OFPGC_DELETE,
        }
        mod_cmd = cmd_convert.get(cmd, None)
        if mod_cmd is None:
            raise CommandNotFoundError(cmd=cmd)

        ofctl.mod_group_entry(dp, group, mod_cmd)

    @command_method
    def mod_port_behavior(self, req, dp, ofctl, port_config, cmd, **kwargs):
        port_no = port_config.get('port_no', None)
        port_no = int(str(port_no), 0)

        port_info = self.dpset.port_state[int(dp.id)].get(port_no)
        if port_info:
            port_config.setdefault('hw_addr', port_info.hw_addr)
            if dp.ofproto.OFP_VERSION < ofproto_v1_4.OFP_VERSION:
                port_config.setdefault('advertise', port_info.advertised)
            else:
                port_config.setdefault('properties', port_info.properties)
        else:
            raise PortNotFoundError(port_no=port_no)

        if cmd != 'modify':
            raise CommandNotFoundError(cmd=cmd)

        ofctl.mod_port_behavior(dp, port_config)

    @command_method
    def send_experimenter(self, req, dp, ofctl, exp, **kwargs):
        ofctl.send_experimenter(dp, exp)

    @command_method
    def set_role(self, req, dp, ofctl, role, **kwargs):
        ofctl.set_role(dp, role)

    def set_ip_black_list(self, req, **_kwargs):
        # A = sensor_name
        # B = mac_address
        # C = ip
        # D = counter_packet
        # E = host_name
        # F = crypt
        # G = access

        sensor = Sensor.get_sensor_by_id(req.json_body['id'])
        if sensor == None:
            data = {'access': False}
            body = json.dumps(data)
        else:
            ##if crypgraphy messages
            isCryptography = bool(
                Cryptography.Decrypt(sensor.get_sensor_key(), sensor.get_sensor_iv(), req.json_body['F']))

            if isCryptography:
                sensor_name = Cryptography.Decrypt(sensor.get_sensor_key(), sensor.get_sensor_iv(), req.json_body['A'])
                mac_address = Cryptography.Decrypt(sensor.get_sensor_key(), sensor.get_sensor_iv(), req.json_body['B'])
                ip = Cryptography.Decrypt(sensor.get_sensor_key(), sensor.get_sensor_iv(), req.json_body['C'])
                counter_packet = int(Cryptography.Decrypt(sensor.get_sensor_key(), sensor.get_sensor_iv(), req.json_body['D']))
                host_name = Cryptography.Decrypt(sensor.get_sensor_key(), sensor.get_sensor_iv(), req.json_body['E'])
                validate_sensor = sensor.validate_sensor(sensor_name, mac_address, counter_packet, host_name)

            else:
                sensor_name = req.json_body['A']
                mac_address = req.json_body['B']
                ip = req.json_body['C']
                counter_packet = req.json_body['D']
                host_name = req.json_body['E']
                validate_sensor = sensor.validate_sensor(sensor_name, mac_address, counter_packet, host_name)

            if isCryptography and validate_sensor:
                if ip not in StatsController.list_ip_deny:

                    # StatsController.list_ip_deny.append(ip)
                    StatsController.list_ip_deny[ip] = True
                    data = {'G': Cryptography.Encrypt(sensor.get_sensor_key(), sensor.get_sensor_iv(), str(True)),
                    'D' : Cryptography.Encrypt(sensor.get_sensor_key(), sensor.get_sensor_iv(), str(sensor.add_conter()))}
                    body = json.dumps(data)
            elif not isCryptography and validate_sensor:
                if ip not in StatsController.list_ip_deny:
                    # StatsController.list_ip_deny.append(ip)
                    StatsController.list_ip_deny[ip] = True

                    data = {'G': True,
                    'D' : sensor.add_conter()}
                    body = json.dumps(data)
            else:
                data = {'G': Cryptography.Encrypt(sensor.get_sensor_key(), sensor.get_sensor_iv(), str(False))}
                body = json.dumps(data)
        return Response(content_type='application/json', body=body)

    def get_parameter(self, req, **_kwargs):

        # sensor, sensor_mac,
        # self.__number_passwd,
        # crypto.Create_key(),
        # crypto.Create_IV()
        key, iv , id = Sensor.request_sensors(req.json_body['sensor'],
                                              req.json_body['passwd'],
                                              req.json_body['mac_address'],
                                              req.json_body['host_name'])
        

        if (key == ""):
            print("False get parameter")

            data = {'access': False}
        else:

            print("True get parameter")
            dps = list(self.dpset.dps.keys())
            data = {'access': True,
                    'id': id ,
                    'dpid': dps,
                    'key': key,
                    'IV': iv}

        body = json.dumps(data)

        return Response(content_type='application/json', body=body)

    # def get_dpids(self, req, **_kwargs):
    #     # data = {
    #     #     "dps": list(self.dpset.dps.keys())
    #     # }
    #     # body = json.dumps(data)
    #     # return Response(content_type='application/json', body=body)
    #
    #     dps = list(self.dpset.dps.keys())
    #     body = json.dumps(dps)
    #     return Response(content_type='application/json', body=body)


logger = logging.getLogger(__file__)
formatter = logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s')
logger.propagate = False
logger.setLevel(logging.INFO)

if not logger.handlers:
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)

_SERVICE_TYPE = (
    "secondary",
    "primary"
)


##arp
_QUERY = 1
_RESPONSE = 2

# conn = pymysql.connect(host='192.168.0.200', user='rede', password='123456', db='REDE')

def _load_config_file():
    try:
        with open(cfg.CONF['test-switch']['dir']) as file_handler:
            return json.load(file_handler)
    except:
        return json.load(sys.stdin)


class SDNControllerFlow(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }


    def __init__(self, *args, **kwargs):
        super(SDNControllerFlow, self).__init__(*args, **kwargs)
        #############

        #self.teste_acesso = "valore teste"
        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        mapper = wsgi.mapper

        wsgi.registory['StatsController'] = self.data
        path = '/stats'

        uri = path + '/switches/'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_dpids',
                       conditions=dict(method=['POST']))

        uri = path + '/desc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_desc_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/flowdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/flow/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/aggregateflow/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController,
                       action='get_aggregate_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/table/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_table_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/tablefeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_table_features',
                       conditions=dict(method=['GET']))

        uri = path + '/port/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/port/{dpid}/{port}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queue/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queue/{dpid}/{port}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queue/{dpid}/{port}/{queue_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queueconfig/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_config',
                       conditions=dict(method=['GET']))

        uri = path + '/queueconfig/{dpid}/{port}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_config',
                       conditions=dict(method=['GET']))

        uri = path + '/queuedesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/queuedesc/{dpid}/{port}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/queuedesc/{dpid}/{port}/{queue}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/meterfeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_features',
                       conditions=dict(method=['GET']))

        uri = path + '/meterconfig/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_config',
                       conditions=dict(method=['GET']))

        uri = path + '/meterconfig/{dpid}/{meter_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_config',
                       conditions=dict(method=['GET']))

        uri = path + '/meterdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/meterdesc/{dpid}/{meter_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/meter/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/meter/{dpid}/{meter_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/groupfeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_features',
                       conditions=dict(method=['GET']))

        uri = path + '/groupdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/groupdesc/{dpid}/{group_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/group/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/group/{dpid}/{group_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/portdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/portdesc/{dpid}/{port_no}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/role/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_role',
                       conditions=dict(method=['GET']))

        uri = path + '/flowentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_flow_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/flowentry/clear/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='delete_flow_entry',
                       conditions=dict(method=['DELETE']))

        uri = path + '/meterentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_meter_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/groupentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_group_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/portdesc/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_port_behavior',
                       conditions=dict(method=['POST']))

        uri = path + '/experimenter/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='send_experimenter',
                       conditions=dict(method=['POST']))

        uri = path + '/role'
        mapper.connect('stats', uri,
                       controller=StatsController, action='set_role',
                       conditions=dict(method=['POST']))

        # uri = path + '/black_list/{ip}'
        # mapper.connect('stats', uri,
        #                controller=StatsController, action='set_ip_black_list',
        #                conditions=dict(method=['POST']))
        uri = path + '/black_list/'
        mapper.connect('stats', uri,
                       controller=StatsController, action='set_ip_black_list',
                       conditions=dict(method=['POST']))

        uri = path + '/parameter/'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_parameter',
                       conditions=dict(method=['POST']))

        ########

        usr_config = self.database()
        # create list objet sensor
        for sensor in self._list_name_mac_sensors:
            sensor_mac = usr_config["sensors_refence"][sensor]
            crypto = Cryptography()
            Sensor.sensors_list_map.append(Sensor(sensor, sensor_mac, self.__number_passwd,
                                                  crypto.Create_key(), crypto.Create_IV(),
                                                  self.__is_passwd, self.__passwd))

        ## list the created sensor objects
        for sensor in Sensor.sensors_list_map:
            print(sensor.get_sensor())

        for ip_address in self._primary_servers_ip + self._secondary_servers_ip:
            self._mapping_server_ip_mac_[ip_address] = None


        self.monitor_thread = hub.spawn(self.monitor)
        self.select_balance = True

    def database(self):
        self.datapaths = {}
        usr_config = _load_config_file()
        self.cookie_value = 0
        self._ip_origin = ""
        self._switch_mac_address = usr_config["service_mac"]
        self._switch_primary_ip = usr_config["service_ips"]["primary"]
        self._switch_secondary_ip = usr_config["service_ips"]["secondary"]
        self._primary_servers_ip = usr_config["server_ips"]["primary"]
        self._secondary_servers_ip = usr_config["server_ips"]["secondary"]
        self._mapping_client_ip_mac = dict()
        self._mapping_mac_port = dict()
        self._mapping_server_ip_mac_ = dict()
        self.__number_passwd = usr_config["number_password"]
        self._list_name_mac_sensors = usr_config["sensors"]
        self.__is_passwd = eval(usr_config["fixe_passwd"])
        self.__passwd = usr_config["passwd"]
        self.__timeout =  int(usr_config["timeout"])
        return usr_config

    def monitor(self):
        while True:
            hub.sleep(3)
            value_ipv4 = ""
            for datapath, match, cookie_id in self.datapaths.values():

                if match["ipv4_dst"] in StatsController.list_ip_deny and StatsController.list_ip_deny[
                    match["ipv4_dst"]] == True:
                    self.del_flows(datapath, cookie_id)
                    value_ipv4 = match["ipv4_dst"]
                elif match["ipv4_src"] in StatsController.list_ip_deny and StatsController.list_ip_deny[
                    match["ipv4_src"]] == True:
                    self.del_flows(datapath, cookie_id)
                    value_ipv4 = match["ipv4_src"]

            StatsController.list_ip_deny[value_ipv4] = False

    def del_flows(self, datapath, cookie=0):

        # re[self.cookie_value]
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        cookie_mask = 0
        if cookie:
            cookie_mask = 0xffffffffffffffff

        mod = parser.OFPFlowMod(
            datapath, cookie=cookie, cookie_mask=cookie_mask,
            table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        self._ip_origin = ""
        msg = ev.msg
        dp = msg.datapath

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        in_port = msg.match["in_port"]

        if eth.ethertype in (ether_types.ETH_TYPE_ARP, ether_types.ETH_TYPE_IP):
            self.__multi(dp, in_port, pkt, eth.ethertype, dp)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def pre_service_preparation(self, ev):

        datapath = ev.msg.datapath
        self.add_default_entry(datapath)
        self.send_arp_requests(datapath)

    def send_arp_requests(self, dp):
        for ip_address in self._secondary_servers_ip + self._primary_servers_ip:
            arp_body = arp.arp_ip(
                _QUERY,
                self._switch_mac_address, self._switch_secondary_ip,
                '00:00:00:00:00:00', ip_address
            )
            ethernet_head = ethernet.ethernet(
                src=self._switch_mac_address,
                dst="ff:ff:ff:ff:ff:ff",
                ethertype=ether.ETH_TYPE_ARP
            )

            n_packet = packet.Packet()
            n_packet.add_protocol(ethernet_head)
            n_packet.add_protocol(arp_body)
            n_packet.serialize()

            self.__send_single_packet(
                datapath=dp,
                out_port=dp.ofproto.OFPP_FLOOD,
                payload=n_packet
            )


    def __multi(self, datapath, in_port, pkt, type_hint, dp):
        self._ip_origin = ""
        ##################
        read_packet = packet.Packet(pkt) if not isinstance(pkt, packet.Packet) else pkt
        ethernet_inf = read_packet.get_protocol(ethernet.ethernet)
        if ipv4.ipv4 in read_packet:

            inf = read_packet.get_protocol(ipv4.ipv4)
            ip_src = inf.src
            ip_dst = inf.dst
            mac_src = ethernet_inf.src
            mac_dst = ethernet_inf.dst

        else:

            inf = read_packet.get_protocol(arp.arp)
            ip_src = inf.src_ip
            ip_dst = inf.dst_ip
            mac_src = inf.src_mac
            mac_dst = inf.dst_mac

        #####################################
        if ip_src not in (self._switch_primary_ip, self._switch_secondary_ip):
            self._mapping_mac_port[mac_src] = in_port
            if ip_src in self._mapping_server_ip_mac_:
                self._mapping_server_ip_mac_[ip_src] = mac_src
            else:
                self._mapping_client_ip_mac[ip_src] = mac_src
        ###########################################################
        if type_hint == ether_types.ETH_TYPE_ARP:
            if pkt.get_protocol(arp.arp).opcode == _QUERY:

                ##########################################
                arp_body = arp.arp_ip(
                    _RESPONSE,
                    self._switch_mac_address, ip_dst,
                    mac_src, ip_src
                )
                ethernet_head = ethernet.ethernet(
                    src=self._switch_mac_address,
                    dst=mac_src,
                    ethertype=ether.ETH_TYPE_ARP
                )

                r_packet = packet.Packet()
                r_packet.add_protocol(ethernet_head)
                r_packet.add_protocol(arp_body)
                r_packet.serialize()
                ##########################################
                dst_mac = mac_src
            else:
                return

        else:
            if ip_src in self._mapping_server_ip_mac_:
                if ip_dst not in (self._switch_primary_ip, self._switch_secondary_ip):
                    src_ip = self._switch_secondary_ip if ip_src in self._secondary_servers_ip else self._switch_primary_ip
                    dst_ip = ip_dst
                    dst_mac = self._mapping_client_ip_mac[dst_ip]
                else:
                    return
            else:

                ########################################
                service_type = "secondary" if ip_dst == self._switch_secondary_ip else "primary"
                server_ip = self.__get_service_type(ip_src, service_type=service_type)
                server_mac = self._mapping_server_ip_mac_[server_ip]

                client_to_server_match_obj = datapath.ofproto_parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether.ETH_TYPE_IP,
                    ipv4_src=ip_src,
                    ipv4_dst=ip_dst
                )
                client_to_server_action_obj = [
                    datapath.ofproto_parser.OFPActionSetField(eth_src=self._switch_mac_address),
                    datapath.ofproto_parser.OFPActionSetField(eth_dst=server_mac),
                    datapath.ofproto_parser.OFPActionSetField(ipv4_dst=server_ip),
                    datapath.ofproto_parser.OFPActionOutput(
                        self._mapping_mac_port[server_mac]
                    )
                ]

                client_mac = self._mapping_client_ip_mac[ip_src]
                server_to_client_match_obj = datapath.ofproto_parser.OFPMatch(
                    in_port=self._mapping_mac_port[server_mac],
                    eth_type=ether.ETH_TYPE_IP,
                    ipv4_src=server_ip,
                    ipv4_dst=ip_src
                )
                server_to_client_action_obj = [
                    datapath.ofproto_parser.OFPActionSetField(eth_src=self._switch_mac_address),
                    datapath.ofproto_parser.OFPActionSetField(eth_dst=client_mac),
                    datapath.ofproto_parser.OFPActionSetField(
                        ipv4_src=self._switch_secondary_ip if service_type == "secondary" else self._switch_primary_ip
                    ),
                    datapath.ofproto_parser.OFPActionSetField(ipv4_dst=ip_src),
                    datapath.ofproto_parser.OFPActionOutput(
                        self._mapping_mac_port[client_mac]
                    )
                ]


                # self.add_flow_entry(datapath, 1, client_to_server_match_obj, client_to_server_action_obj, timeout=1)
                self.add_flow_entry(datapath, 1, client_to_server_match_obj, client_to_server_action_obj, timeout=self.__timeout,
                                    set_datapath=True)

                # self.add_flow_entry(datapath, 1, server_to_client_match_obj, server_to_client_action_obj, timeout=1)
                self.add_flow_entry(datapath, 1, server_to_client_match_obj, server_to_client_action_obj, timeout=self.__timeout,
                                    set_datapath=True)

                #######################################

                src_ip = ip_src
                dst_ip = self.__get_service_type(ip_src,
                                                 service_type="secondary" if ip_dst == self._switch_secondary_ip else "primary")
                dst_mac = self._mapping_server_ip_mac_[dst_ip]

            src_mac = self._switch_mac_address

            ######################################3

            r_packet = self.spoofing(dst_ip, dst_mac, pkt, src_ip, src_mac)

            ##############################3

        self.__send_single_packet(
            datapath=datapath,
            out_port=self._mapping_mac_port[dst_mac],
            payload=r_packet
        )

    def spoofing(self, dst_ip, dst_mac, pkt, src_ip, src_mac):
        r_packet = packet.Packet()
        ethernet_head = ethernet.ethernet(
            src=src_mac,
            dst=dst_mac,
            ethertype=ether_types.ETH_TYPE_IP
        )
        if icmp.icmp in pkt:
            ipv4_payload = pkt.get_protocol(icmp.icmp)
        elif tcp.tcp in pkt:
            ipv4_payload = pkt.get_protocol(tcp.tcp)
        elif udp.udp in pkt:
            ipv4_payload = pkt.get_protocol(udp.udp)
        ethernet_payload = pkt.get_protocol(ipv4.ipv4)
        ethernet_payload.src = src_ip
        ethernet_payload.dst = dst_ip
        r_packet.add_protocol(ethernet_head)
        r_packet.add_protocol(ethernet_payload)
        r_packet.add_protocol(ipv4_payload)
        r_packet.serialize()
        return r_packet

    def __send_single_packet(self, *, datapath, out_port, payload):

        action = [
            datapath.ofproto_parser.OFPActionOutput(out_port)
        ]

        packet_out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=action,
            data=payload.data
        )
        datapath.send_msg(packet_out)

    def __get_service_type(self, ip_src, *, service_type):
        value_select = True
        if ip_src is not None:
            if ip_src not in StatsController.list_ip_deny:
                return random.choice(self._primary_servers_ip)
            else:
                return random.choice(self._secondary_servers_ip)

    def add_flow_entry(self, datapath, priority, match, actions, timeout=10, set_datapath=False):

        if set_datapath:
            # self.datapaths[datapath.id] = [datapath, match, actions, self.cookie_value]
            self.datapaths[self.cookie_value] = [datapath, match, self.cookie_value]

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            inst = [
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
            ]

            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                idle_timeout=timeout,
                instructions=inst,
                cookie=self.cookie_value
            )

            datapath.send_msg(mod)

        else:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            inst = [
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
            ]

            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                idle_timeout=timeout,
                instructions=inst,
                cookie=self.cookie_value
            )

            datapath.send_msg(mod)
        self.cookie_value += 1

    def add_default_entry(self, datapath) -> None:

        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                datapath.ofproto.OFPP_CONTROLLER,
                datapath.ofproto.OFPCML_NO_BUFFER
            )
        ]
        self.add_flow_entry(datapath, 0, match, actions, timeout=0)

    @set_ev_cls([ofp_event.EventOFPStatsReply,
                 ofp_event.EventOFPDescStatsReply,
                 ofp_event.EventOFPFlowStatsReply,
                 ofp_event.EventOFPAggregateStatsReply,
                 ofp_event.EventOFPTableStatsReply,
                 ofp_event.EventOFPTableFeaturesStatsReply,
                 ofp_event.EventOFPPortStatsReply,
                 ofp_event.EventOFPQueueStatsReply,
                 ofp_event.EventOFPQueueDescStatsReply,
                 ofp_event.EventOFPMeterStatsReply,
                 ofp_event.EventOFPMeterFeaturesStatsReply,
                 ofp_event.EventOFPMeterConfigStatsReply,
                 ofp_event.EventOFPGroupStatsReply,
                 ofp_event.EventOFPGroupFeaturesStatsReply,
                 ofp_event.EventOFPGroupDescStatsReply,
                 ofp_event.EventOFPPortDescStatsReply
                 ], MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION >= ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls([ofp_event.EventOFPSwitchFeatures,
                 ofp_event.EventOFPQueueGetConfigReply,
                 ofp_event.EventOFPRoleReply,
                 ], MAIN_DISPATCHER)
    def features_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        del self.waiters[dp.id][msg.xid]
        lock.set()


