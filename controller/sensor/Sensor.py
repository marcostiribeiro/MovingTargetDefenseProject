import random
import string


class Sensor:
    conter_id = 0
    sensors_list_map = []
    def __init__(self, sensor_nome, sensor_mac, number_caracter, sensor_key, sensor_iv,is_passwd,passwd):
        self.__sensor_id = Sensor.conter_id
        self.__sensor_nome = sensor_nome
        self.__sensor_mac = sensor_mac
        self.__is_passwd = is_passwd
        self.__passwd = passwd
        self.__sensor_password = self.Generate_password(number_caracter)
        self.__sensor_key = sensor_key
        self.__sensor_iv = sensor_iv
        self.__connected = False
        self.__conter_packet = 0
        self.__hostname = ""
        Sensor.conter_id += 1

    @staticmethod
    def request_sensors(_sensor, _passwd, _mac_address,host_name):
        key, iv,id = "", "", ""
        for sensor in Sensor.sensors_list_map:
            if (sensor.get_sensor_nome() == _sensor and sensor.get_sensor_password() == _passwd and sensor.get_sensor_mac() == _mac_address and not sensor.get_connected()):
                key = sensor.get_sensor_key()
                iv = sensor.get_sensor_iv()
                id = sensor.get_sensor_id()
                sensor.set_connected(True)
                sensor.set_hostname(host_name)
        return key, iv, id


    def validate_sensor(self,sensor_name,mac_address,counter_packet,host_name):
        if(self.__sensor_nome == sensor_name and self.__sensor_mac == mac_address and
                self.__conter_packet == counter_packet  and self.__hostname == host_name):
            return True
        else:
            return False


    def get_hostname(self):
        return self.__hostname

    def set_hostname(self, _hostname):
        self.__hostname = _hostname

    def get_sensor_id(self):
        return self.__sensor_id

    def add_conter(self):
        self.__conter_packet += 1

    def get_connected(self):
        return self.__connected

    def set_connected(self, _connected):
        self.__connected = _connected


    def get_sensor_nome(self):
        return self.__sensor_nome

    def set_sensor_nome(self, _sensor_nome):
        self.__sensor_nome = _sensor_nome


    def get_sensor_mac(self):
        return self.__sensor_mac

    def set_sensor_mac(self, _sensor_mac):
        self.__sensor_mac = _sensor_mac


    def get_sensor_password(self):
        return self.__sensor_password

    def set_sensor_password(self, _sensor_password):
        self.__sensor_password = _sensor_password


    def get_sensor_key(self):
        return self.__sensor_key

    def set__sensor_key(self, _sensor_key):
        self.__sensor_key = _sensor_key



    def get_sensor_iv(self):
        return self.__sensor_iv

    def set_sensor_iv(self, _sensor_iv):
        self.__sensor_iv = _sensor_iv

    def get_sensor_by_id(id):
        for sensor in Sensor.sensors_list_map:
            if sensor.get_sensor_id() == id:
                return sensor
        return None

    def Generate_password(self, number_caracter):

        if bool(self.__is_passwd):
            return self.__passwd
        else:
            letters = string.ascii_lowercase
            return ''.join(random.choice(letters) for i in range(number_caracter))

    def get_sensor(self):
        return 'ID Sensor >> {0} Sensor Name >> {1} - MAC Address >> {2} - Password >> {3} - Sensor Key >> {4} - Sensor IV >> {5}'.format(self.__sensor_id,
            self.__sensor_nome, self.__sensor_mac, self.__sensor_password, self.__sensor_key, self.__sensor_iv)
