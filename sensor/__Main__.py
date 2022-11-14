
import pickle5 as pickle
from builtins import print
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from os import path
import os
import sys
import subprocess

from Cryptodome.Cipher import AES
from base64 import b64encode
from base64 import b64decode

import socket
## rest API request
import requests

## Mac Address
from getmac import get_mac_address as gma

##Pass arguments for applications
import argparse

headers = {
    'Content-Type': 'application/json',
}

class sensor:

    def __init__(self) -> None:
        self.ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.id_sensor = 0
        self.key = ""
        self.IV  = ""
        self.dpid = ""
        self.__counter_packet = 0
        self.hostname = socket.gethostname()
        self.list_ip_black_list = []
        self.loop = True
        # self.model = self.create_model("SVM")
        options = self.args()
        self.model = self.create_model(options.model)
        self.interfaceLan = options.interface
        self.interface_controller = options.interface_controller
        self.server_ip = options.sdn
        self.server_web = options.webserver
        self.Is_encrypted = True
        if options.crypt == "False":
            self.Is_encrypted = False
        self.login = options.login
        ##if set linecount
        if options.linecount:
            self.linecount = options.linecount
        else:
            self.linecount = 600
        ##if cryptgrapy
        if  options.crypt:
            self.conect_server(self.login, options.password, self.interface_controller )
        self.flow_file = open(self.ROOT_DIR + "/assets/files/logs/" + "flow_file.txt", "w+")

    def get_counter_packet(self):
        return self.__counter_packet

    def add_counter_packet(self):
        self.__counter_packet += 1

    ######################## block encryption################################################333

    @staticmethod
    def Encrypt(vkey, viv, text_plane):
        iv = bytes(viv, 'UTF-8')
        key = bytes(vkey, 'UTF-8')
        text = bytes(text_plane, 'utf-8')
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ct_bytes = cipher.encrypt(text)
        return b64encode(ct_bytes).decode('utf-8')

    @staticmethod
    def Decrypt(vkey, viv, encoded_message):
        iv = bytes(viv, 'UTF-8')
        key = bytes(vkey, 'UTF-8')
        ct = b64decode(encoded_message)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        pt = cipher.decrypt(ct)
        return pt.decode('utf-8')

    #requests keys for encryption
    def conect_server(self, name_sensor,password_sensor, interface):
        mac_address = gma(interface)
        data = {'sensor': name_sensor,
                'senha': password_sensor,
                'mac_address': mac_address,
                'host_name': self.hostname}
        url_post = 'http://' + self.server_ip + ':8080/stats/parameter/'
        response = requests.post(url_post, headers=headers, json=data)
        result = response.json()
        if (result['access'] == False):
            print('access denied')
            sys.exit()
        else:
            self.id_sensor = result['id']
            self.dpid = result['dpid']
            self.key = result['key']
            self.IV = result['IV']

            print("Id Sensor -", self.id_sensor)
            print("Id DPID -", self.dpid)
            print("KEY -", self.key )
            print("Init Vector  -", self.IV )
            print("Count Number -", self.linecount)

    ######################## block encryption################################################333
    #
    # Add IP on the list detected malicions IP
    #
    def add_ip_black_list(self, ip):
        if ip in self.list_ip_black_list:
            return False
        else:
            self.list_ip_black_list.append(ip)
            return True
    #
    # Main method that will perform the tests
    #
    def send_ip_flow_detect_controller(self, ip):
        mac_address = gma(self.interface_controller)
        if self.Is_encrypted:

            #A = sensor_name
            #B = mac_address
            #C = ip
            #D = counter_packet
            #E = host_name
            #F = crypt
            #G = access

            data = {'id' :   self.id_sensor,
                    'A': self.Encrypt(self.key, self.IV ,self.login),
                    'B': self.Encrypt(self.key, self.IV ,mac_address),
                    'C': self.Encrypt(self.key, self.IV ,ip),
                    'D': self.Encrypt(self.key, self.IV, str(self.__counter_packet)),
                    'E' : self.Encrypt(self.key, self.IV, self.hostname),
                    'F': self.Encrypt(self.key, self.IV,str(True))
                    }

        else:
            data = {'id': self.id_sensor,
                    'A': self.login,
                    'B': mac_address,
                    'C': ip,
                    'D': self.__counter_packet,
                    'F': False }
        self.get_counter_packet()
        url_post = 'http://' + self.server_ip + ':8080/stats/black_list/'
        response = requests.post(url_post, headers=headers, json=data)
        result = response.json()

        if (bool(self.Decrypt(self.key, self.IV, int(result['G']))) == False):
            print('access denied')
            sys.exit()
        else:
            if self.Is_encrypted:
                if self.Decrypt(self.key, self.IV, int(result['D'])) ==   self.__counter_packet:
                    print("successful connection ")
                    self.add_counter_packet()
                else:
                    print('access denied')
                    sys.exit()
            else:
                if result['D'] == self.__counter_packet:
                    print("successful connection ")
                    self.add_counter_packet()
                else:
                    print('access denied')
                    sys.exit()


    def main(self):
        while self.loop:
            try:
                self.capture_packet_network()
                self.teste_network_data()
                os.remove(self.ROOT_DIR + "/assets/files/pcap/out.pcap")
            except ValueError as exception:
                if exception.args[0] == "short":
                    print("Insufficient data flow")

    ##################### block code network ##################################################
    #
    #  Capture pcap packet
    #
    def capture_packet_network(self):
        print("Start data capture")
        pcap_file = open(self.ROOT_DIR + "/assets/files/pcap/out.pcap", "w", encoding="ISO-8859-1")
        pcap_list = self.proc_capture_pcap(self.interfaceLan, self.linecount)
        pcap_file.writelines(pcap_list)
        pcap_file.close()
        self.proc_run_cic()

    #
    # Process for packet capture
    #

    def proc_capture_pcap(self, interface: str, line_count: int = 5000):
        pcap = ["tcpdump", "-i", interface, "-s", "65535", "-w", "-"]
        process = subprocess.Popen(
            pcap,
            stdout=subprocess.PIPE,
            universal_newlines=False,
            encoding="ISO-8859-1",
        )
        ctr = 0
        list = []
        while ctr < line_count:
            ln = process.stdout.readline()
            list.append(ln)
            ctr += 1
        process.stdout.close()
        exit_status = process.wait()
        if exit_status:
            raise subprocess.CalledProcessError(exit_status, pcap)
        return list

        #
        # Running cicflowmeter
        #
    def proc_run_cic(self):
        cic_cmd = ["sh", "cfm", self.ROOT_DIR + "/assets/files/pcap", self.ROOT_DIR + "/files/flowOut"]
        cic_process = subprocess.Popen(
            cic_cmd,
            cwd=self.ROOT_DIR + "/assets/files/CICFlowMeter/assets",
            stdout=subprocess.DEVNULL,
        )
        status = cic_process.wait()
        if status:
            raise subprocess.CalledProcessError(status, cic_cmd)

    ##################### block code network ##################################################

    ################### block code args ##################################3
    def args(self):
        parse =  self.parseOptions()
        args = parse.parse_args()
        return args

    ##create  options for parameter applications
    def parseOptions(self):

        # set parameter
        arg = argparse.ArgumentParser(
            description="Applications to detect attack DDOS in SDN system and other")
        # Set IP device for mitigation attack, SDN ou Other.
        arg.add_argument(
            "--sdn",
            action="store",
            required=False,
            dest="sdn",
            help="Set IP for destination device or  IP SDN Controller",
            default=None,
        )

        # Option for cryptography
        arg.add_argument(
            "-c",
            action="store",
            required=False,
            dest="crypt",
            help="Select options criptography communications.",
            default="True",
        )

        # Set LAN interface for collect flow
        arg.add_argument(
            "--interface",
            action="store",
            required=True,
            dest="interface",
            help="Select Lan interface for collect flow",
            default="enp0s8",
        )

        # Set LAN interface for server controller
        arg.add_argument(
            "--interface_controller",
            action="store",
            required=True,
            dest="interface_controller",
            help="Select Lan interface for connect server controller",
            default="enp0s3",
        )
        # Set login for cryptography communications
        arg.add_argument(
            "-l",
            action="store",
            required=False,
            dest="login",
            help="Set nome sensor defined in SDN Controller for cryptography communications.",
            default= None,
        )
        # Set password for cryptography communications
        arg.add_argument(
            "-p",
            action="store",
            required=False,
            dest="password",
            help="Set password for cryptography communications.",
            default=None,
        )
        # Set algoritmo used in classification Machine Leaning
        arg.add_argument(
            "--model",
            action="store",
            required=False,
            dest="model",
            type=str,
            nargs='*',
            help="select machine learning algorithm, 'RF', 'SVM', 'GNB', 'NN', 'SC'",
            default="RF",
        )
        # Set ip server web for monitoring
        arg.add_argument(
            "--webserver",
            action="store",
            required=False,
            dest="webserver",
            help="Set ip server web for monitoring  ",
            default=None,
        )

        # Set the number of lines collected by the sensor
        arg.add_argument(
            "--linecount",
            action="store",
            required=False,
            dest="linecount",
            help="Set the number of lines collected by the sensor",
            default=None,
        )




        return arg
    ################### block code args ##################################3

    ##################### block code Machine Learning ##################################################
    #
    # Transform pcap file
    #

    def tranform_data(self):
        uri = self.ROOT_DIR + "/assets/files/flowOut/out.pcap_Flow.csv"
        dataframe = self.load_dataset(uri)
        metadata = pd.DataFrame()
        metadata["from_ip"] = dataframe["Src IP"]
        metadata["to_ip"] = dataframe["Dst IP"]
        metadata["protocol"] = dataframe["Protocol"]
        metadata["from_port"] = dataframe["Src Port"]
        metadata["to_port"] = dataframe["Dst Port"]
        self.pre_processing(dataframe)
        x_train, x_test, _, _ = self.train_test(dataframe)
        data = np.concatenate((x_test, x_train))
        return {"data": data, "metadata": metadata}

    #
    # Teste flow
    #

    def teste_network_data(self):
        try:
            flow_data = self.tranform_data()
        except ValueError:
            raise ValueError("short")
        flow_features = flow_data["data"]
        metadata = flow_data["metadata"]
        predictions = self.model[1].predict(flow_features)
        for row, prediction in zip(metadata.values, predictions):
            from_ip, to_ip, proto, from_port, to_port = row
            if prediction:
                if self.server_web == to_ip:
                    if self.add_ip_black_list(from_ip):
                        self.send_ip_flow_detect_controller(from_ip)
                break
    #
    #validates malicious flow
    #
    def analise_packet_flow(self, flow_info):

        metadata, predictions = flow_info
        for row, prediction in zip(metadata.values, predictions):
            from_ip, to_ip, proto, from_port, to_port = row
            if prediction:
                if self.server_web == to_ip:
                    if self.add_ip_black_list(from_ip):
                        self.send_ip_flow_detect_controller(from_ip)

        #
        # Checks if there is already a trained model,
        # if not, create the model and serialize
        #         #
    def create_model(self,_model):

        if 'RF' in _model:
            if path.exists(self.ROOT_DIR + "/assets/model/" + "RF_model.pck"):
                model_file = open(self.ROOT_DIR + "/assets/model/RF_model.pck", "rb")
                model = pickle.load(model_file)
                print("********* Selected Model    **********")
                print(model[0])
                print("**************************************")
                model_file.close()
                return model
            else:
                type_ml = "RF"
                from sklearn.ensemble import RandomForestClassifier
                model_file = open(self.ROOT_DIR + "/assets/model/RF_model.pck", "wb")
                model = RandomForestClassifier(max_depth=2, random_state=0)
                dataframe = self.pre_processing(self.load_dataset(uri))
                x_train, x_test, y_train, y_test = self.train_test(dataframe)
                model.fit(x_train, y_train)
                rf = [type_ml, model]
                pickle.dump(rf, model_file)
                model_file.close()
                print("Random Forest - Fim")
        if 'GNB' in _model:
            if path.exists(self.ROOT_DIR + "/assets/model/" + "GNB_model.pck"):
                model_file = open(self.ROOT_DIR + "/assets/model/GNB_model.pck", "rb")
                model = pickle.load(model_file)
                print("********* Selected Model    **********")
                print(model[0])
                print("**************************************")
                model_file.close()
                return model

            else:
                type_ml = "GNB"
                from sklearn.naive_bayes import GaussianNB
                model_file = open(self.ROOT_DIR + "/assets/model/GNB_model.pck", "wb")
                model = GaussianNB()
                dataframe = self.pre_processing(self.load_dataset(uri))
                x_train, x_test, y_train, y_test = self.train_test(dataframe)
                model.fit(x_train, y_train)
                gnb = [type_ml, model]
                pickle.dump(gnb, model_file)
                model_file.close()

        if 'SVM' in _model:
            if path.exists(self.ROOT_DIR + "/assets/model/SVM_model.pck"):
                model_file = open(self.ROOT_DIR + "/assets/model/SVM_model.pck", "rb")
                model = pickle.load(model_file)
                print("********* Selected Model    **********")
                print(model[0])
                print("**************************************")
                model_file.close()
                return model
            else:
                type_ml = "SVM"
                from sklearn.svm import LinearSVC
                model_file = open(self.ROOT_DIR + "/assets/model/SVM_model.pck", "wb")
                model = LinearSVC(random_state=1234, max_iter=100)
                dataframe = self.pre_processing(self.load_dataset(uri))
                x_train, x_test, y_train, y_test = self.train_test(dataframe)
                model.fit(x_train, y_train)
                svm = [type_ml, model]
                pickle.dump(svm, model_file)
                model_file.close()

        if 'NN' in _model:
            if path.exists(self.ROOT_DIR + "/assets/model/NN_model.pck"):
                model_file = open(self.ROOT_DIR + "/model/NN_model.pck", "rb")
                model = pickle.load(model_file)
                print("********* Selected Model    **********")
                print(model[0])
                print("**************************************")
                model_file.close()
                return model
            else:
                type_ml = "NN"
                from sklearn.neural_network import MLPClassifier
                model_file = open(self.ROOT_DIR + "/assets/model/NN_model.pck", "wb")
                model = MLPClassifier(hidden_layer_sizes=(10, 10, 10), max_iter=10, random_state=0)
                dataframe = self.pre_processing(self.load_dataset(uri))
                x_train, x_test, y_train, y_test = self.train_test(dataframe)
                model.fit(x_train, y_train)
                nn = [type_ml, model]
                pickle.dump(nn, model_file)
                model_file.close()

        if 'SC' in _model:
            if path.exists(self.ROOT_DIR + "/assets/model/StackingClassifier_model.pck"):
                model_file = open(self.ROOT_DIR + "/assets/model/StackingClassifier_model.pck", "rb")
                model = pickle.load(model_file)
                print("********* Selected Model    **********")
                print(model[0])
                print("**************************************")
                model_file.close()
                return model

            else:
                type_ml = "ALL"
                from sklearn.ensemble import StackingClassifier
                from sklearn.linear_model import LogisticRegression
                model_file = open(self.ROOT_DIR + "/assets/model/RF_model.pck", "rb")
                model = pickle.load(model_file)
                model_rf = model[1]
                print(model_rf)
                model_file.close()
                model_file = open(self.ROOT_DIR + "/assets/model/GNB_model.pck", "rb")
                model = pickle.load(model_file)
                model_gnb = model[1]
                print(model_gnb)
                print(model_gnb)
                model_file.close()
                model_file = open(self.ROOT_DIR + "/assets/model/SVM_model.pck", "rb")
                model = pickle.load(model_file)
                model_svm = model[1]
                print(model_svm)
                model_file.close()
                model_file = open(self.ROOT_DIR + "/assets/model/NN_model.pck", "rb")
                model = pickle.load(model_file)
                model_nn = model[1]
                print(model_nn)
                model_file.close()

                estimators = [('rf', model_rf),
                              ('svm', model_svm),
                              ('gnb', model_gnb),
                              ('nn', model_nn)]
                train_test_file = open(self.ROOT_DIR + "/assets/model/StackingClassifier_model.pck", "wb")
                model_all = StackingClassifier(estimators=estimators, final_estimator=LogisticRegression())
                dataframe = self.pre_processing(self.load_dataset(uri))
                x_train, x_test, y_train, y_test = self.train_test(dataframe)
                model_all.fit(x_train, y_train)
                all = [type_ml, model_all]
                pickle.dump(all, train_test_file)
                train_test_file.close()

    #
    # Split data traine and test
    #
    def train_test(self, dataframe):
        x_data = []
        y_data = []

        for row in dataframe.values:
            x_data.append(row[:-1])
            y_data.append(row[-1])

        x_train, x_test, y_train, y_test = train_test_split(x_data, y_data, random_state=1, test_size=0.10)
        return np.array(x_train), np.array(x_test), np.array(y_train), np.array(y_test)

    #
    #Load config dataset
    #
    def load_dataset(self, uri):

        if (uri != self.ROOT_DIR + "/assets/dataset/dtddos.csv"):
            input_df = pd.read_csv(self.ROOT_DIR + "/assets/files/flowOut/out.pcap_Flow.csv")
            return input_df
        chunksize = 1000
        list_of_dataframes = []
        for df in pd.read_csv(uri, chunksize=chunksize, nrows=6472647, index_col=0, low_memory=False):
            list_of_dataframes.append(df)
        ddos_dados = pd.concat(list_of_dataframes)
        features = ddos_dados.columns
        list_of_dataframes = []
        for df in pd.read_csv(uri, chunksize=chunksize, nrows=6321980, index_col=0, skiprows=6472647,
                              low_memory=False):
            list_of_dataframes.append(df)
        benign_dados = pd.concat(list_of_dataframes)
        benign_dados.columns = features
        dataframe = pd.concat([ddos_dados, benign_dados])
        return dataframe

    #
    # pre-processed the dataframe
    # delete unused fields
    #
    def pre_processing(self, dataframe):
        dataframe.drop(["Flow ID", "Timestamp", "Src IP", "Dst IP", "Flow Byts/s", "Flow Pkts/s"],
                       inplace=True, axis=1, )
        dataframe["Label"] = dataframe["Label"].apply(lambda x: 1 if x == "ddos" else 0)
        for col in dataframe.columns:
            dataframe[col] = np.nan_to_num(dataframe[col])
        return dataframe

    ##################### block code Machine Learning ##################################################
def init():
    sensors = sensor()
    sensors.main()
if __name__ == "__main__":
    init()


