# flake8: noqa: F405

from abc import ABCMeta, abstractmethod
from six import add_metaclass, string_types
from threading import Event, Thread

from scapy import sendrecv
from scapy.base_classes import Packet_metaclass
from scapy.compat import chb
from scapy.contrib.automotive.obd.obd import *
from scapy.packet import fuzz


@add_metaclass(ABCMeta)
class _ObdResponseGenerator:
    @abstractmethod
    def generate(self, req):
        pass

    @staticmethod
    def generate_packet_with_random_values(the_class):
        # Instantiates an instance of the class `the_class`
        # and fills its fields with random values
        if isinstance(the_class, string_types):
            payload = eval(the_class)()
        elif isinstance(the_class, Packet_metaclass):
            payload = the_class()
        else:
            raise TypeError("Only strings or Packet metaclasses are allowed.")

        payload = fuzz(payload)
        return payload

    @staticmethod
    def _generate_invalid(req):
        return OBD() / OBD_NR(request_service_id=req.service,
                              response_code='subFunctionNotSupported-'
                                            'InvalidFormat')

    @abstractmethod
    def is_valid(self, req):
        pass


# For all ID-based services except Service 02
class _ObdResponseGeneratorId(_ObdResponseGenerator):
    def generate(self, req):
        if not self.is_valid(req):
            return _ObdResponseGenerator._generate_invalid(req)

        id_field_name = req.payload.fields_desc[0].name
        ids = req.payload.getfieldval(id_field_name)

        full_payload = b''

        for one_id in ids:
            try:
                class_name = _ObdResponseGeneratorId.\
                    get_class_name(id_field_name, one_id)
                payload = _ObdResponseGenerator.\
                    generate_packet_with_random_values(class_name)
                full_payload += chb(one_id) + bytes(payload)
            except NameError:
                # appears when PID/IID etc. not supported
                # do not respond, OBD spec conform
                print("{0} {1:#04x} not supported".
                      format(id_field_name.upper(), one_id))

        if len(full_payload) == 0:
            # if no payload, do not generate/send an empty answer
            return None

        packet = OBD(chb(req.service + 0x40) + full_payload)
        return packet

    def is_valid(self, req):
        return len(req) >= 2

    @staticmethod
    def get_class_name(name, id_num):
        # example: name='pid', id_num=10
        #          result='OBD_PID0A'
        id_hex_string = '{:02X}'.format(id_num)
        return 'OBD_' + name.upper() + id_hex_string


# Service 02 requests have a slightly different structure.
# They have a frame_no, the other ID-based services do not.
# S2 IDs are stored in a list of packets, instead of a simple list
# of integers.
class _ObdResponseGeneratorIdService02(_ObdResponseGenerator):
    def generate(self, req):
        if not self.is_valid(req):
            return _ObdResponseGenerator._generate_invalid(req)

        full_payload = b''

        for r in req.payload.requests:
            id_field_name = r.fields_desc[0].name
            one_id = r.getfieldval(id_field_name)
            try:
                class_name = _ObdResponseGeneratorId.get_class_name(
                    id_field_name, one_id)
                payload = _ObdResponseGenerator.\
                    generate_packet_with_random_values(class_name)
                full_payload += bytes(r) + bytes(payload)
            except NameError:
                # appears when PID/IID etc. not supported
                # do not respond, OBD spec conform
                print("{0} {1:#04x} not supported".
                      format(id_field_name.upper(), one_id))

        if len(full_payload) == 0:
            # if no payload, do not generate/send an empty answer
            return None

        packet = OBD(chb(req.service + 0x40) + full_payload)
        return packet

    def is_valid(self, req):
        return len(req) >= 3


class _ObdResponseGeneratorDtc(_ObdResponseGenerator):
    def __init__(self, count):
        self.count = count

    def generate(self, req):
        if not self.is_valid(req):
            return _ObdResponseGenerator._generate_invalid(req)

        payload = _ObdResponseGenerator.\
            generate_packet_with_random_values(OBD_DTC)

        byte_string = chb(req.service + 0x40) + chb(self.count)
        for _ in range(self.count):
            byte_string += bytes(payload)

        packet = OBD(byte_string)
        return packet

    def is_valid(self, req):
        return len(req) == 1


class _ObdResponseGeneratorClearDtc(_ObdResponseGenerator):
    def generate(self, req):
        if not self.is_valid(req):
            return _ObdResponseGenerator._generate_invalid(req)
        packet = OBD() / OBD_S04_PR()
        return packet

    def is_valid(self, req):
        return len(req) == 1


class _ObdResponseGeneratorNotSupported(_ObdResponseGenerator):
    def generate(self, req):
        packet = OBD() / OBD_NR(request_service_id=req.service,
                                response_code='serviceNotSupported')
        return packet

    def is_valid(self, req):
        return True


class ObdSimulator(Thread):
    def __init__(self, main_socket, broadcast_socket,
                 dtc_count_responses=1, verbose=False):
        """

        :param main_socket: Defines the object of the socket to send
                            and receive packets.
        :param broadcast_socket: Defines the object of the broadcast socket.
                                 Listen-only, responds with the main_socket.
                                 `None` to disable broadcast capabilities.
        :param dtc_count_responses: Defines the number of DTCs to respond with
               when a "Read DTCs request" is received
        :param verbose: Defines if the server should output what is happening.
        """
        Thread.__init__(self)
        dtc_generator = _ObdResponseGeneratorDtc(dtc_count_responses)
        clear_dtc_generator = _ObdResponseGeneratorClearDtc()
        id_generator = _ObdResponseGeneratorId()
        id_s2_generator = _ObdResponseGeneratorIdService02()

        self.verbose = verbose

        # main socket is for receiving and reading
        self.main_socket = main_socket

        self.sockets = [self.main_socket]

        # broadcast socket is for reading only,
        # received packets will be answered by the main socket
        if broadcast_socket is not None:
            self.sockets.append(broadcast_socket)

        self.dispatch_dic = {
            1: id_generator,
            2: id_s2_generator,
            3: dtc_generator,
            4: clear_dtc_generator,
            6: id_generator,
            7: dtc_generator,
            8: id_generator,
            9: id_generator,
            10: dtc_generator
        }

        self.not_supported = _ObdResponseGeneratorNotSupported()

        self._stopped = Event()

    def process_request(self, req):
        if self._stopped.is_set():
            return

        if self.verbose:
            print("Request:")
            req.show()

        # Dispatcher
        generator = self.dispatch_dic.get(req.service, self.not_supported)
        if self.verbose:
            if isinstance(generator, _ObdResponseGeneratorNotSupported):
                print("Received OBD packet with unsupported service")

            if not generator.is_valid(req):
                print("Received an invalid OBD packet")

        packet = generator.generate(req)

        if self.verbose and packet is not None:
            print("Response:")
            packet.show()

        if packet is not None:
            self.main_socket.send(packet)

    def run(self):
        while not self._stopped.is_set():
            sendrecv.sniff(opened_socket=self.sockets,
                           timeout=1,
                           store=False,
                           prn=self.process_request)

    def stop(self):
        self._stopped.set()
