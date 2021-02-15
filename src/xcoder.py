from signal_protocol_python import SignalProtocol, lib
from signal_protocol_python.buffer import Buffer
from base64 import b64encode
from wire import WebSocket
from time import time

import asyncio
import math
import ssl

import SignalService_pb2


class Encoder:
    def __init__(self, protocol, api):
        self.protocol = protocol
        self.api = api
    
    @staticmethod
    def pad(serialized):
        # Add terminator at end
        terminated = bytearray(serialized)
        terminated.append(0x80)

        # for privacy reasons pad to fixed chunk sizes (multiple of 160)
        CHUNK_SIZE = 160
        terminated_len = len(terminated)
        padded_len = math.ceil(terminated_len/CHUNK_SIZE)*CHUNK_SIZE
        return bytes(terminated + b'\0'*(padded_len-terminated_len))
    
    async def encode(self, address, msg):
        content = SignalService_pb2.Content()
        content.dataMessage.body = msg
        content.dataMessage.timestamp = int(time())
        data = content.SerializeToString()

        padded = self.pad(data)
        session = self.protocol.session(*address)
        ciphertext = session.encrypt(padded)
        
        if ciphertext.type == lib.CIPHERTEXT_SIGNAL_TYPE:
            type_ = SignalService_pb2.Envelope.CIPHERTEXT
        else:
            type_ = SignalService_pb2.Envelope.PREKEY_BUNDLE

        _, device_id = address
        return {
            'type': type_,
            'destinationDeviceId': device_id,
            'destinationRegistrationId': session.cipher.remote_registstration_id,
            'content': ciphertext.serialize().b64().decode(),
        }
    
    async def send(self, address, msg):
        encoded = await self.encode(address, msg)
        number, _ = address
        return await self.api.send_message(number, encoded)




class Decoder:
    def __init__(self, queue_out, protocol):
        self.queue_out = queue_out
        self.protocol = protocol
        self.queue_in = asyncio.Queue()

        loop = asyncio.get_event_loop()
        loop.create_task(self.decode())
    
        self.receiver = WebSocket(self.queue_in, protocol.number, protocol.password)

    @staticmethod
    def parse_content(data):
        content = SignalService_pb2.Content()
        content.ParseFromString(data)
        return content.dataMessage.body

    @staticmethod
    def unpad(padded):
        # TODO: assert len(padded) % 160 == 0 (actuall it is 159)
        encoded = padded.rstrip(b'\0')
        assert encoded[-1] == 0x80
        return encoded[:-1]

    async def decode(self):
        while True:
            data = await self.queue_in.get()

            envelope = SignalService_pb2.Envelope()
            envelope.ParseFromString(data)

            print('\n\ndecode', envelope)
            if envelope.type == SignalService_pb2.Envelope.CIPHERTEXT:
                msg_type =  lib.CIPHERTEXT_SIGNAL_TYPE
            elif envelope.type == SignalService_pb2.Envelope.PREKEY_BUNDLE:
                msg_type =  lib.CIPHERTEXT_PREKEY_TYPE
            else:
                print("ignoring", envelope)
                continue

            serialized = (msg_type, Buffer.create(envelope.content))
            address = (envelope.sourceE164.encode(), envelope.sourceDevice)
            decrypted = self.protocol.session(*address).decrypt(*serialized).bin()
            
            unpadded = self.unpad(decrypted)
            plaintext = self.parse_content(unpadded)
            await self.queue_out.put((address, plaintext))

