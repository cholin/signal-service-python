import asyncio

from signal_protocol_python import SignalProtocol
from xcoder import Encoder, Decoder
from wire import WebAPI


class Messenger:
    def __init__(self, number, password):
        uri = 'sqlite:/{}.db'.format(int(number))
        self.protocol = SignalProtocol(number.encode(), uri)
        self.protocol.number = number
        self.protocol.password = password
        self.message_queue_in = asyncio.Queue()

        loop = asyncio.get_event_loop()
        loop.create_task(self.receive())

        self.decoder = Decoder(self.message_queue_in, self.protocol)

        self.api  = WebAPI(number, password)
        self.encoder = Encoder(self.protocol, self.api)
    
    async def register(self):
        await self.api.register(self.protocol.number, self.protocol.password)
    
    async def register_keys(self):
        # generate
        self.protocol.generate_signed_pre_key()
        list(self.protocol.generate_pre_keys())

        # store
        keys = self.protocol.get_public_keys()
        await self.api.register_keys(keys)
    
    @property
    def access_key(self):
        """
        Derive access_key from profile_key
        
        Encrypting zeros through AES+GCM with profile_key and fixed nonce
        """
        from Crypto.Cipher import AES
        cipher = AES.new(self.profile_key, AES.MODE_GCM, nonce=12*b'0')
        return cipher.encrypt_and_digest(16*b'0')[0]

    async def confirm(self, verification_code):
        import secrets
        reg_id = self.protocol.registration_id
        self.profile_key = secrets.token_bytes(32)
        await self.api.confirm(reg_id, self.access_key, verification_code)
        await asyncio.sleep(1)
        await self.register_keys()
    
    async def receive(self):
        while True:
            address, message = await self.message_queue_in.get()
            print("Echoing Message", address, message)
            await self.send(address, message)
    
    async def refresh_keys(self):
        if await self.api.keys() > 10:
            print("enough keys available")
            return
        await self.register_keys()

    async def send(self, address, message):
        session = self.protocol.session(*address)
        if not session.initialized:
            await self.new_session(*address)
        await self.encoder.send(address, message)
    
    async def new_session(self, number, device_id):
        from signal_protocol_python.curve import EcPublicKey
        from signal_protocol_python.keys import RatchetIdentityKeyPair
        from signal_protocol_python.buffer import Buffer

        ctx = self.protocol.ctx
        data = await self.api.get_public_keys_for_user(number, device_id)
        identity_pub_key = EcPublicKey.decode_point(ctx, Buffer.fromb64(data['identityKey']))
        
        print(data)
        device_data = next(device for device in data['devices'] if device['deviceId'] == device_id)
        reg_id = int(device_data['registrationId'])
        signed_pub_pre_key = EcPublicKey.decode_point(ctx, Buffer.fromb64(device_data['signedPreKey']['publicKey']), device_data['signedPreKey']['keyId'])
        signed_pub_pre_key.signature = Buffer.fromb64(device_data['signedPreKey']['signature'])
        ephemeral_pub_key = EcPublicKey.decode_point(ctx, Buffer.fromb64(device_data['preKey']['publicKey']), device_data['preKey']['keyId'])

        print("new session")
        session = self.protocol.session(number, device_id)
        session.process(reg_id, identity_pub_key, signed_pub_pre_key, ephemeral_pub_key)