import logging
import asyncio
import aiohttp
import pathlib
import ssl
import os

from utils import Timer
from functools import partial
from time import time
from base64 import b64encode

import SubProtocol_pb2

logger = logging.getLogger('pysignal.wire')

URL = "https://textsecure-service-staging.whispersystems.org"

class WebAPI:

    def __init__(self, number, password):
        self.auth = aiohttp.BasicAuth(number, password)

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        staging_pem = pathlib.Path(__file__).with_name("textsecure-service-staging.whispersystems.org.pem")
        ssl_context.load_verify_locations(staging_pem)
        self.ssl_context = ssl_context
    
    async def _request(self, method_name, url, *args, **kwargs):
        token = os.environ.get('TOKEN')
        # only append token if we create or confirm an account
        if token and all(s in url for s in ['v1', 'accounts', 'code']):
            url += f'?captcha={token}''

        kwargs['ssl'] =  self.ssl_context

        logger.debug(f'{method_name} {url} {kwargs["json"] if "json" in kwargs else ""}')

        async with aiohttp.ClientSession(auth=self.auth) as session:
            method = getattr(session, method_name)
            async with method(url, *args, **kwargs) as resp:
                errors = {
                    '': "Unknown Error",
                    400: "badly formatted number",
                    401: "badly formatted basic_auth",
                    402: "captcha error",
                    403: "incorrect verification_code",
                    413: "rate limit exceeded",
                    415: "invalid transport",
                    417: "number already registered"
                }

                if not resp.ok:
                    status_code = resp.status
                    error_code = status_code if status_code in errors else ''
                    raise RuntimeError(f'{status_code} - {errors[error_code]}')

                if resp.content_type == 'application/json':
                    return await resp.json()
                return True

    async def whoami(self):
        url = f'{URL}/v1/accounts/whoami'
        return await self._request('get', url)
    
    async def set_name(self, name):
        url = f'{URL}/v1/accounts/name'
        json = json={'deviceName':name}
        return await self._request('put', url, json=json)

    async def devices(self):
        url = f'{URL}/v1/devices'
        return await self._request('get', url)
    
    async def get_profile(self, user):
        url = f'{URL}/v1/profile/{user}'
        return await self._request('get', url)
    
    async def keys(self):
        url = f'{URL}/v2/keys'
        data =  await self._request('get', url)
        return int(data['count'])
    
    async def register(self, number, password, transport='sms'):
        # https://github.com/AsamK/signal-cli/wiki/Registration-with-captcha
        url = f'{URL}/v1/accounts/{transport}/code/{number}'
        await self._request('get', url)
    
    async def confirm(self, registration_id, access_key, verification_code):
        data = {
            'supportsSms' : False,
            'fetchesMessages': True,
            'registrationId': registration_id,
            'unidentifiedAccessKey': b64encode(access_key).decode(),
            'unrestrictedUnidentifiedAccess': False,
            'capabilities': {'uuid': True}
        }
        url = f'{URL}/v1/accounts/code/{verification_code}'
        await self._request('put', url, json=data)

    async def register_keys(self, keys):
        url = f'{URL}/v2/keys'
        return await self._request('put', url, json=keys)

    async def get_public_keys_for_user(self, number, device_id):
        url=f'{URL}/v2/keys/{number.decode()}/{device_id}'
        return await self._request('get', url)

    async def send_message(self, number, message):
        await self.send_messages(number, [message])

    async def send_messages(self, number, messages):
        if not isinstance(messages, list):
            raise ValueError("messages is not a list")

        data = {
            'messages': messages,
            'timestamp': int(time())
        }
        logger.info(f'sending to {number}: {data}')
        url=f'{URL}/v1/messages/{number.decode()}'
        return await self._request('put', url, json=data)



class WebSocket:
    KEEP_ALIVE_TIMEOUT = 55   # every 55 seconds send a keep-alive pkg

    def __init__(self, queue_in, login, password):
        self.queue_in = queue_in
        self.queue_out = asyncio.Queue()
        self.login = login
        self.password = password

        self.keep_alive_timer = Timer(self.KEEP_ALIVE_TIMEOUT, self.keep_alive_timeout)
        
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        staging_pem = pathlib.Path(__file__).with_name("textsecure-service-staging.whispersystems.org.pem")
        ssl_context.load_verify_locations(staging_pem)
        self.ssl_context = ssl_context

        self._task = asyncio.get_event_loop().create_task(self.connect())

    async def ack(self, request_id):
        msg = SubProtocol_pb2.WebSocketMessage()
        msg.type = SubProtocol_pb2.WebSocketMessage.RESPONSE
        msg.response.id = request_id
        msg.response.status = 200
        msg.response.message = 'OK'        
        await self.queue_out.put(msg.SerializeToString())

    async def keep_alive_timeout(self, timer):
        logger.info("keep_alive_timeout")
        msg = SubProtocol_pb2.WebSocketMessage()
        msg.type = SubProtocol_pb2.WebSocketMessage.REQUEST
        msg.request.verb = 'GET'
        msg.request.path = '/v1/keepalive'
        await self.queue_out.put(msg.SerializeToString())
        timer.start()

    async def _write(self, ws):
        while True:
            data = await self.queue_out.get()
            await ws.send_bytes(data)
            self.keep_alive_timer.reset()

            logger.info(f"sent {len(data)} bytes")

    async def _read(self, ws):
        while True:
            async for msg in ws:
                self.keep_alive_timer.reset()
                if msg.type == aiohttp.WSMsgType.BINARY:
                    ws_msg = SubProtocol_pb2.WebSocketMessage()
                    ws_msg.ParseFromString(msg.data)

                    logger.info(f"received {len(msg.data)} bytes: {ws_msg}")

                    if ws_msg.type == SubProtocol_pb2.WebSocketMessage.REQUEST:
                        await self.queue_in.put(ws_msg.request.body)
                        await self.ack(ws_msg.request.id)

    async def connect(self):
        client_version = 'v0.0.0'
        base_url = URL.replace('https', 'wss')
        uri = f"{base_url}/v1/websocket/?login={self.login}&password={self.password}&agent=PYSIGNAL&version={client_version}"
        async with aiohttp.ClientSession() as session:
            try:
                while True:
                    logger.info("connecting")
                    self.keep_alive_timer.start()
                    async with session.ws_connect(uri, ssl=self.ssl_context) as ws:
                        logger.info("connected")
                        reader = asyncio.create_task(self._read(ws))
                        writer = asyncio.create_task(self._write(ws))

                        done, pending = await asyncio.wait(
                            [reader, writer],
                            return_when=asyncio.FIRST_COMPLETED
                        )

                        pending.append(self.keep_alive_timer)
                        logger.warning("canceling")
                        
                        for task in pending:
                            task.cancel()
 
                        for task in done:
                            task.result()

                    logger.warn("disconnected")
            except aiohttp.client_exceptions.WSServerHandshakeError:
                logger.error("invalid auth")
                return
