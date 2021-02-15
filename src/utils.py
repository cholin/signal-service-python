import asyncio
import logging

class Timer:
    def __init__(self, timeout, callback):
        self._timeout = timeout
        self._callback = callback
        self._task = None

    def start(self):
        if not self._task:     
            self._task = asyncio.create_task(self._job())

    async def _job(self):
        await asyncio.sleep(self._timeout)
        await self._callback(self)

    def cancel(self):
        if self._task:
            self._task.cancel()
            self._task = None
    
    def reset(self):
        self.cancel()
        self.start()


async def sequentially(coroutines):
    for c in coroutines:
        await c

async def periodic(messenger, timeout, cb):
    while True:
        await cb()
        await asyncio.sleep(timeout)

async def twilio_get_verification_code(to):
    import os
    from twilio.rest import Client
    from datetime import datetime, timedelta
    import re
    from functools import partial

    account_sid = os.environ['TWILIO_ACCOUNT_SID']
    auth_token = os.environ['TWILIO_AUTH_TOKEN']
    client = Client(account_sid, auth_token)

    recent = datetime.utcnow() - timedelta(minutes=1)
    get_sms_list = partial(client.messages.list, to=to, date_sent_after=recent)
    
    entries = get_sms_list()
    while len(entries) == 0:
        print("sleeping", len(entries))
        await asyncio.sleep(1)
        entries = get_sms_list()
    
    record = entries[0]
    verification_code = int(''.join(re.findall(r'\d+', record.body)))
    record.delete()
    print("got verification code", verification_code)
    return verification_code