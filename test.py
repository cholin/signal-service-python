import asyncio
import logger

from utils import twilio_get_verification_code, sequentially
from messenger import Messenger

async def create_account(messenger):
    print("Registering...")
    await messenger.register()

    code = await twilio_get_verification_code(messenger.protocol.number)
    print("Got verification SMS code")

    print("Confirming...")
    await messenger.confirm(code)
    await asyncio.sleep(2)

def run():
    number = '+12345678'
    password = 'PASSWORD_FOO'
    messenger = Messenger(number, password)

    loop = asyncio.get_event_loop() 

    initial = [
        create_account(messenger),
        messenger.new_session(b'+1987654321',1),
        messenger.send((b'+1987654321',1), 'Starting')
    ]
    loop.run_until_complete(sequentially(initial))

    from datetime import datetime
    from utils import periodic
    loop.create_task(periodic(messenger, 10, lambda: messenger.send((b'+1987654321',1), f'Msg {datetime.now():%H:%M:%S}')))    
    
    loop.run_forever()

run()
