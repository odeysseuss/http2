import asyncio

async def requests(id, msg_count=5):
    try:
        r, w = await asyncio.open_connection('localhost', 8000)

        for i in range(msg_count):
            msg = f"Client {id} Sent {i}\n"
            w.write(msg.encode())
            await w.drain()

            data = await r.read(1024)
            print(f"Client {id} received: {data.decode().strip()}")

        w.close()
        await w.wait_closed()

    except Exception as e:
        print(f"Client {id} error: {e}")

async def main():
    tasks = [requests(i) for i in range (1024)]
    await asyncio.gather(*tasks)

asyncio.run(main())
