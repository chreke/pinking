"""
A proxy for the ipfs daemon

Run `ipfs --api /ip4/127.0.0.1/tcp/8081 [commands]` to go through the proxy
instead of directly to the daemon
"""
import logging
import sys
from urllib.parse import urljoin

import asyncio
import aiohttp
from aiohttp import web, ClientSession

IPFS_DAEMON_URL = 'http://127.0.0.1:5001'
CHUNK_SIZE = 256


@aiohttp.streamer
async def request_data_streamer(writer, request):
    chunk = await request.content.read(CHUNK_SIZE)
    while chunk:
        await writer.write(chunk)
        chunk = await request.content.read(CHUNK_SIZE)


async def proxy(request):
    target_url = urljoin(IPFS_DAEMON_URL, request.match_info['path'])
    get_data = request.rel_url.query

    #
    # Insert user auth, hash tracking etc here
    #

    async with aiohttp.ClientSession() as session:
        headers = request.headers
        if headers.get('Transfer-Encoding', None) == 'chunked':
            data = request_data_streamer(request)
            # For some reason, can't have 'Transfer-Encoding' set if
            # data is a stream
            del headers['Transfer-Encoding']
        else:
            data = await request.read()

        async with session.request(request.method, target_url,
                                   headers=headers, params=get_data,
                                   data=data) as ipfs_response:
            proxy_response = web.StreamResponse(status=ipfs_response.status,
                                                headers=ipfs_response.headers)
            proxy_response.enable_chunked_encoding()
            await proxy_response.prepare(request)
            chunk = await ipfs_response.content.read(CHUNK_SIZE)
            while chunk:
                await proxy_response.write(chunk)
                chunk = await ipfs_response.content.read(CHUNK_SIZE)
            await proxy_response.write_eof()

    return proxy_response


if __name__ == "__main__":
    app = web.Application()
    app.router.add_route('*', '/{path:.*?}', proxy)

    loop = asyncio.get_event_loop()
    f = loop.create_server(app.make_handler(), '0.0.0.0', 8081)
    srv = loop.run_until_complete(f)
    print('serving on', srv.sockets[0].getsockname())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
