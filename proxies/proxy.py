import asyncio
import logging
from urllib.parse import urljoin

import aiohttp
from aiohttp import web
from aiohttp.web import StreamResponse

CHUNK_SIZE = 256

@aiohttp.streamer
async def _request_data_streamer(writer, request):
    chunk = await request.content.read(CHUNK_SIZE)
    while chunk:
        await writer.write(chunk)
        chunk = await request.content.read(CHUNK_SIZE)


async def ipfs_proxy_handler(request, target_url):
    """
    Proxy handler for requests to ipfs daemon.
    Streams the content if encoding is chunked (e.g. ipfs add), passing it on
    to the daemon. Then the response from the daemon is streamed back to the
    caller.

    Set the proxy target url using `partial` in functools
    """
    target_url = urljoin(target_url, str(request.rel_url))
    headers = request.headers
    get_data = request.rel_url.query
    method = request.method

    logging.info(f'Received {method} request')

    async with aiohttp.ClientSession() as session:
        if headers.get('Transfer-Encoding', None) == 'chunked':
            data = _request_data_streamer(request)
            # For some reason, can't have 'Transfer-Encoding' set if
            # data is a stream
            del headers['Transfer-Encoding']
        else:
            data = await request.read()

        async with session.request(method, target_url,
                                   headers=headers, params=get_data,
                                   data=data) as ipfs_response:
            if ipfs_response.headers.get('Content-Length', None) is not None:
                proxy_response = web.Response(status=ipfs_response.status,
                                              headers=ipfs_response.headers,
                                              body=await ipfs_response.read())
            else:
                proxy_response = StreamResponse(status=ipfs_response.status,
                                                headers=ipfs_response.headers)
                proxy_response.enable_chunked_encoding()
                await proxy_response.prepare(request)
                chunk = await ipfs_response.content.read(CHUNK_SIZE)
                while chunk:
                    await proxy_response.write(chunk)
                    chunk = await ipfs_response.content.read(CHUNK_SIZE)
                await proxy_response.write_eof()

    return proxy_response


def run_proxy(proxy_handler, listen_port=5001, ssl_context=None):
    app = web.Application()
    app.router.add_route('*', '/{path:.*?}', proxy_handler)
    try:
        web.run_app(app, host='0.0.0.0', ssl_context=ssl_context,
                    port=listen_port)
    except KeyboardInterrupt:
        asyncio.get_event_loop().run_until_complete(cleanup())
