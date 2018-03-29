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


async def ipfs_proxy_handler(request, target_url, query=None, auth=None,
                             return_body=False, write_eof=True):
    """
    Proxy handler for requests to ipfs daemon.
    Streams the content if encoding is chunked (e.g. ipfs add), passing it on
    to the daemon. Then the response from the daemon is streamed back to the
    caller. Returns the proxy response, and the last message

    Set the proxy target url using `partial` in functools
    """
    target_url = urljoin(target_url, request.rel_url.path)
    headers = request.headers
    if query is None:
        query = request.rel_url.query
    method = request.method

    async with aiohttp.ClientSession(auth=auth) as session:
        if headers.get('Transfer-Encoding', None) == 'chunked':
            data = _request_data_streamer(request)
            # For some reason, can't have 'Transfer-Encoding' set if
            # data is a stream
            del headers['Transfer-Encoding']
        else:
            data = await request.read()

        async with session.request(method, target_url, params=query,
                                   headers=headers, data=data) as ipfs_response:
            if ipfs_response.headers.get('Content-Length', None) is not None:
                body = await ipfs_response.read()
                proxy_response = web.Response(status=ipfs_response.status,
                                              headers=ipfs_response.headers,
                                              body=body)
            else:
                proxy_response = StreamResponse(status=ipfs_response.status,
                                                headers=ipfs_response.headers)
                proxy_response.enable_chunked_encoding()
                await proxy_response.prepare(request)
                chunk = await ipfs_response.content.read(CHUNK_SIZE)
                if return_body: body = chunk
                while chunk:
                    await proxy_response.write(chunk)
                    if return_body: body += chunk
                    chunk = await ipfs_response.content.read(CHUNK_SIZE)
                if write_eof: await proxy_response.write_eof()

    if return_body:
        return proxy_response, body
    return proxy_response
