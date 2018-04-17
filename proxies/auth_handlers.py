import base64
import asyncio
import logging
from aiohttp import web
from collections import defaultdict
from proxy import ipfs_proxy_handler


def get_user_password(request):
    basic_auth = request.headers.get('Authorization', None)
    if basic_auth:
        user_pass_bytes = base64.b64decode(basic_auth.split(' ')[1])
        return user_pass_bytes.decode('utf-8').split(':')
    return None, None


async def _authenticate(request, django_url):
    """
    Check with Django
    """
    resp = await app['session'].request(
        'GET', f'{django_url}/api/auth/', headers=request.headers)
    await asyncio.sleep(0.01)
    if resp.status != 200:
        error_msg = {'Message': await resp.text(), 'Code': 0, 'Type': 'error'}
        return web.json_response(error_msg, status=resp.status)
    return None


_locks = defaultdict(lambda: False)
async def auth_and_lock(request, handler, handler_kwargs):
    auth_response = await _authenticate(request, handler_kwargs['django_url'])
    if auth_response is not None:
        return auth_response

    user, _ = get_user_password(request)
    if _locks.get(user) == True:
        error_msg = {'Message': f'multiple simultaneous requests is not allowed',
                     'Code': 0, 'Type': 'error'}
        return web.json_response(error_msg, status=429)

    try:
        _locks[user] = True
        ret = await handler(request, **handler_kwargs)
        _locks[user] = False
        return ret
    except:
        _locks[user] = False
        raise

    _locks[user] = False


async def auth_handler(request, ipfs_url, django_url):
    return await ipfs_proxy_handler(request, ipfs_url)
