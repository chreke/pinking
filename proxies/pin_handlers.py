import json
import asyncio
import logging
from collections import defaultdict
from multidict import MultiDict
from aiohttp import web


# TODO: fix this, already defined in pin.models.Pin but not sure how to import
PIN_TYPE_CHOICES = ['direct', 'recursive', 'indirect', 'mfs']

app = None

async def _pins_from_multihash(multihash, ipfs_url, pin_type, first=True):
    """
    Recursively applies `ipfs object links` to get all downstream hashes and
    their block sizes. Note: one could use `ipfs refs --recursive` but it
    is slower due to probably downloading the data, or traversing block hashes
    """
    refs = []
    stat_url = f'{ipfs_url}/api/v0/object/stat'
    links_url = f'{ipfs_url}/api/v0/object/links'
    resp = await app['session'].request('POST', stat_url, params={'arg': multihash})
    if resp.status != 200:
        return resp
    block_size = json.loads(await resp.text())['BlockSize']
    refs.append({'multihash': multihash, 'block_size': block_size,
                 'pin_type': pin_type if first else 'indirect'})

    resp = await app['session'].request('POST', links_url, params={'arg': multihash})

    if resp.status != 200:
        return resp

    # Recusively traverse children
    links = json.loads(await resp.text()).get('Links', None) or []
    for link in links:
        ret = await _pins_from_multihash(
            link['Hash'], ipfs_url, pin_type, first=False)
        if not isinstance(ret, list):
            return ret
        refs += ret

    return refs


async def _get_pins_django(django_url, auth, include_mfs=False):
    pins_url = f'{django_url}/api/pins/'
    headers = {'Authorization': auth}
    await asyncio.sleep(0.01)
    async with app['session'].request('GET', pins_url, headers=headers) as resp:
        if resp.status != 200:
            return resp
        pins = json.loads(await resp.text())

        # Massage pins to the ipfs api format
        out_pins = defaultdict(list)
        for pin in pins:
            pin_type = PIN_TYPE_CHOICES[pin['pin_type']]
            if pin_type == 'mfs' and not include_mfs:
                continue
            out_pins[pin['multihash']].append(pin_type)

        return out_pins


async def _add_pins_django(pins, django_url, auth):
    for pin in pins:
        pin['pin_type'] = PIN_TYPE_CHOICES.index(pin['pin_type'])
    pins_url = f'{django_url}/api/pins/'
    headers = {'Authorization': auth}
    await asyncio.sleep(0.01)
    return await app['session'].request('POST', pins_url, headers=headers, json=pins)


async def _delete_pins_django(pins, django_url, auth):
    for pin in pins:
        if 'block_size' in pin:
            del pin['block_size']
        pin['pin_type'] = PIN_TYPE_CHOICES.index(pin['pin_type'])

    pins_url = f'{django_url}/api/delete-pins/'
    headers = {'Authorization': auth}
    await asyncio.sleep(0.01)
    return await app['session'].request('POST', pins_url, headers=headers, json=pins)


async def pin_ls_handler(request, ipfs_url, django_url):
    """
    Get the pins from django/the database and return them
    """
    auth = request.headers['Authorization']
    ret = await _get_pins_django(django_url, auth)
    if not isinstance(ret, dict):
        return web.Response(status=ret.status, text=await ret.text())

    ipfs_format_pins = {'Keys': {}}
    for multihash, pin_types in ret.items():
        winning_pin_type = None
        if 'recursive' in pin_types:
            winning_pin_type = 'recursive'
        elif 'indirect' in pin_types:
            winning_pin_type = 'indirect'
        elif 'direct' in pin_types:
            winning_pin_type = 'direct'

        ipfs_format_pins['Keys'][multihash] = {'Type': winning_pin_type}
    return web.json_response(ipfs_format_pins)


async def add_pins(multihash_args, pin_type, ipfs_url, django_url, auth):
    # Get pins from django
    ret = await _get_pins_django(django_url, auth, include_mfs=(pin_type=='mfs'))
    if not isinstance(ret, dict):
        return web.Response(status=ret.status, text=await ret.text())
    django_pins = ret

    # If any one of the pins fails, need to return error, and not pin any of
    # the other hashes
    for multihash in multihash_args:
        django_pin_types = django_pins.get(multihash, [])
        if pin_type == 'direct' and 'recursive' in django_pin_types:
            error_msg = {'Message': f'pin: {multihash} already pinned recursively',
                         'Code': 0, 'Type': 'error'}
            return web.json_response(error_msg, status=500)

    add_pins = []
    delete_pins = []
    for multihash in multihash_args:
        django_pin_types = django_pins.get(multihash, [])
        if pin_type in django_pin_types:
            # Do nothing, just return the multihash
            pass
        else:
            ret = await _pins_from_multihash(multihash, ipfs_url, pin_type)
            if not isinstance(ret, list):
                return web.Response(status=ret.status, text=await ret.text())
            pins = ret
            if pin_type == 'recursive' and 'direct' in django_pin_types:
                # If we're replacing a direct with recursive, delete the direct one
                delete_pins.append({'multihash': multihash, 'pin_type': 'direct'})
            add_pins += pins

    # Add new pins to ipfs as direct pins 
    pin_url = f'{ipfs_url}/api/v0/pin/add'
    pin_params = MultiDict()
    for pin in add_pins:
        pin_params['arg'] = pin['multihash']

    async with app['session'].request('POST', pin_url, params=pin_params) as resp:
        if resp.status != 200:
            return web.Response(status=resp.status, text=await resp.text())

    # Add new pins to django
    # NOTE: if this fails, we should roll back the direct pins we added to ipfs
    # but we can also let the garbage collector take care of it
    if len(add_pins) > 0:
        resp = await _add_pins_django(add_pins, django_url, auth)
        if resp.status != 201:
            return web.Response(status=resp.status, text=await resp.text())

    # Delete replaced pins (this will not affect disk usage, since duplicates
    # shouldn't count)
    if len(delete_pins) > 0:
        await _delete_pins_django(delete_pins, django_url, auth)


async def pin_add_handler(request, ipfs_url, django_url):
    multihash_args = request.query.getall('arg', [])
    pin_type = ('recursive' if request.query.get('recursive', 'true') == 'true'
                else 'direct')
    auth = request.headers['Authorization']
    ret = await add_pins(multihash_args, pin_type, ipfs_url, django_url, auth)
    if ret is not None:
        return ret
    return web.json_response({'Pins': multihash_args})


async def rm_pins(multihash_args, ipfs_url, django_url, auth, include_mfs=False):
    ret = await _get_pins_django(django_url, auth, include_mfs=include_mfs)
    if not isinstance(ret, dict):
        return web.Response(status=ret.status, text=await ret.text())
    django_pins = ret
    
    delete_pins = []
    for multihash in multihash_args:
        if multihash not in django_pins:
            msg = {'Message': 'not pinned', 'Code': 0, 'Type': 'error'}
            return web.json_response(msg, status=500)
        pin_types_django = django_pins[multihash]
        recursive_types = list(set(pin_types_django) & set(['recursive', 'mfs']))
        if len(recursive_types) > 0:
            ret = await _pins_from_multihash(multihash, ipfs_url, recursive_types[0])
            if not isinstance(ret, list):
                return web.Response(status=ret.status, text=await ret.text())
            delete_pins += ret
        elif 'direct' in pin_types_django:
            delete_pins.append({'multihash': multihash, 'pin_type': 'direct'})
        else:
            # TODO: The real message from IPFS is:
            # "{h1} is pinned indirectly under {h2}"
            # We don't currently store which recursive pin owns which indirect pin
            # though, so for now:
            msg = {
                'Message': f'{multihash} is pinned indirectly under another pin',
                'Code': 0,
                'Type': 'error'
            }
            return web.json_response(msg, status=500)
    
    if len(delete_pins) > 0:
        await _delete_pins_django(delete_pins, django_url, auth)


async def pin_rm_handler(request, ipfs_url, django_url):
    """
    Remove pins by first getting all user pins from django, then
    figure out the type of the pin to be removed and which indirect (if any)
    pins that should also be removed
    """
    multihash_args = request.query.getall('arg', [])

    auth = request.headers['Authorization']
    ret = await rm_pins(multihash_args, ipfs_url, django_url, auth)
    if ret is not None:
        return ret
    return web.json_response({'Pins': multihash_args})
