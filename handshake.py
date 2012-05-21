from hashlib import sha1
from base64 import b64encode

WS_UUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

WS_HEADER_KEYS = ['Upgrade',
                  'Connection',
                  'Host',
                  'Origin',
                  'Sec-WebSocket-Key',
                  'Sec-WebSocket-Version',
                  'Sec-WebSocket-Key1',
                  'Sec-WebSocket-Key2']


def ws_response(raw_request):
    parsed = parse_request(raw_request)
    return handshake_response(parsed)


def handshake_response(request):
    """request is a dictionary parsed from 
    the initial client request"""
    
    response = ["HTTP/1.1 101 Switching Protocols"]
    print request
    print "\n"
    if request.get('Upgrade') == 'websocket':
        response.append("Upgrade: websocket")
    else:
        return None
    if request.get('Connection') == 'Upgrade':
        response.append("Connection: Upgrade")
    else:
        return None
    if request.get('Sec-WebSocket-Key'):
        response_key = confirm_client_key(request['Sec-WebSocket-Key'])
        response.append('Sec-WebSocket-Accept: %s' % response_key)
    else:
        return None
    response.append('\r\n\r\n')
    r = '\r\n'.join(response)
    print r
    return r

      
def confirm_client_key(client_key):
    concated_key = client_key + WS_UUID
    s1 = sha1(concated_key)
    return b64encode(s1.digest())


def parse_line(line):
    """Returns a dictionary after parsing the raw
    reqeust line"""

    if 'GET ' ==  line[0:4]:
        line_split = line.split()
        return {'request_type': 'GET', 
                'request_path': line_split[1],
                'protocol': line_split[2]}

    for key in WS_HEADER_KEYS:
        if key in line[0:len(key) + 1]:
            _key, _sep, value = line.partition(': ')
            return {key: value}

    if 'Sec-WebSocket-Protocol' in line[0:24]:
        _key, _sep, value = line.partition(': ')
        raw_values = value.strip().split(',')
        values = [v.strip() for v in raw_values]
        return {'Sec-WebSocket-Protocol': values}

    if line:
        return {'body': line}
    return None


def parse_request(raw_request):
    lines = raw_request.splitlines()
    request_object = {}
    for line in lines:
        value = parse_line(line)
        if value:
            request_object.update(value)
    return request_object

