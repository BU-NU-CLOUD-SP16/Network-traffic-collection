from mimetools import Message
from StringIO import StringIO


def extract_http(request_text, dict_filed):
    request_line, headers_alone = request_text.split('\r\n', 1)
    headers = Message(StringIO(headers_alone))
    # print request_line
    request_line = request_line.split(' ', 2)
    # print request_line[0]
    if request_line[0] in {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT'} and 'host' in headers.keys():
        dict_filed['tags']['action'] = request_line[0]
        dict_filed['tags']['Domain'] = headers['host']
        dict_filed['tags']['URL'] = headers['host'] + request_line[1]
        # print request_line[1]
    else:
        dict_filed['tags']['result_code'] = request_line[1]
    if 'user_agent' in headers.keys():
        dict_filed['tags']['user_agent'] = headers['user_agent']
    if 'referer' in headers.keys():
        dict_filed['tags']['referer'] = headers['referer']
    if 'content-type' in headers.keys():
        dict_filed['tags']['content-type'] = headers['content-type']
    if 'accept' in headers.keys():
        dict_filed['tags']['content-type'] = headers['accept']
    # print headers.keys()
    # print dict_filed['URL']
    """
    print len(headers)     # -> "3"
    print headers.keys()   # -> ['accept-charset', 'host', 'accept']
    print headers.get('referer')
        """