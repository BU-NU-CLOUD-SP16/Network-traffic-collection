from mimetools import Message
from StringIO import StringIO


def extract_http(request_text, dict_filed):
    request_line, headers_alone = request_text.split('\r\n', 1)
    headers = Message(StringIO(headers_alone))
    # print request_line
    request_line = request_line.split(' ', 2)
    # print request_line[0]
    if request_line[0] in {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT'}:
        dict_filed['action'] = request_line[0]
        dict_filed['Domain'] = headers['host']
        dict_filed['URL'] = headers['host'] + request_line[1]
        # print request_line[1]
    else:
        dict_filed['result_code'] = request_line[1]
    if 'user_agent' in headers.keys():
        dict_filed['user_agent'] = headers['user_agent']
    if 'referer' in headers.keys():
        dict_filed['user_agent'] = headers['referer']
    if 'content-type' in headers.keys():
        dict_filed['content-type'] = headers['content-type']
    if 'accept' in headers.keys():
        dict_filed['content-type'] = headers['accept']
    # print headers.keys()
    # print dict_filed['URL']
    """
    print len(headers)     # -> "3"
    print headers.keys()   # -> ['accept-charset', 'host', 'accept']
    print headers.get('referer')
        """