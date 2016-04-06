with open("http.log") as f:
    content = f.readlines()
rows = len(content)
Matrix = [[0 for x in range(13)] for x in range(rows-7)]
print content[6]
print rows
for i in range(8, rows-1):
    columns = content[i].split("\t")
    dict_field = {'Timestamp': None, 'sIP': None, 'sPort': None, 'dIP': None, 'dPort': None,
                      'Domain': None, 'URL': None,'user_agent': None, 'referer': None,
                      'result_code': None, 'action': None, 'bytes': None, 'content-type': None}
    dict_field['Timestamp'] = columns[0]
    dict_field['sIP'] = columns[2]
    dict_field['sPort'] = columns[3]
    dict_field['dIP'] = columns[4]
    dict_field['dPort'] = columns[5]
    dict_field['Domain'] = columns[8]
    dict_field['URL'] = columns[9]
    dict_field['user_agent'] = columns[11]
    dict_field['referer'] = columns[10]
    dict_field['result_code'] = columns[14]
    dict_field['action'] = columns[7]
    dict_field['bytes'] = columns[12] + columns[13]
    dict_field['content-type'] = columns[26][0:columns[26].find('\n')]

    print dict_field
    '''
    print columns[0] + ' ' + columns[2] + ' ' + columns[3] + ' ' + columns[4] + ' ' + columns[5] + ' ' + \
          columns[8] + ' ' + columns[9] + ' ' + columns[11] + ' ' + columns[14] + ' ' + columns[7] + ' ' +\
          columns[12] + ' ' + columns[13] + ' ' + columns[24] + ' ' + columns[26]
    '''