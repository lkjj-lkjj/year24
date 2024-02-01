# coding=utf-8
"""
@Time : 2024/1/3
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""

import re

import requests
from bs4 import BeautifulSoup

import global_variable
from html_doc.filezip import generate_zip


class VulInfo:
    def __init__(self, cveid, source, score, description):
        self.cveid = cveid
        self.source = source
        self.score = score
        self.description = description


def get_origin_vul_data(exist_vul):
    list1 = []
    list2 = []
    list3 = []
    list4 = []
    for vul in exist_vul:
        if vul['score'] is None or vul['score'] == '':
            vul['score'] = '-1'
        if 'is_fixed' not in vul:
            vul['is_fixed'] = False

        temp = VulInfo(vul['cveid'], vul['source'], vul['score'], vul['cve_description'])
        if float(temp.score) < 4.0:
            list4.append(temp)
        elif float(temp.score) < 7.0:
            list3.append(temp)
        elif float(temp.score) < 9.0:
            list2.append(temp)
        else:
            list1.append(temp)

    return list1, list2, list3, list4


def analyze_year_info(exist_vul):
    year_dict = dict()
    for vul in exist_vul:
        year_info = vul['cveid'].split('-')[1]
        if year_info in year_dict:
            year_dict[year_info] += 1
        else:
            year_dict[year_info] = 1
    year_sorted = {k: v for k, v in sorted(year_dict.items(), key=lambda item: item[1], reverse=False)}
    new_barX = str(list(year_sorted.keys()))
    new_barXdata = str(list(year_sorted.values()))
    return new_barX, new_barXdata


def generate_html(exist_vul, username, hostname, time_ob, local_version, pkg_num, server_type='D'):
    list1, list2, list3, list4 = get_origin_vul_data(exist_vul)
    analyze_year_info(exist_vul)

    fixed_num = 0
    for vul in exist_vul:
        if 'is_fixed' in vul:
            if vul['is_fixed']:
                fixed_num += 1

    with open(global_variable.DOC_TMP_PATH + '/html_doc/test.html', 'r') as file:
        html_content = file.read()

    # Parse the HTML content with BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')

    # Find the element with the specified ID
    soup.find(id='pkg_num').string = str(pkg_num)
    soup.find(id='hostname').string = hostname
    soup.find(id='vul_total').string = str(len(exist_vul))
    soup.find(id='vul_lever1').string = str(len(list1))
    soup.find(id='vul_lever2').string = str(len(list2))
    soup.find(id='vul_lever3').string = str(len(list3))
    soup.find(id='vul_lever4').string = str(len(list4))

    soup.find(id='ip_info').string = hostname
    soup.find(id='username_info').string = username
    soup.find(id='date_info_begin').string = time_ob[0]
    soup.find(id='date_info_end').string = time_ob[1]
    soup.find(id='version_info').string = local_version
    soup.find(id='time_consume').string = time_ob[2] + ' 秒'
    soup.find(id='fixed_num').string = str(fixed_num)

    html_content = soup.prettify()

    sorted_vul = sorted(exist_vul, key=lambda x: x['score'], reverse=True)
    num = 1
    temp = dict()
    new_str = ''
    for vul in sorted_vul:
        temp['id'] = num
        temp['cveid'] = vul['cveid']
        temp['source'] = vul['source']
        temp['score'] = vul['score']
        temp['level'] = vul['level']
        temp['is_fixed'] = vul['is_fixed']
        temp['description'] = vul['cve_description'].replace("'", ' ').replace('"', ' ').replace('\n', ' ').replace('\r', ' ').replace(r'\r', ' ').replace(r'\n', ' ')
        temp['fix_suggest'] = vul['fix_suggest']
        temp['reference_link'] = vul['reference_link']
        if 'affectPkg' in vul:
            temp['affectPkg'] = vul['affectPkg']

        formatted_str = '{{{}}}'.format(', '.join('{}: "{}"'.format(key, value) for key, value in temp.items()))
        new_str += formatted_str + ',\n'
        num += 1
        temp.clear()

    old_js_part = 'const accordionData = [];'
    new_js_part = '''const accordionData = [\n''' + new_str + '''];'''
    modified_js = re.sub(re.escape(old_js_part), new_js_part, html_content)

    old_pie_data = 'var piedata = []'
    new_pie_data = '''var piedata = [
        {value: ''' + str(len(list1)) + ''', name: '严重漏洞', itemStyle: {color: '#960000'}},
        {value: ''' + str(len(list2)) + ''', name: '高危漏洞', itemStyle: {color: '#ff0000'}},
        {value: ''' + str(len(list3)) + ''', name: '中危漏洞', itemStyle: {color: '#f79646'}},
        {value: ''' + str(len(list4)) + ''', name: '低危漏洞', itemStyle: {color: '#ffc000'}},
    ]'''
    modified_js_1 = re.sub(re.escape(old_pie_data), new_pie_data, modified_js)

    old_barX = 'var barX = []'
    old_barXdata = 'var barXdata = []'
    new_barX, new_barXdata = analyze_year_info(exist_vul)
    new_barX = 'var barX = ' + new_barX
    new_barXdata = 'var barXdata = ' + new_barXdata

    modified_js_2 = re.sub(re.escape(old_barX), new_barX, modified_js_1)
    modified_js_3 = re.sub(re.escape(old_barXdata), new_barXdata, modified_js_2)
    filename = hostname + ' ' + time_ob[0]
    with open('scan_doc/html/' + filename + '.html',
              'w') as file:
        file.write(modified_js_3)

    generate_zip(filename)
    return filename+'.zip'

