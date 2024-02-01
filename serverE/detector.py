# coding=utf-8
"""
@Time : 2024/1/3
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""
import os
import sys
import time
from datetime import datetime
import requests
from prettytable import PrettyTable

import global_variable
from doc_generator.generator import generate_doc
from doc_generator.wordToPDF import generate_pdf
from doc_generator.generate_excel import generate_excel
from html_doc.generator_html import generate_html
from mysql_.vul import Vul
from serverE.Kernel_4_19 import *
from serverE.Kernel_5_10 import *
from utils.checksource import check_source
from utils.scan_result_analyze import cal_lever


class Version:
    def __init__(self, epoch, version, revision):
        self.epoch = epoch
        self.version = version
        self.revision = revision

    def get_origin_info(self):
        if self.epoch != "":
            return self.epoch + ':' + self.version + '-' + self.revision
        return self.epoch + self.version + '-' + self.revision


def split_str(version):
    result = []
    temp = ""
    for c in version:
        if c.isdigit():
            temp += c
        else:
            if temp:
                result.append(temp)
                temp = ""
            result.append(c)
    if temp != "":
        result.append(temp)
    return result


def form_vul_dict():
    vul_dict = dict()
    vul_list = get_vul_list()
    for vul in vul_list:
        if vul["status"] == "unaffected" or vul["fixed_version"] is None:
            continue
        if vul["source"] in vul_dict:
            vul_dict[vul["source"]].append(vul)
        else:
            vul_dict[vul["source"]] = []
            vul_dict[vul["source"]].append(vul)
    return vul_dict


def get_vul_list():
    try:
        headers = {
            'content-type': 'application/json',
        }

        cookies = {
            'vulSessionid': 'loTQ6IBdd66E58SUdataXVRdyaXjZw0h'
        }

        jsons = {
            "os": "ServerE",
            "version": ""
        }
        res = requests.post('https://src.uniontech.com/utapi/request_vul_json', headers=headers, cookies=cookies,
                            json=jsons)

        if 'status' in res.json():
            if res.json()['status'] == 'failed':
                raise Exception("Can't get vulnerabilities from remote lab")
        return res.json()['content']
    except OSError:
        raise


def if_pkg_version(version):
    rule = r'^([a-z0-9\+\.\-\_]+-)?([a-zA-Z0-9\.\~\+\:]+)-([a-zA-Z0-9\.\~\+]+)$'
    res = re.fullmatch(rule, version)
    if res:
        return True
    else:
        return False


def get_parts_of_the_version(version):
    if version[0].isdigit():
        version = '-' + version
    pos = version.rfind('-')
    revision = version[pos + 1:]
    version = version[:pos]
    pos = version.rfind('-')
    version = version[pos + 1:]
    epoch = '0'
    if ':' in version:
        epoch = version.split(':')[0]
        version = version.split(':')[1]
    return Version(epoch, version, revision)


def version_compare_epoch_last(version1, version2):
    # compare version
    v1_v_list = split_str(version1.version)
    v2_v_list = split_str(version2.version)

    for v1, v2 in zip(v1_v_list, v2_v_list):
        if v1 == '~' and v2 != '~':
            return 0
        if v1 != '~' and v2 == '~':
            return 1

        if v1.isdigit() and v2.isdigit():
            v1 = int(v1)
            v2 = int(v2)
            if v1 > v2:
                return 1
            if v1 < v2:
                return 0
        else:
            if v1 > v2:
                return 1
            if v1 < v2:
                return 0

    if len(v1_v_list) > len(v2_v_list):
        if v1_v_list[len(v2_v_list)] == '~':
            return 0
        else:
            return 1
    elif len(v1_v_list) < len(v2_v_list):
        if v2_v_list[len(v1_v_list)] == '~':
            return 1
        else:
            return 0

    # compare revision
    pos1 = version1.revision.find('uel')
    pos2 = version2.revision.find('uel')

    if pos1 == -1 and pos2 != -1:
        version2.revision = version2.revision[:pos2]

    v1_r_list = split_str(version1.revision)
    v2_r_list = split_str(version2.revision)

    for v1, v2 in zip(v1_r_list, v2_r_list):
        if v1 == '~' and v2 != '~':
            return 0
        if v1 != '~' and v2 == '~':
            return 1

        if v1.isdigit() and v2.isdigit():
            v1 = int(v1)
            v2 = int(v2)
            if v1 > v2:
                return 1
            if v1 < v2:
                return 0
        else:
            if v1 > v2:
                return 1
            if v1 < v2:
                return 0

    if pos1 == -1 and pos2 != -1:
        if len(v1_r_list) > len(v2_r_list):
            if v1_r_list[len(v2_r_list)].isdigit():
                return 1
        return 0

    if len(v1_r_list) > len(v2_r_list):
        if v1_r_list[len(v2_r_list)] == '~':
            return 0
        else:
            return 1
    elif len(v1_r_list) < len(v2_r_list):
        if v2_r_list[len(v1_r_list)] == '~':
            return 1
        else:
            return 0

    return 0


def mistake_detect(package_name, vul_match_version):
    try:
        global PACKAGE_CACHE
        global LATEST_VERSION
        if package_name in PACKAGE_CACHE:
            if PACKAGE_CACHE[package_name] is not None:
                version_info = PACKAGE_CACHE[package_name]
            else:
                LATEST_VERSION = 'None'
                return 1
        else:
            PACKAGE_CACHE[package_name] = None
            command = 'yum info available name'
            command = command.replace('name', package_name)

            global CLIENT
            _, output, _ = CLIENT.exec_command(command)
            output = output.read().decode()
            epoch = re.search(r"(Epoch|时期)\s+:\s(.+)", output)
            if not epoch:
                epoch = '0'
            else:
                epoch = epoch.group(2)
            version = re.search(r"(Version|版本)\s+:\s(.+)", output).group(2)
            revision = re.search(r"(Release|发布)\s+:\s(.+)", output).group(2)
            version_info = Version(epoch, version, revision)
            PACKAGE_CACHE[package_name] = version_info

        LATEST_VERSION = version_info.get_origin_info()
        if version_compare_epoch_last(vul_match_version, version_info) == 1:
            return 1
        else:
            return 0
    except Exception as e:
        LATEST_VERSION = 'None'
        # print("Warning: In mistake detect, can't find the latest version of " + package_name)
        return 1


def print_progress_bar(progress):
    bar_length = 40
    block = int(round(bar_length * progress))
    progress_text = f"项目: [{'=' * block}{' ' * (bar_length - block)}] {int(progress * 100)}%"
    sys.stdout.write('\r' + progress_text + ' ')
    sys.stdout.flush()


def hash_compare(vul_dict, os_list, kernel_version, kernel_arch, kernel_compare_version, cmd):
    exist_vul = []
    table = PrettyTable(['漏洞 ID', '漏洞库包名', '已修复版本', '最新版本', '目标主机包名', '目标主机版本'])
    # detect pkgs vul
    num = 0
    os_len = len(os_list)
    for pkg in os_list:
        num += 1
        if num % 100 == 0:
            cmd.update_process(int(num / os_len))
        # print_progress_bar(num / os_len)
        vul_list = vul_dict.get(pkg[0])
        if vul_list:
            for vul in vul_list:
                vul_version = vul["fixed_version"].strip()
                if if_pkg_version(vul_version):
                    version1 = get_parts_of_the_version(vul_version)
                    version2 = get_parts_of_the_version(pkg[1])
                    if version_compare_epoch_last(version1, version2) == 1:
                        if mistake_detect(pkg[0], version1) == 0:
                            table.add_row(
                                [vul['cveid'], vul['source'], vul['fixed_version'], LATEST_VERSION, pkg[0],
                                 pkg[1]])
                            exist_vul.append(vul)
    # print("\n\n软件包漏洞：")
    # print(table)

    kernel_table = PrettyTable(["漏洞 ID", "内核", "已修复版本", "目标主机版本"])
    # detect kernel vul
    kernel_vuls = vul_dict.get("kernel-" + kernel_version)
    if kernel_vuls:
        for vul in kernel_vuls:
            vul_version = vul["fixed_version"].strip()
            if kernel_version == "4.19":
                if if_kernel419_version(vul_version):
                    if kernel419_version_compare(vul_version, kernel_compare_version) == 1:
                        kernel_table.add_row(
                            [vul['cveid'], vul['source'], vul['fixed_version'], '.'.join(kernel_compare_version)])
                        # exist_vul.append(vul)
            if kernel_version == "5.10":
                if if_kernel510_version(vul_version):
                    if kernel510_version_compare(vul_version, kernel_compare_version) == 1:
                        pass
                        # print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                        # print("Kernel-5.10 漏洞：",
                        #       "\n漏洞修复版本：", vul_version,
                        #       "\n本地版本：", kernel_compare_version)
                        # exist_vul.append(vul)
    # print("\n内核漏洞：")
    # print(kernel_table)
    cmd.update_process(100)
    return exist_vul


def is_fixed(vul_version, pkg_name):
    if CLIENT:
        try:
            command = 'yum list installed ' + pkg_name
            stdin, stdout, stderr = CLIENT.exec_command(command, get_pty=True)
            output = stdout.read().decode('utf-8', errors='replace')

            rule = r'[^\s]+uel[^\s]+'

            res = re.search(rule, output).group(0)
            vul_version = get_parts_of_the_version(vul_version)
            pkg_version = get_parts_of_the_version(res)
            if version_compare_epoch_last(vul_version, pkg_version) == 1:
                return False
            else:
                return True
        except Exception as e:
            return False


def fix_vulnerability(exist_vul):
    if CLIENT:
        fixed_pkg = []
        for item in exist_vul:
            # print('\n正在修复软件包：{}'.format(item['source']))
            try:
                if item['source'] not in fixed_pkg:
                    command = "echo {} | sudo -S yum update -y {}".format(PASSWORD, item['source'])
                    stdin, stdout, stderr = CLIENT.exec_command(command, get_pty=True)

                if not is_fixed(item['fixed_version'], item['source']):
                    item['is_fixed'] = False
                    # print("修复失败：", item['source'])
                else:
                    item['is_fixed'] = True
                    if item['source'] not in fixed_pkg:
                        fixed_pkg.append(item['source'])
                    # print("修复成功：", item['source'])
            except Exception as e:
                item['is_fixed'] = False
                # print("Fixed vulnerability error:", item['source'], e)


def detect_run(os_list, kernel_version, kernel_arch, kernel_compare_version, client, server_type, cmd, system_version):
    current_time = str(datetime.now()).split('.')[0]
    start_time = time.time()
    # print("ServerE 扫描开始", cmd.host)
    cmd.append_information("{} 扫描开始".format(server_type))
    global CLIENT, PASSWORD, NETWORK, YUM_SOURCE
    CLIENT = client
    PASSWORD = cmd.password
    vul_dict = form_vul_dict()

    change_sources_ = check_source(server_type, client)
    if change_sources_ == 1:
        cmd.append_information("检测到源被修改，可能导致扫描结果不准确")
        pass
        # continue_ = input("是否继续 y/N")
        # if continue_.lower() in ['y', 'yes']:
        #     pass
        # else:
        #     return

    if cmd.update or cmd.repair:
        if client:
            stdin, stdout, stderr = CLIENT.exec_command('echo {} | sudo -S echo checksudo'.format(PASSWORD),
                                                        get_pty=True)
            time.sleep(2)
            msg = stdout.read().decode('utf-8', errors='replace')
            if 'checksudo' not in msg:
                cmd.append_information("当前用户没有sudo权限，无法进行--update，--repair")
                raise Exception("当前用户没有sudo权限，无法进行--update，--repair")
        else:
            return

    try:
        if cmd.update:
            # print('正在更新源')
            cmd.append_information("正在更新源...")
            command = 'echo {} | sudo -S yum makecache'.format(PASSWORD)
            stdin, stdout, stderr = CLIENT.exec_command(command, get_pty=True)
            cmd.append_information("更新源成功！")
            # print(stdout.read().decode('utf-8', errors='replace'))
    except Exception as e:
        print("Can't exec [sudo yum makecache], please check your sudo permission; " + e.__str__())

    try:
        cmd.append_information("正在扫描...")
        exist_vul = hash_compare(vul_dict, os_list, kernel_version, kernel_arch, kernel_compare_version, cmd)
        cmd.append_information("扫描结束！")
    except Exception as e:
        raise Exception("Scanning vulnerabilities error; " + e.__str__())

    word_link = ''
    pdf_link = ''
    html_link = ''
    excel_link = ''

    if len(exist_vul) == 0:
        scan_result = "本次共扫描{}个软件包，".format(len(os_list)) + "目标主机【" + cmd.host + "】" + '未发现漏洞，不再进行修复和生成文档'
        cmd.insert_scan_data(word_link, pdf_link, html_link, excel_link, scan_result, len(os_list))
        cmd.append_information("未发现漏洞，不再进行修复和生成文档")
        return

    if cmd.repair:
        cmd.append_information("漏洞修复中...")
        # print("修复漏洞中...")
        fix_vulnerability(exist_vul)
        cmd.append_information("修复完成！")

    for item in exist_vul:

        try:
            float(item['score'])
        except Exception:
            item['score'] = None

        if not item['cve_description']:
            item['cve_description'] = ''

        if 'is_fixed' not in item:
            item['is_fixed'] = False

        if item['score'] is not None and item['score'] != '':
            if float(item['score']) >= 9:
                item['level'] = '严重'
            elif float(item['score']) >= 7:
                item['level'] = '高危'
            elif float(item['score']) >= 4:
                item['level'] = '中危'
            else:
                item['level'] = '低危'
        else:
            item['level'] = '未知'

        item['reference_link'] = 'https://src.uniontech.com/#/security_advisory_detail?utsa_id=' + item['utsa_id']

        if not item['is_fixed']:
            if item['cveid'][:3] == 'CVE':
                item['fix_suggest'] = '''外网用户：通过 yum upgrade-minimal --cve ''' + item[
                    'cveid'] + ''' 或者 yum update PackageName 命令升级。内网用户：通过在内网环境部署离线yum仓库源进行更新。其他情况：联系客户经理'''
            else:
                item['fix_suggest'] = '''外网用户：通过 yum update ''' + item[
                    'source'] + ''' 命令升级。内网用户：通过在内网环境部署离线yum仓库源进行更新。其他情况：联系客户经理'''
        else:
            item['fix_suggest'] = ''
        Vul([cmd.id, item.get('cveid'), item.get('local_version'), item.get('fixed_version'),
             item.get('is_fixed')]).insert()
    end_time = time.time()
    consume_time = end_time - start_time
    current_time_end = str(datetime.now()).split('.')[0]
    # print("扫描时长: {:.2f} 秒".format(end_time - start_time))

    if cmd.word or cmd.pdf or cmd.html or cmd.excel:
        # print("生成文档中...")
        cmd.append_information("生成报告中...")
        if cmd.word:
            word_link = generate_doc(exist_vul, cmd.username, cmd.host,
                                     [current_time, current_time_end, str(round(consume_time, 2))], system_version,
                                     len(os_list),
                                     server_type)
        if cmd.pdf and not cmd.word:
            generate_doc(exist_vul, cmd.username, cmd.host,
                         [current_time, current_time_end, str(round(consume_time, 2))], system_version,
                         len(os_list),
                         server_type)
            pdf_link = generate_pdf(cmd.host + ' ' + current_time)

        if cmd.pdf and cmd.word:
            pdf_link = generate_pdf(cmd.host + ' ' + current_time)
        if cmd.html:
            html_link = generate_html(exist_vul, cmd.username, cmd.host,
                                      [current_time, current_time_end, str(round(consume_time, 2))], system_version,
                                      len(os_list),
                                      server_type)
        if cmd.excel:
            excel_link = generate_excel(exist_vul, cmd, system_version,
                                        [current_time, current_time_end, str(round(consume_time, 2))], server_type)
        # print("文档生成在", global_variable.DOC_FILE_PATH)
        cmd.append_information("报告生成成功！")
    # print('\n')
    a, b, c, d, e = cal_lever(exist_vul)

    scan_result = "本次共扫描{}个软件包，".format(len(os_list)) + "目标主机【" + cmd.host + "】共检测出漏洞" + str(
        len(exist_vul)) + "个，其中严重漏洞" + str(b) + "个，高危漏洞" + str(c) + "个，中危漏洞" + str(
        d) + "个，低危漏洞" + str(e) + "个。修复漏洞" + str(a) + "个（详细信息请下载扫描文档）。"
    cmd.insert_scan_data(word_link, pdf_link, html_link, excel_link, scan_result, len(os_list))


CLIENT = None
LATEST_VERSION = ''
PACKAGE_CACHE = dict()
PASSWORD = ''
NETWORK = True
YUM_SOURCE = None
