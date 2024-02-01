# coding=utf-8
"""
@Time : 2024/1/3
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""
import datetime
import os
import re

import paramiko
from desktop.detector import detect_run as desktop_runner
from serverA.detector import detect_run as serverA_runner
from serverE.detector import detect_run as serverE_runner


def exec_scan_command(domain):

    hostname = domain.host
    port = domain.port
    username = domain.username
    password = domain.password

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


    try:
        client.connect(hostname, port, username, password, timeout=8)
    except Exception:
        raise Exception("连接超时，未能同过SSH连接到目标主机：", hostname)

    try:
        with client.open_sftp() as sftp:
            with sftp.file('/etc/os-version', 'r') as remote_file:
                for line in remote_file:
                    if line.startswith('EditionName='):
                        editionName = line[len('EditionName='):].strip()
                    if line.startswith('EditionName[zh_CN]='):
                        editionNameCh = line[len('EditionName[zh_CN]='):].strip()
                    if line.startswith('SystemName[zh_CN]='):
                        systemName = line[len('SystemName[zh_CN]='):].strip()
                    if line.startswith('SystemName='):
                        systemName_ = line[len('SystemName='):].strip()
                    if line.startswith('ProductType[zh_CN]='):
                        productType = line[len('ProductType[zh_CN]='):].strip()
                    if line.startswith('MajorVersion='):
                        majorVersion = line[len('MajorVersion='):].strip()
                    if line.startswith('MinorVersion'):
                        minorVersion = line[len('MinorVersion='):].strip()
    except IOError:
        print('仅支持扫描统信UOS操作系统，跳过检测目标主机：', domain.host)
        return

    system_version = systemName + ' ' + productType + ' ' + editionNameCh + ' ' + majorVersion + ' ' + minorVersion
    if (editionName == 'Professional' or editionName == 'd') and (
            systemName_[:3] == 'UOS' or systemName_[:9] == 'UnionTech'):
        server_type = 'Desktop' if editionName == 'Professional' else 'ServerD'
        _, stdout, _ = client.exec_command('dpkg -l | grep "^ii"')
        stdout = stdout.read().decode()

        package_info = re.findall(r'ii\s+(.*?)\s+(\d\S+)', stdout)
        if not package_info:
            raise Exception("Target server [dpkg -l | grep '^ii'] can't exec")
        # get kernel version
        _, output, _ = client.exec_command('uname -a')
        output = output.read().decode()
        rule = r"(\d\.\d{2})"
        res = re.search(rule, output)
        if res:
            res = res.group(1)
        else:
            raise Exception("Target server [uname -a] can't exec")

        kernel_arch = re.search(r'(amd64|arm64|loongsin-3)', output).group(1)

        kernel_version = ""
        if res == "5.10":
            rule = r"#(\d{2}\.\d{2}\.)(\d{2}\.\d{2})"
            kernel_version = re.search(rule, output).group(2)
            kernel_version = kernel_version.split('.')
        elif res == "4.19":
            rule = r"#(\d{4})"
            kernel_version = re.search(rule, output).group(1)
            kernel_version = [kernel_version[0:2], kernel_version[2:4]]

        desktop_runner(package_info, res, kernel_arch, kernel_version, client, server_type, domain, system_version)

    elif editionName == 'a' or editionName == 'c' and systemName_ == 'UOS Server':
        server_type = 'ServerA' if editionName == 'a' else 'ServerC'
        _, stdout, _ = client.exec_command('yum list installed')
        stdout = stdout.read().decode()

        # 使用正则表达式来匹配包名和版本信息
        package_pattern = re.compile(r'(\S+)\.(\S+)\s+(\S+)\s+@(\S+)')

        # 在输出中查找匹配的行
        matches = package_pattern.findall(stdout)
        res = []
        for match in matches:
            res.append((match[0], match[2]))

        # get kernel version
        _, output, _ = client.exec_command('uname -r')
        output = output.read().decode()
        result = re.match(r'(.+)(\.\d*-)(.+)\.(.+)', output)
        kernel = result.group(1)
        temp = result.group(3).split('.')
        kernel_version = temp[0:4]
        kernel_arch = result.group(4)

        serverA_runner(res, kernel, kernel_arch, kernel_version, client, server_type,
                       domain, system_version)

    elif editionName == 'e' and systemName_ == 'UOS Server':
        server_type = 'ServerE'
        _, stdout, _ = client.exec_command('yum list installed')
        stdout = stdout.read().decode()
        # 使用正则表达式来匹配包名和版本信息
        package_pattern = re.compile(r'(\S+)\.(\S+)\s+(\S+)\s+@(\S+)')

        # 在输出中查找匹配的行
        matches = package_pattern.findall(stdout)
        res = []
        for match in matches:
            res.append((match[0], match[2]))

        # get kernel version
        _, output, _ = client.exec_command('uname -r')
        output = output.read().decode()
        result = re.match(r'(.+)(\.\d*-)(.+)\.(.+)', output)
        kernel = result.group(1)
        temp = result.group(3).split('.')
        kernel_version = temp[0:5]
        kernel_arch = result.group(4)

        serverE_runner(res, kernel, kernel_arch, kernel_version, client,
                       server_type, domain, system_version)
    else:
        print('仅支持扫描统信UOS操作系统，跳过检测目标主机：', domain.host)



