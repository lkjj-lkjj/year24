"""
@Time : 2024/1/3
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""
import re


def if_kernel419_version(version):
    rule = r'(x86:#\d{4}|arm:#\d{4}|loongarch:#\d{4})'
    res = re.search(rule, version)
    if res:
        return True
    else:
        return False


def get_parts_of_kernel_4_19_version(version, local_kernel):
    rule = r'arch:(#\d{4})+'
    if local_kernel == 'amd64':
        rule.replace('arch', 'x86')
    elif local_kernel == 'arm64':
        rule.replace('arch', 'arm')
    elif local_kernel == 'loongsin-3':
        rule.replace('arch', 'loongarch')
    else:
        print("arch error, check your kernel arch")
    temp = re.search(rule, version)
    if temp:
        temp = temp.group(0)
    else:
        return None
    res = re.findall(r'#\d{4}', temp)
    return res


def get_version419_nums(version_parts):
    res = []
    for version in version_parts:
        version = [version[1:3], version[3:5]]
        res.append(version)
    return res


def kernel_4_19_version_compare(version1, version2, kernel_arch):
    version1_parts = get_parts_of_kernel_4_19_version(version1, kernel_arch)
    if version1_parts:
        version_nums = get_version419_nums(version1_parts)
        for version in version_nums:
            if int(version[0]) == int(version2[0]) and int(version[1]) > int(version2[1]):
                return 1
    return 0


def if_kernel419_version_serverD(version, vul_arch, local_kernel):
    rule = r'4\.19\.\d+-\d{4}'
    res = re.fullmatch(rule, version)

    if local_kernel == 'amd64':
        local_kernel = 'x86'
    elif local_kernel == 'arm64':
        local_kernel = 'arm'
    elif local_kernel == 'loongsin-3':
        local_kernel = 'loongarch'

    if local_kernel in vul_arch.lower():
        is_arch = True
    else:
        is_arch = False

    if res and is_arch:
        return True
    else:
        return False


def get_parts_of_kernel_4_19_version_serverD(version):
    rule = r'4\.19\.\d+-(\d{4})'
    res = re.search(rule, version).group(1)
    return res


def kernel_4_19_version_compare_serverD(version1, version2):
    version1_parts = get_parts_of_kernel_4_19_version_serverD(version1)
    if version1_parts:
        if int(version1_parts[0:2]) == int(version2[0]) and int(version1_parts[2:4]) > int(version2[1]):
            return 1
    return 0






