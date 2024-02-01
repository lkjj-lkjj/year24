"""
@Time : 2024/1/3
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""
import re


def if_kernel510_version(version):
    rule = r'^(#\d{2}\.\d{2}\.\d{2}\.\d{2}-CVE\/?)*$'
    res = re.fullmatch(rule, version)
    if res:
        return True
    else:
        return False


def get_parts_of_kernel_5_10_version(version):
    rule = r'(\#\d{2}\.\d{2}\.\d{2}\.\d{2}-CVE)(\/|$)'
    res = re.findall(rule, version)
    return res


def get_version510_nums(version_parts):
    res = []
    for version in version_parts:
        version = version[0][7:12].split('.')
        res.append(version)
    return res


def kernel_5_10_version_compare(version1, version2):
    version1_parts = get_parts_of_kernel_5_10_version(version1)
    version_nums = get_version510_nums(version1_parts)
    for version in version_nums:
        if int(version2[0]) == int(version[0]) and int(version2[1]) < int(version[1]):
            return 1
    return 0


def test():
    version = '#20.00.50.36-CVE/#20.00.51.28-CVE/#20.00.52.14-CVE'
    my_version = ('51', '22')
    print(kernel_5_10_version_compare(version, my_version))


