# coding=utf-8
"""
@Time : 2024/1/3
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""

import re


def if_kernel419_version(version):
    rule = r'^4\.19\.\d+-(\d+\.)+(\d+)(\.uelc.+)?$'
    res = re.fullmatch(rule, version)
    if res:
        return True
    else:
        return False


def get_kernel419_version(version):
    rule = r'-((\d+\.)*\d+)'
    res = re.search(rule, version)
    match = res.group(1)
    return match.split('.')


def kernel419_version_compare(version1, version2_parts):
    version1_parts = get_kernel419_version(version1)
    if version1_parts:
        for v1, v2 in zip(version1_parts, version2_parts):
            if int(v1) > int(v2):
                return 1
            if int(v1) < int(v2):
                return 0

        if len(version1_parts) > len(version2_parts):
            return 1
    return 0
