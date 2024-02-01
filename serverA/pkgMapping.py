# coding=utf-8
"""
@Time : 2024/1/3
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""

import csv

import global_variable


def get_pkg_source_map_dict(arch='x86_64'):
    if arch == 'x86_64':
        column1 = 0
        column2 = 1
    elif arch == 'aarch64':
        column1 = 2
        column2 = 3
    elif arch == 'loongarch64':
        column1 = 4
        column2 = 5
    else:
        print("Error, arch error")
        return

    with open(global_variable.DOC_TMP_PATH + '/serverA/pkg.csv', 'r') as csv_file:
        csv_reader = csv.reader(csv_file)
        next(csv_reader)

        # 创建一个空字典用于存储映射关系
        csv_dict = {}

        # 遍历CSV文件的每一行
        for row in csv_reader:
            key = row[column1]
            value = row[column2]
            csv_dict[key] = value
        return csv_dict
