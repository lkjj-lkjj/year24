# coding=utf-8
"""
@Time : 2024/1/3
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""

import pandas as pd
import global_variable


def generate_excel(exist_vul, cmd, system_version, time_ob, server_type):
    for item in exist_vul:
        if item['score'] == '-1':
            item['score'] = None
    df_sheet1 = pd.DataFrame(exist_vul)
    if server_type == "ServerA":
        select_column = ['cveid', 'source', 'score', 'level', 'is_fixed', 'affectPkg',
                         'fix_suggest', 'reference_link', 'cve_description']
        df_sheet1 = df_sheet1[select_column]
        custom_headers = ['漏洞ID', '受影响软件包', '漏洞评分', '漏洞等级', '是否已修复',
                          '受影响二进制软件包', '修复建议',
                          '参考链接', '漏洞描述']
    else:
        select_column = ['cveid', 'source', 'score', 'level', 'is_fixed', 'fix_suggest',
                         'reference_link', 'cve_description']
        df_sheet1 = df_sheet1[select_column]
        custom_headers = ['漏洞ID', '受影响软件包', '漏洞评分', '漏洞等级', '是否已修复', '修复建议',
                          '参考链接', '漏洞描述']

    scan_info = {'扫描器版本': '0.1', '目标主机IP': cmd.host, '目标主机用户': cmd.username,
                 '扫描用时(秒)': time_ob[2], '扫描起始时间': time_ob[0],
                 '扫描结束时间': time_ob[1], '目标主机系统版本': system_version}
    df_sheet2 = pd.DataFrame([scan_info], index=['主机信息'])

    filename = cmd.host + ' ' + time_ob[0] + ".xlsx"

    with pd.ExcelWriter(global_variable.DOC_FILE_PATH + "/excel/" + filename) as writer:
        df_sheet2.to_excel(writer, sheet_name='主机信息')
        df_sheet1.to_excel(writer, sheet_name='漏洞描述', header=custom_headers, index=False)

    return filename
