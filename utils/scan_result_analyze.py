"""
@Time : 2024/1/24 下午6:05
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""


def cal_lever(vuls):
    fixed_num = 0
    serve_num = 0
    high_num = 0
    medium_num = 0
    low_num = 0

    for vul in vuls:
        if vul['score'] is not None and vul['score'] != '':
            if vul['is_fixed']:
                fixed_num += 1

            if float(vul['score']) < 4.0:
                low_num += 1
            elif float(vul['score']) < 7.0:
                medium_num += 1
            elif float(vul['score']) < 9.0:
                high_num += 1
            else:
                serve_num += 1
        else:
            low_num += 1

    return fixed_num, serve_num, high_num, medium_num, low_num
