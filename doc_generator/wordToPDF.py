# coding=utf-8
"""
@Time : 2024/1/3
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""

import os
import subprocess
import global_variable


def convert_to_pdf(input_docx, output_pdf):
    try:
        # a = subprocess.run(["libreoffic", "--headless", "--convert-to", "pdf", "--outdir", output_pdf, input_docx],
        #                check=True)
        # print('asd')
        cmd = "libreoffice --headless --convert-to pdf --outdir '{}' '{}'".format(output_pdf, input_docx)
        ret, output = subprocess.getstatusoutput(cmd)
        if ret != 0:
            print("未找到libreoffice库，生成PDF文件失败")
    except subprocess.CalledProcessError as e:
        print(f"Conversion failed. Error: {e}")


def generate_pdf(filename):
    input_docx_file = global_variable.DOC_FILE_PATH + "/word/" + filename + ".docx"
    output_pdf_file = global_variable.DOC_FILE_PATH + "/pdf"
    convert_to_pdf(input_docx_file, output_pdf_file)
    return filename+'.pdf'
