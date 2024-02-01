# coding=utf-8
"""
@Time : 2024/1/3
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""

import shutil
import os
import zipfile
import global_variable


def merge_folders_and_files(folder_path, file_path, destination_folder):
    # 如果目标文件夹存在，先删除
    if os.path.exists(destination_folder):
        shutil.rmtree(destination_folder)

    # 创建目标文件夹
    os.makedirs(destination_folder)

    # 复制文件夹
    shutil.copytree(folder_path, os.path.join(destination_folder, os.path.basename(folder_path)))

    # 复制文件
    file_name = os.path.basename(file_path)
    destination_file = os.path.join(destination_folder, file_name)
    shutil.copy2(file_path, destination_file)


def zip_folder(folder_path, zip_name):
    # 创建一个Zip文件
    with zipfile.ZipFile(zip_name, 'w') as zipf:
        # 遍历文件夹中的所有文件和子文件夹
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                # 构建文件的完整路径
                file_path = os.path.join(root, file)
                # 将文件添加到Zip文件中，并使用相对路径保存
                zipf.write(file_path, os.path.relpath(file_path, folder_path))


def delete_folder(folder_path):
    # 检查文件夹是否存在
    if os.path.exists(folder_path):
        # 删除文件夹及其内容
        shutil.rmtree(folder_path)


def generate_zip(filename):
    folder_path = 'uscan_doc/doc_temple/html/other_lib'
    file_path = 'scan_doc/html/' + filename + '.html'
    destination_folder = global_variable.DOC_FILE_PATH + '/htmlzip/' + filename
    merge_folders_and_files(folder_path, file_path, destination_folder)

    zip_folder(destination_folder, destination_folder + '.zip')
    delete_folder(destination_folder)
