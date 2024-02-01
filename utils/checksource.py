"""
@Time : 2024/1/8 下午2:09
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""
import os


def check_source(server_type, client):
    if server_type == 'Desktop' or server_type == 'ServerD':
        with client.open_sftp() as sftp:
            with sftp.file('/etc/apt/sources.list', 'r') as file1:
                for line in file1:
                    line = line.strip(' ')
                    if not line.startswith('#'):
                        if 'desktop-professional' not in line and 'eagle' not in line and 'fou' not in line:
                            return 1

    elif server_type == 'ServerA' or server_type == 'ServerC' or server_type == 'ServerE':
        with client.open_sftp() as sftp:
            source_files = sftp.listdir('/etc/yum.repos.d')

            for file_name in source_files:
                file_path = os.path.join('/etc/yum.repos.d', file_name)
                with sftp.file(file_path, 'r') as file:
                    for line in file:
                        line = line.strip(' ')
                        if line.startswith('name'):
                            if 'UnionTechOS' not in line:
                                return 1
    else:
        return 1

    return 0


