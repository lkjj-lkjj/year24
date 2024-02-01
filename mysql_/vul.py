"""
@Time : 2024/1/31 下午4:56
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""
from mysql_.mysql_connector import get_mysql_connection


class Vul:
    def __init__(self, obj):
        self.domainid = obj[0]
        self.cveid = obj[1]
        self.local_version = obj[2]
        self.fixed_version = obj[3]
        self.isfixed = obj[4]

    def insert(self):
        with get_mysql_connection() as connection:
            with connection.cursor() as cursor:
                query = "insert into vuls(domainid, cveid, local_version, fixed_version, isfixed) values(%s, %s, %s, %s, %s)"
                cursor.execute(query, (self.domainid, self.cveid, self.local_version, self.fixed_version, self.isfixed))
                connection.commit()
