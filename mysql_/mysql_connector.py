"""
@Time : 2024/1/22 上午11:15
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""
import mysql.connector.pooling

db_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name='uscan_db',
    pool_size=10,
    host='10.0.34.63',
    user='admin',
    password='likejia123',
    database='uscan'
)


def get_mysql_connection():
    return db_pool.get_connection()
