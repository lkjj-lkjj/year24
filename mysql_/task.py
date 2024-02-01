"""
@Time : 2024/1/22 下午2:05
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""
from .mysql_connector import get_mysql_connection


class Task:
    def __init__(self, obj):
        self.id = obj[0]
        self.userid = obj[1]
        self.dt = obj[2]
        self.name = obj[3]
        self.status = obj[4]
        self.result_link = obj[5]

    def update_status(self, status):
        with get_mysql_connection() as connection:
            with connection.cursor() as cursor:
                query = "UPDATE tasks SET status=%s WHERE id=%s"
                cursor.execute(query, (status, self.id))
                connection.commit()

    def get_task_domains(self):
        with get_mysql_connection() as connection:
            with connection.cursor() as cursor:
                query = "select * from domains where taskid=%s"
                cursor.execute(query, (self.id,))
                results = cursor.fetchall()
                return results

    def update_self(self):
        with get_mysql_connection() as connection:
            with connection.cursor() as cursor:
                query = "select * from tasks where id=%s"
                cursor.execute(query, (self.id,))
                results = cursor.fetchall()
                obj = results[0]

                self.id = obj[0]
                self.userid = obj[1]
                self.dt = obj[2]
                self.name = obj[3]
                self.status = obj[4]
                self.result_link = obj[5]
