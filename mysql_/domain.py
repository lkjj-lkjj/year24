"""
@Time : 2024/1/24 上午11:30
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""
from mysql_.mysql_connector import get_mysql_connection


class Domain:
    def __init__(self, obj):
        self.id = obj[0]
        self.taskid = obj[1]
        self.host = obj[2]
        self.port = obj[3]
        self.username = obj[4]
        self.password = obj[5]
        self.repair = obj[6]
        self.word = obj[7]
        self.pdf = obj[8]
        self.html = obj[9]
        self.excel = obj[10]
        self.update = obj[11]
        self.done = obj[12]
        self.word_link = obj[13]
        self.pdf_link = obj[14]
        self.html_link = obj[15]
        self.excel_link = obj[16]
        self.scan_result = obj[17]
        self.scan_pkg_nums = obj[18]
        self.official_source = obj[19]
        self.process = obj[20]
        self.information = obj[21]

    def update_done(self, done):
        with get_mysql_connection() as connection:
            with connection.cursor() as cursor:
                query = "UPDATE domains SET done=%s WHERE id=%s"
                cursor.execute(query, (done, self.id))
                connection.commit()

    def insert_scan_data(self, word_link, pdf_link, html_link, excel_link, scan_result, scan_pkg_nums):
        with get_mysql_connection() as connection:
            with connection.cursor() as cursor:
                query = "update domains set word_link=%s, pdf_link=%s, html_link=%s, excel_link=%s, scan_result=%s, scan_pkg_nums=%s where id=%s"
                cursor.execute(query, (word_link, pdf_link, html_link, excel_link, scan_result, scan_pkg_nums, self.id))
                connection.commit()

    def append_information(self, new_information):
        with get_mysql_connection() as connection:
            with connection.cursor() as cursor:
                query1 = "select information from domains where id=%s"
                cursor.execute(query1, (self.id,))
                results = cursor.fetchall()
                old_information = results[0][0]
                query2 = "update domains set information=%s where id=%s"
                cursor.execute(query2, (old_information + new_information + '\n', self.id))
                connection.commit()
                self.information = old_information + '\n' + new_information

    def update_process(self, process):
        with get_mysql_connection() as connection:
            with connection.cursor() as cursor:
                query = "update domains set process=%s where id=%s"
                cursor.execute(query, (process, self.id))
                connection.commit()

