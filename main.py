from mysql_.domain import Domain
from mysql_.mysql_connector import get_mysql_connection
import threading
import mysql_.mysql_connector
from mysql_.task import Task
from uscan import exec_scan_command


def search_db_tasks():
    with mysql_.mysql_connector.get_mysql_connection() as connection:
        with connection.cursor() as cursor:
            query = "select * from tasks where status=1 or status=4"
            cursor.execute(query)
            results = cursor.fetchall()

    if len(results) != 0:
        threads = []
        for result in results:
            task = Task(result)
            if task.status == 4:
                task.update_status(2)
                continue

            task.update_status(11)
            thread = threading.Thread(target=mytask, args=(task,))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()


def mytask(task):
    stop = False
    domains = task.get_task_domains()
    for domain_obj in domains:
        task.update_self()
        if task.status == 4:
            stop = True
            break

        domain = Domain(domain_obj)
        if domain.done == 0:
            domain.update_done(1)
            try:
                exec_scan_command(domain)
                domain.update_done(2)
            except:
                domain.update_done(-1)
                domain.update_process(0)
                domain.append_information('扫描异常，退出扫描')
                domain.append_information('请检查目标主机的ssh连接')

    if not stop:
        task.update_status(3)
    else:
        task.update_status(2)

# search_db_tasks()
