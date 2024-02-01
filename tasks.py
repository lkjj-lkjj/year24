"""
@Time : 2024/1/22 上午9:46
@GROUP : 安全技术部
@AUTH : 李可佳
@EMAIL : security@uniontech.com
@COPY_RIGHT : Copyright (C) 2024 Uniontech Security All Rights Reserved.
"""
import threading
from celery import Celery
from datetime import timedelta
import mysql_.mysql_connector
from mysql_.task import Task
from main import mytask
from concurrent.futures import ThreadPoolExecutor

app = Celery('tasks', broker='redis://localhost')

max_task_size = 10

executor = ThreadPoolExecutor(max_workers=max_task_size)

app.conf.beat_schedule = {
    'my-task': {
        'task': 'tasks.search_db_tasks',  # 任务的名称
        'schedule': timedelta(seconds=5),  # 每隔 5 秒执行一次
        'options': {'max_instances': 10}
    },
}


@app.task
def search_db_tasks():
    with mysql_.mysql_connector.get_mysql_connection() as connection:
        with connection.cursor() as cursor:
            query = "select * from tasks where status=1 or status=4"
            cursor.execute(query)
            results = cursor.fetchall()

    if len(results) != 0:
        task_threads = []
        for result in results:
            task = Task(result)

            if task.status == 4:
                task.update_status(2)
                continue

            task_thread = executor.submit(mytask, task)
            task.update_status(11)
            task_threads.append(task_thread)

        for future in task_threads:
            future.result()
