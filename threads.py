from threading import Thread, Lock, Condition
import time
import random
from Queue import Queue


class FlowBalancer:
    def __init__(self, capacity=0):
        self.queue = Queue(capacity)
        self.fn_produce = lambda: None
        self.fn_consume = lambda x: None
        self.producer = Thread(target=self.__produce)
        self.consumer = Thread(target=self.__consume, name="Consumer")
        self.should_finalize = False
        self.on_finalize = lambda: None

    def set_producer(self, prod_fn):
        self.fn_produce = prod_fn
        pass

    def set_consumer(self, cons_fn):
        self.fn_consume = cons_fn
        pass

    def run_consumer(self):
        self.consumer.start()
        return self.consumer

    def put(self, param):
        self.queue.put(param) 

    def __produce(self):
        pass

    def __consume(self):
        """
        Consumes the data in the queue endlessly
        :return:
        """
        while True:
            if self.queue.qsize()==0 and self.should_finalize:
                self.on_finalize()
                break
            qelem = self.queue.get()
            self.fn_consume(qelem)
            self.queue.task_done()

    def finalize(self, fn):
        """
        Sets a function that should be invoked whenever the queue is empty, and makes the consumer thread exit then.
        :param fn:
        :return:
        """
        self.should_finalize = True
        self.on_finalize = fn


