import MySQLdb
from sql import *
from sql.aggregate import *
import sys


class PacketStorage:
    def __init__(self, config):
        self.__insid = 0
        self.commitsize = 100
        self.db = MySQLdb.connect(host=config["host"],
                                  user=config["user"],
                                  passwd=config["password"],
                                  db=config["db"])

        # self.db.autocommit(False)

    def autocommit(self, val):
        self.db.autocommit(val)

    def add_igmp(self, pkt):
        # igmpRecord = Table("igmp")
        # instm = igmpRecord.insert(columns=[
        #     igmpRecord.time,
        #     igmpRecord.src,
        #     igmpRecord.dst,
        #     igmpRecord.msrc,
        #     igmpRecord.mdst,
        #     igmpRecord.group,
        #     igmpRecord.type,
        #     igmpRecord.ver
        # ], values=[[
        #     pkt["time"],
        #     pkt["src"],
        #     pkt["dst"],
        #     pkt["msrc"],
        #     pkt["mdst"],
        #     pkt["group"],
        #     pkt["type"],
        #     pkt["ver"]
        # ]])
        # tpl = tuple(instm)
        try:
            cur = self.db.cursor()
            res = cur.execute('INSERT INTO `igmp` (`time`, `src`, `dst`, `msrc`, `mdst`, `group`, `type`, `ver`) ' +
                              'VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
                              [pkt[0],
                               pkt[1][0], pkt[1][1],
                               pkt[2][0], pkt[2][1],
                               pkt[3][1], pkt[3][0], pkt[3][2]])
            if res == 1:
                if self.__insid >= self.commitsize:
                    self.db.commit()
                    self.__insid = -1
                else:
                    left = self.commitsize - self.__insid
                    # print("Pkt #" + str(self.__insid) + " added, commit after " + str(left) )
                    # sys.stdout.flush()

                self.__insid += 1
                return cur.lastrowid
            return None
        except MySQLdb.Error, e:
            self.db.rollback()
            e = e

    def close(self):
        self.db.commit()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def setup(self):
        cur = self.db.cursor()
        sql = ("""DROP TABLE IF EXISTS `igmp`;""", \
               """CREATE TABLE `igmp` (
                    `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
                    `time` datetime DEFAULT NULL,
                    `src` varchar(16) CHARACTER SET utf8 DEFAULT NULL,
                    `dst` varchar(16) CHARACTER SET utf8 DEFAULT NULL,
                    `msrc` varchar(36) CHARACTER SET utf8 DEFAULT NULL,
                    `mdst` varchar(36) CHARACTER SET utf8 DEFAULT NULL,
                    `group` varchar(16) CHARACTER SET utf8 DEFAULT NULL,
                    `type` tinyint(4) DEFAULT NULL,
                    `ver` tinyint(4) DEFAULT NULL,
                    PRIMARY KEY (`id`)
                  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;""")
        try:
            cur.execute(sql[0])
            cur.execute(sql[1])
            self.db.commit()
        except MySQLdb.Error, e:
            self.db.rollback()

    def set_commitsize(self, db_commit_interval):
        self.commitsize = db_commit_interval
