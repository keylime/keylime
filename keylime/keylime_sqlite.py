'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2017 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''

import common
import keylime_logging
logger = keylime_logging.init_logging('keylime_sqlite')
import os
import sqlite3
import json

class KeylimeDB():
    db_filename = None
    # in the form key, SQL type
    cols_db = None
    # these are the columns that contain json data and need marshalling
    json_cols_db = None
    # in the form key : default value
    exclude_db = None

    def __init__(self,dbname,cols_db,json_cols_db,exclude_db):
        self.db_filename = dbname
        self.cols_db = cols_db
        self.json_cols_db = json_cols_db
        self.exclude_db = exclude_db

        if 'agent_id' not in cols_db or 'PRIMARY_KEY' not in cols_db['agent_id']:
            raise Exception("the primary key of the database must be agent_id")

        # turn off persistence by default in development mode
        if common.DEVELOP_IN_ECLIPSE and os.path.exists(self.db_filename):
            os.remove(self.db_filename)

        os.umask(0o077)
        kl_dir = os.path.dirname(os.path.abspath(self.db_filename))
        if not os.path.exists(kl_dir):
            os.makedirs(kl_dir, 0o700)
        if os.geteuid()!=0 and common.REQUIRE_ROOT:
            logger.warning("Creating database without root.  Sensitive data may be at risk!")

        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            createstr = "CREATE TABLE IF NOT EXISTS main("
            for key in sorted(self.cols_db.keys()):
                createstr += "%s %s, "%(key,self.cols_db[key])
            # lop off the last comma space
            createstr = createstr[:-2]+')'
            cur.execute(createstr)
            conn.commit()
        os.chmod(self.db_filename,0o600)

    def print_db(self):
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM main')
            rows = cur.fetchall()

            colnames = [description[0] for description in cur.description]
            print colnames
            for row in rows:
                print row

    def add_defaults(self,agent):
        for key in self.exclude_db.keys():
            agent[key] = self.exclude_db[key]
        return agent

    def add_agent(self,agent_id, d):
        d = self.add_defaults(d)

        d['agent_id']=agent_id

        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * from main where agent_id=?',(d['agent_id'],))
            rows = cur.fetchall()
            # don't allow overwrite
            if len(rows)>0:
                return None

            insertlist = []
            for key in sorted(self.cols_db.keys()):
                v = d[key]
                if key in self.json_cols_db and (isinstance(d[key],dict) or isinstance(d[key],list)):
                    v = json.dumps(d[key])
                insertlist.append(v)

            cur.execute('INSERT INTO main VALUES(?%s)'%(",?"*(len(insertlist)-1)),insertlist)

            conn.commit()

        # these are JSON strings and should be converted to dictionaries
        for item in self.json_cols_db:
            if d[item] is not None and isinstance(d[item],basestring):
                d[item] = json.loads(d[item])

        return d

    def remove_agent(self,agent_id):
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * from main where agent_id=?',(agent_id,))
            rows = cur.fetchall()
            if len(rows)==0:
                return False
            cur.execute('DELETE FROM main WHERE agent_id=?',(agent_id,))
            conn.commit()

        return True

    def update_agent(self,agent_id, key, value):
        if key not in self.cols_db.keys():
            raise Exception("Database key %s not in schema: %s"%(key,self.cols_db.keys()))

        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            # marshall back to string
            if key in self.json_cols_db:
                value = json.dumps(value)
            cur.execute('UPDATE main SET %s = ? where agent_id = ?'%(key),(value,agent_id))
            conn.commit()

        return

    def update_all_agents(self,key,value):
        if key not in self.cols_db.keys():
            raise Exception("Database key %s not in schema: %s"%(key,self.cols_db.keys()))

        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            # marshall back to string if needed
            if key in self.json_cols_db:
                value = json.dumps(value)
            cur.execute('UPDATE main SET %s = ?'%key,(value,))
            conn.commit()
        return

    def get_agent(self,agent_id):
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * from main where agent_id=?',(agent_id,))
            rows = cur.fetchall()
            if len(rows)==0:
                return None

            colnames = [description[0] for description in cur.description]
            d ={}
            for i in range(len(colnames)):
                if colnames[i] in self.json_cols_db:
                    d[colnames[i]] = json.loads(rows[0][i])
                else:
                    d[colnames[i]]=rows[0][i]
            d = self.add_defaults(d)
            return d

    def get_agent_ids(self):
        with sqlite3.connect(self.db_filename) as conn:
            retval = []
            cur = conn.cursor()
            cur.execute('SELECT agent_id from main')
            rows = cur.fetchall()
            if len(rows)==0:
                return retval
            for i in rows:
                retval.append(i[0])
            return retval

    def count_agents(self):
        return len(self.get_agent_ids())

    def overwrite_agent(self,agent_id,agent):
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            for key in self.cols_db.keys():
                if key is 'agent_id':
                    continue
                if key in self.json_cols_db:
                    cur.execute('UPDATE main SET %s = ? where agent_id = ?'%(key),(json.dumps(agent[key]),agent_id))
                else:
                    cur.execute('UPDATE main SET %s = ? where agent_id = ?'%(key),(agent[key],agent_id))
            conn.commit()
        return

