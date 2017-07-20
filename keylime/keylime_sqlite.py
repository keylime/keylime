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
logger = common.init_logging('keylime_sqlite')
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
        
        if 'instance_id' not in cols_db or 'PRIMARY_KEY' not in cols_db['instance_id']:
            raise Exception("the primary key of the database must be instance_id")
        
        # turn off persistence by default in development mode
        if common.DEVELOP_IN_ECLIPSE and os.path.exists(self.db_filename):
            os.remove(self.db_filename)
            
        os.umask(0o077)
        kl_dir = os.path.dirname(os.path.abspath(self.db_filename))
        if not os.path.exists(kl_dir):
            os.makedirs(kl_dir, 0o700)
        if os.geteuid()!=0 and not common.DEVELOP_IN_ECLIPSE:
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
        return
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM main')
            rows = cur.fetchall()
    
            colnames = [description[0] for description in cur.description]
            print colnames
            for row in rows:
                print row
            
    def add_defaults(self,instance):
        for key in self.exclude_db.keys():
            instance[key] = self.exclude_db[key]
        return instance
            
    def add_instance(self,instance_id, d):        
        d = self.add_defaults(d)
        
        d['instance_id']=instance_id
    
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * from main where instance_id=?',(d['instance_id'],))
            rows = cur.fetchall()
            # don't allow overwrite
            if len(rows)>0:
                return None
            
            insertlist = []
            for key in sorted(self.cols_db.keys()):
                v = d[key]
                if key in self.json_cols_db and isinstance(d[key],dict):
                    v = json.dumps(d[key])
                insertlist.append(v)
            
            cur.execute('INSERT INTO main VALUES(?%s)'%(",?"*(len(insertlist)-1)),insertlist)
    
            conn.commit()
            
        # these are JSON strings and should be converted to dictionaries
        for item in self.json_cols_db:
            if d[item] is not None and isinstance(d[item],basestring):
                d[item] = json.loads(d[item])
                                      
        self.print_db()
        return d

    def remove_instance(self,instance_id):
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * from main where instance_id=?',(instance_id,))
            rows = cur.fetchall()
            if len(rows)==0:
                return False
            cur.execute('DELETE FROM main WHERE instance_id=?',(instance_id,))
            conn.commit()
        
        self.print_db()
        return True
        
    def update_instance(self,instance_id, key, value):
        if key not in self.cols_db.keys():
            raise Exception("Database key %s not in schema: %s"%(key,self.cols_db.keys()))
        
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            # marshall back to string
            if key in self.json_cols_db:
                value = json.dumps(value)
            cur.execute('UPDATE main SET %s = ? where instance_id = ?'%(key),(value,instance_id))
            conn.commit()
        
        self.print_db()
        return
    
    def update_all_instances(self,key,value):
        if key not in self.cols_db.keys():
            raise Exception("Database key %s not in schema: %s"%(key,self.cols_db.keys()))
        
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            # marshall back to string if needed
            if key in self.json_cols_db:
                value = json.dumps(value)
            cur.execute('UPDATE main SET %s = ?'%key,(value,))
            conn.commit()
        self.print_db()
        return
       
    def get_instance(self,instance_id):
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * from main where instance_id=?',(instance_id,))
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
    
    def get_instance_ids(self):
        with sqlite3.connect(self.db_filename) as conn:
            retval = []
            cur = conn.cursor()
            cur.execute('SELECT instance_id from main')
            rows = cur.fetchall()
            if len(rows)==0:
                return retval
            for i in rows:
                retval.append(i[0])
            return retval

    def count_instances(self):
        return len(self.get_instance_ids())

    def overwrite_instance(self,instance_id,instance):
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            for key in self.cols_db.keys():
                if key is 'instance_id':
                    continue
                if key in self.json_cols_db:
                    cur.execute('UPDATE main SET %s = ? where instance_id = ?'%(key),(json.dumps(instance[key]),instance_id))
                else:
                    cur.execute('UPDATE main SET %s = ? where instance_id = ?'%(key),(instance[key],instance_id))
            conn.commit()
        self.print_db()
        return
    
