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
import asyncio
import aiosqlite
import os
import sqlite3
import yaml

from keylime import common

logger = common.init_logging('keylime_sqlite')

class KeylimeDB():
    db_filename = None
    # in the form key, SQL type
    cols_db = None
    # these are the columns that contain yaml data and need marshalling
    yaml_cols_db = None
    # in the form key : default value
    exclude_db = None

    def __init__(self,dbname,cols_db,yaml_cols_db,exclude_db):
        self.db_filename = dbname
        self.cols_db = cols_db
        self.yaml_cols_db = yaml_cols_db
        self.exclude_db = exclude_db

        if 'agent_id' not in cols_db or 'PRIMARY_KEY' not in cols_db['agent_id']:
            raise Exception("the primary key of the database must be agent_id")

        # turn off persistence by default in development mode
        if common.DEVELOP_IN_ECLIPSE and os.path.exists(self.db_filename):
            os.remove(self.db_filename)

        # create the database file and perms
        os.umask(0o077)
        kl_dir = os.path.dirname(os.path.abspath(self.db_filename))
        if not os.path.exists(kl_dir):
            os.makedirs(kl_dir, 0o700)
        if os.geteuid()!=0 and common.REQUIRE_ROOT:
            logger.warning("Creating database without root.  Sensitive data may be at risk!")

    async def create_db(self):
        async with aiosqlite.connect(self.db_filename) as db:
            createstr = "CREATE TABLE IF NOT EXISTS main("
            for key in sorted(self.cols_db.keys()):
                createstr += "%s %s, "%(key,self.cols_db[key])
            # lop off the last comma space
            createstr = createstr[:-2]+')'
            await db.execute(createstr)
            await db.commit()

        os.chmod(self.db_filename,0o600)

    async def print_db(self):
        async with aiosqlite.connect(self.db_filename) as db:
            cursor = await db.execute('SELECT * FROM main')
            rows = await cursor.fetchall()
            colnames = [description[0] for description in cursor.description]

    def add_defaults(self,agent):
        for key in list(self.exclude_db.keys()):
            agent[key] = self.exclude_db[key]
        return agent

    async def add_agent(self,agent_id, d):
        d = self.add_defaults(d)

        d['agent_id']=agent_id

        async with aiosqlite.connect(self.db_filename) as db:

            cursor = await db.execute('SELECT * from main where agent_id=?',(d['agent_id'],))
            rows = await cursor.fetchall()
            # don't allow overwrite
            if len(rows)>0:
                return None

            insertlist = []
            for key in sorted(self.cols_db.keys()):
                v = d[key]
                if key in self.yaml_cols_db and (isinstance(d[key],dict) or isinstance(d[key],list)):
                    v = yaml.dump(d[key])
                insertlist.append(v)

            await db.execute('INSERT INTO main VALUES(?%s)'%(",?"*(len(insertlist)-1)),insertlist)

            await db.commit()

        # these are yaml strings and should be converted to dictionaries
        for item in self.yaml_cols_db:
            if d[item] is not None and isinstance(d[item],str):
                d[item] = yaml.safe_load(d[item])

        return d

    async def remove_agent(self,agent_id):
        async with aiosqlite.connect(self.db_filename) as db:

            cursor = await db.execute('SELECT * from main where agent_id=?',(agent_id,))
            rows = await cursor.fetchall()
            if len(rows)==0:
                return False
            await db.execute('DELETE FROM main WHERE agent_id=?',(agent_id,))
            await db.commit()
        return True

    async def update_agent(self,agent_id, key, value):
        if key not in list(self.cols_db.keys()):
            raise Exception("Database key %s not in schema: %s"%(key,list(self.cols_db.keys())))

        async with aiosqlite.connect(self.db_filename) as db:

            # marshall back to string
            if key in self.yaml_cols_db:
                value = yaml.dump(value)
            await db.execute('UPDATE main SET %s = ? where agent_id = ?'%(key),(value,agent_id))
            await db.commit()
        return

    async def update_all_agents(self,key,value):
        if key not in list(self.cols_db.keys()):
            raise Exception("Database key %s not in schema: %s"%(key,list(self.cols_db.keys())))

        async with aiosqlite.connect(self.db_filename) as db:
            # marshall back to string if needed
            if key in self.yaml_cols_db:
                value = yaml.dump(value)
            await db.execute('UPDATE main SET %s = ?'%key,(value,))
            await db.commit()
        return

    async def get_agent(self,agent_id):
        async with aiosqlite.connect(self.db_filename) as db:
            cursor = await db.execute('SELECT * from main where agent_id=?',(agent_id,))
            rows = await cursor.fetchall()
            if len(rows)==0:
                return None

            colnames = [description[0] for description in cursor.description]
            d ={}
            for i in range(len(colnames)):
                if colnames[i] in self.yaml_cols_db:
                    d[colnames[i]] = yaml.safe_load(rows[0][i])
                else:
                    d[colnames[i]]=rows[0][i]
            d = self.add_defaults(d)
            return d

    async def get_agent_ids(self):
        async with aiosqlite.connect(self.db_filename) as db:
            retval = []
            cursor = await db.execute('SELECT agent_id from main')
            rows = await cursor.fetchall()
            if len(rows)==0:
                return retval
            for i in rows:
                retval.append(i[0])
            return retval

    async def count_agents(self):
        return len(await self.get_agent_ids()) # hmm

    async def overwrite_agent(self,agent_id,agent):
        async with aiosqlite.connect(self.db_filename) as db:
            for key in list(self.cols_db.keys()):
                if key is 'agent_id':
                    continue
                if key in self.yaml_cols_db:
                    await db.execute('UPDATE main SET %s = ? where agent_id = ?'%(key),(yaml.dump(agent[key]),agent_id))
                else:
                    await db.execute('UPDATE main SET %s = ? where agent_id = ?'%(key),(agent[key],agent_id))
            await db.commit()
        return

