#!/usr/bin/python

'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for 
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the 
Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
above. Use of this work other than as specifically authorized by the U.S. Government may 
violate any copyrights that exist in this work.
'''

from urlparse import urlparse
import json
import base64
import time
import common
import registrar_client
import tpm_quote
import tpm_initialize
import os
import crypto
import ssl
import socket
import ca_util
import sqlite3

logger = common.init_logging('cloudverifier_common')

class CloudInstance_Operational_State:
    START = 1
    SAVED = 2
    GET_QUOTE = 3
    GET_QUOTE_RETRY = 4
    PROVIDE_V = 5
    PROVIDE_V_RETRY = 6 
    FAILED = 7
    TERMINATED = 8   
    INVALID_QUOTE = 9

class Timer(object):
    def __init__(self, verbose=False):
        self.verbose = verbose

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        self.end = time.time()
        self.secs = self.end - self.start
        self.msecs = self.secs * 1000  # millisecs
        if self.verbose:
            print 'elapsed time: %f ms' % self.msecs
            
def init_tls(config,section='cloud_verifier',verifymode=ssl.CERT_REQUIRED,generatedir='cv_ca',need_client=True):
    if not config.getboolean('general',"enable_tls"):
        logger.warning("TLS is currently disabled, keys will be sent in the clear! Should only be used for testing.")
        return None
    
    logger.info("Setting up TLS...")
    my_cert = config.get(section, 'my_cert')
    ca_cert = config.get(section, 'ca_cert')
    my_priv_key = config.get(section, 'private_key')
    my_key_pw = config.get(section,'private_key_pw')
    tls_dir = config.get(section,'tls_dir')

    if tls_dir =='generate':
        if my_cert!='default' or my_priv_key !='default' or ca_cert !='default':
            raise Exception("To use tls_dir=generate, options ca_cert, my_cert, and private_key must all be set to 'default'")
        
        if generatedir[0]!='/':
            generatedir =os.path.abspath('%s/%s'%(common.WORK_DIR,generatedir))
        tls_dir = generatedir
        ca_path = "%s/cacert.crt"%(tls_dir)
        if os.path.exists(ca_path):
            logger.info("Existing CA certificate found in %s, not generating a new one"%(tls_dir))
        else:    
            logger.info("Generating a new CA in %s and a tenant certificate for connecting"%tls_dir)
            logger.info("use keylime_ca -d %s to manage this CA"%tls_dir)
            if not os.path.exists(tls_dir):
                os.makedirs(tls_dir,0o700)
            if my_key_pw=='default':
                logger.warning("CAUTION: using default password for CA, please set private_key_pw to a strong password")
            ca_util.setpassword(my_key_pw)
            ca_util.cmd_init(tls_dir)
            ca_util.cmd_mkcert(tls_dir, socket.gethostname())
            if need_client:
                ca_util.cmd_mkcert(tls_dir, 'tenant')
    
    if tls_dir == 'CV':
        if section !='registrar':
            raise Exception("You only use the CV option to tls_dir for the registrar not %s"%section)
        tls_dir = os.path.abspath('%s/%s'%(common.WORK_DIR,'cv_ca'))
        if not os.path.exists("%s/cacert.crt"%(tls_dir)):
            raise Exception("It appears that the verifier has not yet created a CA and certificates, please run the verifier first")

    # if it is relative path, convert to absolute in WORK_DIR
    if tls_dir[0]!='/':
        tls_dir = os.path.abspath('%s/%s'%(common.WORK_DIR,tls_dir))
            
    if ca_cert == 'default':
        ca_path = "%s/cacert.crt"%(tls_dir)
    else:
        ca_path = "%s/%s"%(tls_dir,ca_cert)

    if my_cert=='default':
        my_cert = "%s/%s-cert.crt"%(tls_dir,socket.gethostname())
    else:
        my_cert = "%s/%s"%(tls_dir,my_cert)
        
    if my_priv_key=='default':
        my_priv_key = "%s/%s-private.pem"%(tls_dir,socket.gethostname())
    else:
        my_priv_key = "%s/%s"%(tls_dir,my_priv_key)
        
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_verify_locations(cafile=ca_path)
    context.load_cert_chain(certfile=my_cert,keyfile=my_priv_key,password=my_key_pw)
    context.verify_mode = verifymode
    return context

def process_quote_response(instance, json_response, config):
    """Validates the response from the Cloud node.
    
    This method invokes an Registrar Server call to register, and then check the quote. 
    """
    received_public_key = None
    quote = None
    
    # in case of failure in response content do not continue
    try:        
        received_public_key =json_response.get("pubkey",None)
        quote = json_response["quote"]
        ima_list = json_response.get("ima_list",None)
        
        logger.debug("received quote:      %s"%quote)
        logger.debug("for nonce:           %s"%instance['nonce'])
        logger.debug("received public key: %s"%received_public_key)
        logger.debug("received ima_list    %s"%(ima_list!=None))
    except Exception:
        return None
    
    # if no public key provided, then ensure we have cached it
    if received_public_key is None:
        if instance.get('public_key',"") == "" or instance.get('b64_encrypted_V',"")=="":
            logger.error("node did not provide public key and no key or encrypted_v was cached at CV")
            return False
        instance['provide_V'] = False
        received_public_key = instance['public_key']
    
    if instance.get('aikFromRegistrar',"") is "" or instance.get('aikFromRegistrarCacheHits',common.MAX_STALE_REGISTRAR_CACHE)>=common.MAX_STALE_REGISTRAR_CACHE:
        # talk to yourself fool
        registrar_client.serverAuthTLSContext(config,'cloud_verifier')
        aikFromRegistrar = registrar_client.getAIK(config.get("general","registrar_ip"),config.get("general","registrar_port"),instance['instance_id'])
        if aikFromRegistrar is None:
            logger.warning("AIK not found in registrar, quote not validated")
            return False
        instance['aikFromRegistrar']  = aikFromRegistrar
        instance['aikFromRegistrarCacheHits'] = 0
    else:
        aikFromRegistrar = instance['aikFromRegistrar']
        instance['aikFromRegistrarCacheHits'] += 1
        
    if not instance['vtpm_policy']:
        validQuote = tpm_quote.check_quote(instance['nonce'],received_public_key,quote,aikFromRegistrar,instance['tpm_policy'],ima_list)
    else:
        registrar_client.serverAuthTLSContext(config,'cloud_verifier')
        dq_aik = registrar_client.getAIK(config.get("general","provider_registrar_ip"), config.get("general","provider_registrar_port"), instance['instance_id'])
        if dq_aik is None:
            logger.warning("provider AIK not found in registrar, deep quote not validated")
            return False
        validQuote = tpm_quote.check_deep_quote(instance['nonce'],received_public_key,quote,aikFromRegistrar,dq_aik,instance['vtpm_policy'],instance['tpm_policy'],ima_list=ima_list)
    if not validQuote:
        return False
    
    # has public key changed? if so, clear out b64_encrypted_V, it is no longer valid
    if received_public_key != instance.get('public_key',""):
        instance['public_key'] = received_public_key
        instance['b64_encrypted_V'] = ""
        instance['provide_V'] = True

    # ok we're done
    return validQuote


def prepare_v(instance):
    # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
    if common.DEVELOP_IN_ECLIPSE:
        logger.debug("b64_V (non encrypted): " + instance['v'])
        
    if instance.get('b64_encrypted_V',"") !="":
        b64_encrypted_V = instance['b64_encrypted_V']
        logger.debug("Re-using cached encrypted V")
    else:
        # encrypt V with the public key
        b64_encrypted_V = base64.b64encode(crypto.rsa_encrypt(crypto.rsa_import_pubkey(instance['public_key']),str(base64.b64decode(instance['v']))))
        instance['b64_encrypted_V'] = b64_encrypted_V
        
    logger.debug("b64_encrypted_V:" + b64_encrypted_V)
    post_data = {
              'encrypted_key': b64_encrypted_V
            }
    v_json_message = json.dumps(post_data)
    return v_json_message
    
def prepare_get_quote(instance):
    """This method encapsulates the action required to invoke a quote request on the Cloud Node.
    
    This method is part of the polling loop of the thread launched on Tenant POST. 
    """
    instance['nonce'] = tpm_initialize.random_password(20)
    
    params = {
        'nonce': instance['nonce'],
        'mask': instance['tpm_policy']['mask']
        }
    
    if instance['vtpm_policy']:
        params['vmask'] = instance['vtpm_policy']['mask']
        
    if instance.get('public_key',"")=="":
        params['need_pubkey'] = "True"
    
    return params

def process_get_status(instance):
    response = {'operational_state':instance['operational_state'],
                'v':instance['v'],
                'ip':instance['ip'],
                'port':instance['port'],
                'tpm_policy':instance['tpm_policy'],
                'vtpm_policy':instance['vtpm_policy'],
                }
    return json.dumps(response)  
  

def is_instance_resource(path):
    """Returns True if this is a valid instances uri i.e /v1/instances, else False. Trailing slash optional."""  
    parsed_path = urlparse(path.strip("/"))
    tokens = parsed_path.path.split('/')
    return len(tokens) == 2 and tokens[0] == 'v1' and tokens[1] == 'instances'

def get_query_tag_value(path, query_tag):
    """This is a utility method to query for specific the http parameters in the uri.  
    
    Returns the value of the parameter, or None if not found."""  
    data = { }
    parsed_path = urlparse(path)
    query_tokens = parsed_path.query.split('&')
    # find the 'ids' query, there can only be one
    for tok in query_tokens:
        query_tok = tok.split('=')
        query_key = query_tok[0]
        if query_key is not None and query_key == query_tag:
            # ids tag contains a comma delimited list of ids
            data[query_tag] = query_tok[1]    
            break        
    return data.get(query_tag,None) 

def handleVerificationError(instance):
    ###########################################################################
    # TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
    # DO SOMETHING HERE to signal that bad stuff is happening in the system, like a web service call
    # to some admin server to act on the potential breach by shutting things down
    ###########################################################################
    return

# ===== sqlite stuff =====
global_db_filename = None

# in the form key, SQL type
cols_db = {
    'instance_id': 'TEXT PRIMARY_KEY',
    'v': 'TEXT',
    'ip': 'TEXT',
    'port': 'INT',
    'operational_state': 'INT',
    'public_key': 'TEXT',
    'tpm_policy' : 'TEXT', 
    'vtpm_policy' : 'TEXT', 
    }

# in the form key : default value
exclude_db = {
    'aikFromRegistrar': '',
    'aikFromRegistrarCacheHits': 0,
    'nonce': '',
    'b64_encrypted_V': '',
    'provide_V': True,
    'num_retries': 0,
    'pending_event': None,
    }

def init_db(db_filename):
    global global_db_filename
    global_db_filename = db_filename
    
    # turn off persistence by default in development mode
    if common.DEVELOP_IN_ECLIPSE and os.path.exists(global_db_filename):
        os.remove(global_db_filename)
    os.umask(0o077)
    kl_dir = os.path.dirname(os.path.abspath(global_db_filename))
    if not os.path.exists(kl_dir):
        os.makedirs(kl_dir, 0o700)
        
    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        createstr = "CREATE TABLE IF NOT EXISTS main("
        for key in sorted(cols_db.keys()):
            createstr += "%s %s, "%(key,cols_db[key])
        # lop off the last comma space
        createstr = createstr[:-2]+')'
        cur.execute(createstr)
        conn.commit()
    os.chmod(global_db_filename,0o600)
        
def print_db():
    return
    global global_db_filename
    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM main')
        rows = cur.fetchall()

        colnames = [description[0] for description in cur.description]
        print colnames
        for row in rows:
            print row
            
def add_defaults(instance):
    for key in exclude_db.keys():
        instance[key] = exclude_db[key]
    return instance
            
def add_instance(json_body):
    global global_db_filename
    """Threadsafe function to add an instance to the instances container."""
    # always overwrite instances with same ID
    d = {}
    d['instance_id'] = json_body['instance_id']
    d['v'] =json_body['v']
    d['ip'] = json_body['cloudnode_ip']
    d['port'] = int(json_body['cloudnode_port'])
    d['operational_state'] = CloudInstance_Operational_State.START
    d['public_key'] = ""
    d['tpm_policy'] = json_body['tpm_policy']
    d['vtpm_policy'] = json_body.get('vtpm_policy',"{}")
    
    d = add_defaults(d)

    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        cur.execute('SELECT * from main where instance_id=?',(d['instance_id'],))
        rows = cur.fetchall()
        # don't allow overwrite
        if len(rows)>0:
            return None
        
        insertlist = []
        for key in sorted(cols_db.keys()):
            insertlist.append(d[key])
        cur.execute('INSERT INTO main VALUES(?,?,?,?,?,?,?,?)',insertlist)

        conn.commit()
        
    # these are JSON strings and should be converted to dictionaries
    d['tpm_policy'] = json.loads(d['tpm_policy'])
    d['vtpm_policy'] = json.loads(d['vtpm_policy'])
                                  
    print_db()
    return d

def remove_instance(instance_id):
    global global_db_filename
    """Threadsafe function to remove an instance to the instances container."""
    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        cur.execute('SELECT * from main where instance_id=?',(instance_id,))
        rows = cur.fetchall()
        if len(rows)==0:
            return False
        cur.execute('DELETE FROM main WHERE instance_id=?',(instance_id,))
        conn.commit()
    
    print_db()
    return True
    
def update_instance(instance_id, key, value):
    global global_db_filename
    """Threadsafe function to query the existance of an instance in the instances container. Returns None 
    on failure, else the CloudInstance object"""
    if key not in cols_db.keys():
        raise Exception("Database key %s not in schema: %s"%(key,cols_db.keys()))
    
    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        if key is 'tpm_policy' or key is 'vtpm_policy':
            value = json.dumps(value)
        cur.execute('UPDATE main SET %s = ? where instance_id = ?'%(key),(value,instance_id))
        conn.commit()
    
    print_db()
    return
               
def get_instance(instance_id):
    global global_db_filename
    """Threadsafe function to query the existance of an instance in the instances container. Returns None 
    on failure, else the CloudInstance object"""   
    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        cur.execute('SELECT * from main where instance_id=?',(instance_id,))
        rows = cur.fetchall()
        if len(rows)==0:
            return None
        
        colnames = [description[0] for description in cur.description]
        d ={}
        for i in range(len(colnames)):
            if colnames[i] == u'tpm_policy' or colnames[i] == u'vtpm_policy':
                d[colnames[i]] = json.loads(rows[0][i])
            else:
                d[colnames[i]]=rows[0][i]
        d = add_defaults(d)
        return d
    
def get_instance_ids():
    global global_db_filename
    """Threadsafe function to query the existance of an instance in the instances container. Returns None 
    on failure, else the CloudInstance object"""
    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        cur.execute('SELECT instance_id from main')
        rows = cur.fetchall()
        if len(rows)==0:
            return '{}'
        retval = []
        for i in rows:
            retval.append(i[0])
        return json.dumps(retval)
    
def terminate_instance(instance_id):
    global global_db_filename
    retval = False
    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        cur.execute('SELECT * from main where instance_id=?',(instance_id,))
        rows = cur.fetchall()
        if len(rows)>0:
            colnames = [description[0] for description in cur.description]
            op_state = rows[0][colnames.index(u'operational_state')]
            
            if op_state == CloudInstance_Operational_State.SAVED or \
            op_state == CloudInstance_Operational_State.FAILED or \
            op_state == CloudInstance_Operational_State.INVALID_QUOTE:
                cur.execute('DELETE FROM main WHERE instance_id=?',(instance_id,))
            else:            
                cur.execute('UPDATE main SET operational_state = ? where instance_id = ?',(CloudInstance_Operational_State.TERMINATED,instance_id,))
            retval = True
    
    print_db()        
    return retval
    
def overwrite_instance(instance_id,instance):
    global global_db_filename
    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        for key in cols_db.keys():
            if key is 'instance_id':
                continue
            if key == 'tpm_policy' or key == 'vtpm_policy':
                cur.execute('UPDATE main SET %s = ? where instance_id = ?'%(key),(json.dumps(instance[key]),instance_id))
            else:
                cur.execute('UPDATE main SET %s = ? where instance_id = ?'%(key),(instance[key],instance_id))
        conn.commit()
    print_db()
    return

def set_saved():
    global global_db_filename
    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        cur.execute('UPDATE main SET operational_state = ?',(CloudInstance_Operational_State.SAVED,))
        conn.commit()
    print_db()
    return

def count_instances():
    global global_db_filename
    with sqlite3.connect(global_db_filename) as conn:
        cur = conn.cursor()
        cur.execute('SELECT instance_id from main')
        rows = cur.fetchall()
        return len(rows)
    
def test_sql(): 
    # testing
    db_filename = 'cv_testdata.sqlite'
    
    if os.path.exists(db_filename):
        os.remove(db_filename)
        
    init_db(db_filename)
    
    json_body = {
        'v': 'vbaby',
        'instance_id': '209483',
        'cloudnode_ip': 'ipaddy',
        'cloudnode_port': '39843',
        'tpm_policy': '{"a":"1"}',
        'vtpm_policy': '{"ab":"1"}',
        }
    
    json_body2 = {
        'v': 'vbaby',
        'instance_id': '2094aqrea3',
        'cloudnode_ip': 'ipaddy',
        'cloudnode_port': '39843',
        'tpm_policy': '{"ab":"1"}',
        'vtpm_policy': '{"ab":"1"}',
        }
    #some DB testing stuff
    print "testing add"
    add_instance(json_body)
    print 'testing update'
    update_instance('209483','v','NEWVVV')
    print 'testing remove'
    print remove_instance('209483')
    print_db()
    print 'testing get instance ids'
    add_instance(json_body)
    add_instance(json_body2)
    print get_instance_ids()
    
    print 'testing get instance'
    print get_instance(209483)
    
    print 'testing terminate'
    terminate_instance(209483)
    print get_instance(209483)
    
    print 'testing overwrite'
    instance = get_instance('2094aqrea3')
    instance['instance_id']=209483
    instance['v']='OVERWRITTENVVVV'
    overwrite_instance(209483, instance)
    print get_instance(209483)
    
    
    print 'testing set saved'
    set_saved()
    
    import sys
    sys.exit(0)

if __name__=="__main__":
    test_sql()