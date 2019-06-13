# -*- mode: python -*-

block_cipher = None

added_files = [
		( '/usr/local/bin/flushspecific', '.' ),
		( '/usr/local/bin/createek', '.' ),
		( '/usr/local/bin/getpubek', '.' ),
		( '/usr/local/bin/takeown', '.' ),
		( '/usr/local/bin/identity', '.' ),
		( '/usr/local/bin/getpubkey', '.' ),
		( '/usr/local/bin/listkeys', '.' ),
		( '/usr/local/bin/loadkey', '.' ),
		( '/usr/local/bin/activateidentity', '.' ),
		( '/usr/local/bin/getcapability', '.' ),
		( '/usr/local/bin/nv_definespace', '.' ),
		( '/usr/local/bin/nv_writevalue', '.' ),
		( '/usr/local/bin/nv_readvalue', '.' ),
		( '/usr/local/bin/pcrreset', '.' ),
		( '/usr/local/bin/extend', '.' ),
		( '/usr/local/bin/deepquote', '.' ),
		( '/usr/local/bin/tpmquote', '.' ),
		( '/usr/local/bin/getrandom', '.' ),
		( '/usr/local/bin/resetlockvalue', '.'),
		( 'build/crypto/*.so', '.' ),
         ]

a = Analysis(['cloud_agent.py'],
             pathex=['.'],
             binaries=None,
             datas=added_files,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
#          exclude_binaries=True,
          name='keylime_agent_tpm1',
          debug=False,
          strip=False,
          upx=True,
          console=True )
          
#coll = COLLECT(exe,
#               a.binaries,
#               a.zipfiles,
#               a.datas,
#               strip=False,
#               upx=True,
#               name='cloud_agent')
