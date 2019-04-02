# -*- mode: python -*-

block_cipher = None

added_files = [
		( '/usr/local/bin/tpm2_*', '.' ),
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
          name='keylime_agent_tpm2',
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
