# Bundling Keylime Cloud Agent into a portable tarball

These notes provide a rough guide for building a portable tarball for the Cloud Agent.

## Automated

Particularly if your Keylime cloud agent will be running on a bare-bones system (e.g., without libc installed), it can be useful to create a tarball of the Cloud Agent service which includes all needed dependencies.  

This tarball can be generated as part of the automated installer process by using the `-t` option *(Create tarball with keylime_agent)* during installation.  This builds a semi-portable agent binary (keylime_agent) and tarballs it along with all needed dependencies. 

You can also choose to do this directly with the `make_agent_bundle_tarball.sh` script in the keylime directory, which automatically installs all needed tools, builds the semi-portable binary and tarballs it with all of its library dependencies.  This tarball will appear in the dist folder.

If only the semi-portable binary is needed (without library dependencies), then it can be found alongside the tarball in the dist folder (keylime_agent). 

## Manual (semi-portable binary only)

You can build a single binary for the keylime_agent service.  It uses http://www.pyinstaller.org/  Install with `pip install pyinstaller`

Make sure that you have UPX for binary compression.  On ubuntu: `apt-get install upx-ucl`.

Ensure that you have the tools needed to install keylime normally (see section above). On Ubuntu:
`apt-get install -y python-dev python-setuptools python-tornado python-m2crypto python-zmq`.  Now pull in the rest of the python dependencies with `sudo python setup.py install`

Now you can run `make_agent_bundle.sh` in the keylime directory.  The single binary will appear inside the dist folder.  You can distribute this file along with keylime.conf and run the agent service without any other Keylime dependencies.  It will look for the conf file in /etc/ first and then in the same directory as the keylime_agent binary.

## Notes

1. *Due to a bug in pyinstaller 3.2.1 and prior, you may receive errors when running keylime_agent (e.g., cannot load Cryptodome).  For more information, refer to their patch for this bug (https://github.com/pyinstaller/pyinstaller/pull/2453).*
    
    *For this reason, it is recommended to use at least pyinstaller 3.3.  If your system does not have pyinstaller 3.3+, you can mitigate this issue by copying their hook file [PyInstaller/hooks/hook-Cryptodome.py](https://raw.githubusercontent.com/pyinstaller/pyinstaller/dacc07f49e2c22bba5473f4cb5b2a5194cdae5e1/PyInstaller/hooks/hook-Cryptodome.py) into your ``PyInstaller/hooks/`` directory (e.g.,/usr/local/lib/python2.7/dist-packages/PyInstaller/hooks/ or /usr/lib/python2.7/site-packages/PyInstaller/hooks/).*
    
2. *In some cases (e.g., if your target machine already has Python installed), it may be necessary to compile Python (on the build machine) with rpath defined for pyinstaller to work properly:*
    
    ```
    ./configure --enable-shared --prefix=<path_to_python> LDFLAGS=-Wl,-rpath=<path_to_python_libs>
    ```
    
    *See https://bugs.python.org/issue27685 for more information.*
