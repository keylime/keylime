# Webserver Demo

Both the keyfile.txt and autorun.sh files should be sent to the node (via "CA Dir" mode provisioning).  

`keylime_tenant -t 192.168.0.100 -u my_node_id --cert default --include node_files_dir`

The payload.enc file should be in the web server HTML directory
(demo_setup.sh will put it there). 
