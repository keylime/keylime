# Additional Example IMA Policies

## Files 

This directory contains the following example policies: 
* **ima-policy-default**: The default IMA TCG policy, measuring all executed files and all files opened for read by root.  Appraises files owned by root. 
* **ima-policy-keylime**: Less burdensome policy that measures all executed files.  Ignores SELinux-specific files.
* **ima-policy-keylime-etc**: Similar to above, but also measures all /etc/ files (as marked by SELinux)

