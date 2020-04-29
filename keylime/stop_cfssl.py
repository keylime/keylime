import subprocess
import sys
import os

def main(argv=sys.argv):
    p: int = subprocess.call(["pkill", "-f", "cfssl serve"])

    if p == 1:
        print("Proccess not running")
    else:
        print("Killing cfssl")

    os.remove('%s/ca-key.pem'%secdir)
    os.remove('%s/cfsslconfig.yml'%secdir)


if __name__=="__main__":
    try:
        main()
    except Exception as e:
        print(e)
