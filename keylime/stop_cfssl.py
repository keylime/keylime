import subprocess
import sys

def main(argv=sys.argv):
    p: int = subprocess.call(["pkill", "-f", "cfssl serve"])

    if p == 1:
        print("Proccess not running")
    else:
        print("Killing cfssl")


if __name__=="__main__":
    try:
        main()
    except Exception as e:
        print(e)
