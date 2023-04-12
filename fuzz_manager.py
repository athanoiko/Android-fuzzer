import frida
import time
import sys

device = frida.get_usb_device()
pid = device.spawn('com.oiko.vulnerableapp')
time.sleep(1)
session = device.attach(pid)
script = session.create_script(open("agent.js").read())
time.sleep(2)
script.load()
device.resume(pid)

sys.stdin.read()