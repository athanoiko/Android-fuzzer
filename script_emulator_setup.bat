adb root
adb install C:\Users\thanos\Desktop\vulnerableAndroidApp\app\build\outputs\apk\debug\app-debug.apk
adb push "%~dp0\frida-server" /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"