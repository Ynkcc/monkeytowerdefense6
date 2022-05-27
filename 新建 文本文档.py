import frida
import sys
import subprocess
jscode = """
Java.perform(function(){
//libunity.so
//libil2cpp.so

    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset = 0xE82E3C;         //需要hook的函数的偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    //write_data(n_addr_so+"m");
;   console.log(n_addr_so); 
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var ptr_func = new NativePointer(n_addr_func);
    //var ptr_func = Module.findExportByName("libjnitest.so","test_add") //对函数名hook

    Interceptor.attach(ptr_func,{ 
        //onEnter: 进入该函数前要执行的代码，其中args是传入的参数，一般so层函数第一个参数都是JniEnv，第二个参数是jclass，从第三个参数开始是我们java层传入的参数
        onEnter: function(args) {
           // send("Hook start");
            //write_data(arg[0]);
            //args.replace(1)
            arg[0]=10000;
            
//arg[1]=1;
        },
        onLeave: function(retval){ //onLeave: 该函数执行结束要执行的代码，其中retval参数即是返回值
            //send("return:"+retval); //返回值
          //retval.replace(10000); //替换返回值为100
        }
    });
});
"""

def startser():
    subprocess.run("adb devices",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,encoding="utf-8")
    subprocess.run("adb forward tcp:42178 tcp:42178",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,encoding="utf-8")
    subprocess.run("adb shell su -c '/data/local/tmp/server64 -l 0.0.0.0:42178'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,encoding="utf-8")


    
    

def message(message, data):
    if message["type"] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

def main():
    
    host = '127.0.0.1:42178'
    manager = frida.get_device_manager()
    device= manager.add_remote_device(host)
    process = device.attach('Bloons TD 6')
    script= process.create_script(jscode)
    script.on("message", message)
    script.load()
    sys.stdin.read()
#startser()

main()