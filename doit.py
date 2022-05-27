import frida
import sys

jscode = """

Java.perform(function(){
//libunity.so
//libil2cpp.so

    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset = 0x11DF7A8;         //需要hook的函数的偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    //write_data(n_addr_so+"m");
;   console.log(n_addr_so)
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var ptr_func = new NativePointer(n_addr_func);
    //const DoubleCast = new NativeFunction(n_addr_func, 'void', ['bool']);
    //var ptr_func = Module.findExportByName("libjnitest.so","test_add") //对函数名hook

    Interceptor.attach(ptr_func,{ 
        //onEnter: 进入该函数前要执行的代码，其中args是传入的参数，一般so层函数第一个参数都是JniEnv，第二个参数是jclass，从第三个参数开始是我们java层传入的参数
        onEnter: function(args) {
           // send("Hook start");
            //write_data(arg[0]);
            //args.replace(1)
           
            
//arg[1]=1;
        },
        onLeave: function(retval){ //onLeave: 该函数执行结束要执行的代码，其中retval参数即是返回值
            send("return:"+retval); //返回值
          //retval.replace(1); //替换返回值为100
            //返回字符串时
            //var env = Java.vm.getEnv(); //获取env对象，即第一个参数
            //var jstrings = env.newStringUtf("xxxx"); //返回的是字符串指针，构造一个newStringUtf对象用来代替这个指针
            //retval.replace(jstrings); //替换返回值

        }
    });
});
"""
def message(message, data):
    if message["type"] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

process = frida.get_remote_device().attach('Bloons TD 6')
script= process.create_script(jscode)
script.on("message", message)
script.load()
sys.stdin.read()
