
import frida, sys
 
jsCode = """
Java.perform(function(){
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //��Ҫhook��so��
    var n_addr_func_offset = 0x1587B54;         //��Ҫhook�ĺ�����ƫ��
    var n_addr_so = Module.findBaseAddress(str_name_so); //���ص��ڴ�� ������ַ = so��ַ + ����ƫ��
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    send("native: " + nativePointer);
    Interceptor.attach(nativePointer, {
        onEnter: function(args){
            send("start....");
            send(args[0]);
            send(args[1]);
            send(args[2]);
            send(args[3]);


            //send('arg1: '+args[2].readCString());
            //send('arg2: '+args[3]);

            
        },
        onLeave: function(retval){
            send("retval:"+retval);
            retval.replace(1);
            //send("retval:"+ptr(Java.vm.tryGetEnv().getStringUtfChars(retval)).readCString());
            send("over.....")
        }
    });
});
""";
 
def message(message, data):
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)
 
process = frida.get_remote_device().attach("Bloons TD 6")
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()