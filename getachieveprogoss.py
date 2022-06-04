
import frida, sys
 
jsCode = """
Java.perform(function(){
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0x2567064;         //需要hook的函数的偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    send("so基址："+n_addr_so);
    send("native: " + nativePointer);
    var progoss;
    var id;
    
    Interceptor.attach(nativePointer, {
        onEnter: function(args){
            send("start....");
            send(args[0]);
            send("id "+args[1]);
            send("value "+args[2]);
            send(args[3]);
            send(args[4]);
            id=args[1].toInt32();
            progoss=args[2];


        },
        onLeave: function(retval){
            send("retval:"+retval);
            send("成就id "+id)
            send("原进度 "+progoss.readFloat())
            if(id==1195){
            progoss.writeFloat(19999)}
            send("over.....")
        }
    });
    if(0){
    var nativePointer2 = new NativePointer(n_addr_func);
    var n_addr_func_offset2 = 0x11AC1C8; 
    var n_addr_func2 = parseInt(n_addr_so, 16) + n_addr_func_offset2;
    Interceptor.attach(nativePointer2, {
        onEnter: function(args){
            send("fun2  start....");
        },
        onLeave: function(retval){
            send("retval:"+retval);
            send(retval.toInt32())
            retval.replace(1);
            
            send("fun2  over.....")
        }
    });};
});
""";
 
def message(message, data):
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)
 
process = frida.get_remote_device().attach("Bloons TD 6")
# netstat -a -t -p
# kill -9 -pid
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()