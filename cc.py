
import frida, sys
 
jsCode = """
Java.perform(function(){
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0x14F5990;         //需要hook的函数的偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    send("so基址："+n_addr_so);
    send("native: " + nativePointer);
    
    Interceptor.attach(nativePointer, {
        onEnter: function(args){
            send("start....");
            send(args[0]);
            send(args[1]);
            //send("args1:"+hexdump(args[1]));
            if(0){
            send('RegisterNatives called from:' );
            send(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('______HHHHHHH-----'))
            send('----------------------------------------------------------------------------------------------')  
            };
             
            send(args[2]);
            send(args[3]);
            send(args[4]);

        },
        onLeave: function(retval){
            send("retval:"+retval);
            if(retval.toInt32()==25536){
            send('RegisterNatives called from:' );
            send(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('______HHHHHHH-----'))
            send('----------------------------------------------------------------------------------------------')  
            };
            //send(retval.toInt32())
            //send(retval.readInt());
            
            //var myval=retval.add(0x1C);
            //send("retval:"+hexdump(retval))
            //retval.replace(1);
            //myval.writeByteArray([0x20,0x00,0x37]);
            
            //send("hexdump:"+hexdump(retval, { offset: 0, length: 400, header: true, ansi: false }));

            //send("retval:"+retval.readByteArray(16));
            
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
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()