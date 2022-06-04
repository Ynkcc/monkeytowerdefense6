
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0x14346FC;         //需要hook的函数的偏移
    
    var struct_addr=0x0;  //0xF01580.0x78163d9540.0x6dbd0b9540
    var needpart=0x30; //字段偏移
    var needpart2=0x70; //字段偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    var field_addr;
    var field_addr2;
    var arg0 = null;
    send("so基址："+n_addr_so);
    send("native: " + nativePointer);
    
    
    Interceptor.attach(nativePointer, {

        onEnter: function(args){
            
            send("start....");
            send("struct_addr "+args[0]);
            field_addr = args[0].add(needpart);
            send("field_addr: " + field_addr);
            send(args[1]);
            //send("args1:"+hexdump(args[1]));
            if(0){
            send('RegisterNatives called from:' );
            send(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('______HHHHHHH-----'))
            send('----------------------------------------------------------------------------------------------')  
            };
           
        },
        onLeave: function(retval){
            
            send("retval:"+retval);
            //retval.replace(0);
            send("hexdump:")
            console.log(hexdump(field_addr, { offset: 0, length: 400, header: true, ansi: false }));
            arg0=field_addr.readPointer();
            send("arg0: " + arg0);
            field_addr2 = arg0.add(needpart2);
            var arg1=field_addr2.readFloat();
            console.log(hexdump(arg0, { offset: 0, length: 400, header: true, ansi: false }));
            send("arg1: " + arg1);
            //field_addr2.writeFloat(10000)
            send("over.....")
            //send("get_val: "+get_val(arg0))
            //set_val(arg0,40000)
            //send("get_val: "+get_val(arg0))
            
            
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