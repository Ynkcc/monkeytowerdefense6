
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0x14F5990;         //需要hook的函数的偏移
    var struct_addr=0x0;  //0xF01580.0x78163d9540.0x6dbd0b9540
    var needpart=0x72; //字段偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    var field_addr;
    var arg0 = null;
    send("so基址："+n_addr_so);
    send("native: " + nativePointer);
    
    Interceptor.attach(nativePointer, {
        onEnter: function(args){
            if(arg0==null){
            send("start....");
            
            //send("args1:"+hexdump(args[1]));
            if(0){
            send('RegisterNatives called from:' );
            send(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('______HHHHHHH-----'))
            send('----------------------------------------------------------------------------------------------')  
            };
            send(args[0]);
            send(args[1]);
            send(args[2]);
            send(args[3]);
            send(args[4]);
            }
        },
        onLeave: function(retval){
            if(arg0==null){
            send("retval:"+retval);
            field_addr = retval.add(needpart);
            send("field_addr: " + field_addr);
            
            if(retval.toInt32()==25536){
            send('RegisterNatives called from:' );
            send(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('______HHHHHHH-----'))
            send('----------------------------------------------------------------------------------------------')  
            };
            send("over.....")
            
            }
            
        }
    });
    
    
    var n_addr_func_offset2 = 0xF6D168; 
    var n_addr_func2 = parseInt(n_addr_so, 16) + n_addr_func_offset2;
    var nativePointer2 = new NativePointer(n_addr_func);
    Interceptor.attach(nativePointer2, {
        onEnter: function(args){
            send("fun2  start....");
        },
        onLeave: function(retval){
            send("retval:"+retval);
            
            send("hexdump:")
            console.log(hexdump(field_addr, { offset: 0, length: 400, header: true, ansi: false }));
            //var result=field_addr.readInt();
            //send("result: " + result);
            //field_addr.writeByteArray([0x01])
            send("fun2  over.....")
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