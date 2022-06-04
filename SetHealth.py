
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0xF68F20;         //需要hook的函数的偏移
    var struct_addr=0x0;  //0xF01580.0x78163d9540.0x6dbd0b9540
    var needpart=0x0; //字段偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    var field_addr;
    var arg0 = null;

    send("so基址："+n_addr_so);
    send("native: " + nativePointer);
    
    var getval_offset = 0xF67E44;     //需要hook的函数的偏移.0xE544E4.set.0xE5453C.get
    var setval_offset = 0xF67E44; 
    var getval_func = parseInt(n_addr_so, 16) + getval_offset;
    var setval_func = parseInt(n_addr_so, 16) + setval_offset;
    var getval_Pointer = new NativePointer(getval_func);
    var setval_Pointer = new NativePointer(setval_func);
    var set_val = new NativeFunction(setval_Pointer,'void',["pointer","int"]);
    var get_val = new NativeFunction(getval_Pointer,'int',["pointer"]);
    
    
    Interceptor.attach(nativePointer, {
        onEnter: function(args){
            if(arg0==null){
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
             
            send(args[2]);
            send(args[3]);
            send(args[4]);
            }
        },
        onLeave: function(retval){
            if(arg0==null){
            send("retval:"+retval);
            if(retval.toInt32()==25536){
            send('RegisterNatives called from:' );
            send(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('______HHHHHHH-----'))
            send('----------------------------------------------------------------------------------------------')  
            };
            
            
            }
            
        }
    });
    
    set_val(field_addr,79);

    

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