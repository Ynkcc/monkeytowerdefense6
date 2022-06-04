
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    var str_name_so = 'libil2cpp.so';
    var n_addr_so = Module.findBaseAddress(str_name_so); 

    var Dtoch=80000;
    var Ptoch=1000;

    var D_offset = 0x14FD390;     
    var P_offset = 0x15B888C;
    var D_Field_offset=0x34;
    var P_Field_offset=0x44;
    var D_Field_addr;
    var P_Field_addr;
    var D_func = parseInt(n_addr_so, 16) + D_offset;
    var P_func = parseInt(n_addr_so, 16) + P_offset;
    var D_Pointer = new NativePointer(D_func);
    var P_Pointer = new NativePointer(P_func);
    
    var resultval= null;
    send("so基址："+n_addr_so);
    Interceptor.attach(D_Pointer, {
        onEnter: function(args){
            send("D start....");
            D_Field_addr = args[0].add(D_Field_offset);
            send("D_Field_addr: " + D_Field_addr);
        },
        onLeave: function(retval){
            
            send("Damage: " + D_Field_addr.readFloat());
            D_Field_addr.writeFloat(Dtoch)
            send("retval:"+retval);
            retval.replace(1);
            send("D over.....")
        }
    });
    Interceptor.attach(P_Pointer, {
        onEnter: function(args){
            send("P start....");
            P_Field_addr = args[0].add(P_Field_offset);
            send("P_Field_addr: " + P_Field_addr);
        },
        onLeave: function(retval){
            
            send("Pierce: " + P_Field_addr.readFloat());
            P_Field_addr.writeFloat(Ptoch) 
            send("retval:"+retval);
            retval.replace(1);
            send("P over.....")
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