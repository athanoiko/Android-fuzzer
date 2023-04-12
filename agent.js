"use strict";

/////////////////////////     TARGET CONFIG   ///////////////////////////////////////////////

var debugging_enabled           = false;
var target_module               = 'libnativelib.so';
var target_function             = 'c_fuzz_test_3';
var target_function_ret_type    = 'int';
var target_function_arg_types   = ['pointer', 'int'];
var watch_modules               = [];

var corpus                      = ['AAA'];

var deterministic_stage_enabled = true;
var havoc_stage_enabled         = false;


////////////////////////      JAVA INSTRUMENTATION    //////////////////////////////////////

// jstring  : newStringUtf('str')

// example code:
// Java.perform(function x() {
//      console.log("Inside java perform function");
//      var my_class = Java.use("com.example.a11x256.frida_test.my_activity");
//      my_class.fun.overload("int", "int").implementation = function (x, y) { //hooking the old function
//          console.log("original call: fun(" + x + ", " + y + ")");
//          var ret_value = this.fun(2, 5);
//          return ret_value;
// };
// var string_class = Java.use("java.lang.String");

////////////////////////      FUZZER INSTRUMENTATION    ////////////////////////////////////

function fuzzer_Test_One_Input(data, size) {
    
    // data: Uint8Array
    // size: int

    // char *     as parameter     : Memory.allocUtf8String("str") 
    // c string   as return value  : Memory.readCString(arg) 

    data = Memory.allocUtf8String(uint8array_to_str(data));
    
    var ret = native_function_handler(data, size);
    debug("Fuzzing: Returned [" + ret + ']');
}

////////////////////////      FUZZER CONFIG  ///////////////////////////////////////////////

var maps                        = []
var paylod_max_length           = 100;
var stalker_queueCapacity       = 100000000;
var stalker_queueDrainInterval  = 1000*1000;

var splice_stage_enabled        = true;
var stage_cur                   = 0;
var stage_max                   = 0;
var total_execs                 = 0;
var exec_speed                  = 0;
var last_status_ts              = 0;
var start_time                  = 0;
var total_crashes               = 0;
var stage_name                  = '';
var stage_short                 = '';
var stage_max                   = 0;
var coverage_last               = undefined;
var stage_cur_val               = 0;
var accumulated_coverage        = undefined;
var queue_id                    = 0;
var payload                     = '';
var splice_cycle                = 0;

var COVERAGE_TIMEOUT            = 200;
var CRASH_TIMEOUT               = 1000;
var STALKER_TIMEOUT             = 200;

var HAVOC_STACK_POW2            = 7;
var HAVOC_CYCLES                = 256;
var SPLICE_HAVOC                = 32;
var SPLICE_CYCLES               = 15;
var HAVOC_BLK_SMALL             = 32;
var HAVOC_BLK_MEDIUM            = 128;
var HAVOC_BLK_LARGE             = 1500;
var HAVOC_BLK_XL                = 32768;
var INTERESTING_8               = [-128, -1, 0, 1, 16, 32, 64, 100, 127];
var INTERESTING_16              = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767];
var INTERESTING_32              = [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647];
var ARITH_MAX                   = 35;
var SKIP_TO_NEW_PROB            = 99;
var SKIP_NFAV_OLD_PROB          = 95;
var SKIP_NFAV_NEW_PROB          = 75;
var SKIP_SCORE_FAV              = false;
var QUEUE_CACHE_MAX_SIZE        = 512*1024*1024;
var UPDATE_TIME                 = 3*1000;

var stalker_attached            = false;
var stalker_finished            = false;
var native_function_handler     = undefined;
var gc_cnt                      = 0;
var module_ids                  = {};
Stalker.trustThreshold          = 0;
var stalker_events              = [] // ArrayBuffer
var queue                       = [];
var exceptions                  = [];
var craches                     = [];
var crashed_input               = undefined;

var data                        = Memory.alloc(0x100000); // char* data
var size                        = Memory.alloc(0x100000); // data length
var zero_0x100000               = new Uint8Array(0x100000);

///////////////////////       FUZZER      //////////////////////////////////////////////////

console.log();
print("Loading script");

print("Attached module        : " + target_module);
print("Target function        : " + target_function);
print("Function argument types: " + target_function_arg_types);
print("Function return type   : " + target_function_ret_type);
console.log();

run_fuzzer();

console.log();
print("Fuzzer finised");

////////////////////////      IMPORTANT FUNCTIONS        ////////////////////////

function print(msg)   { console.log('[+] ' + msg); }
function error(msg)   { throw '[ERROR] ' + msg; }
function debug(msg)   { if(debugging_enabled){console.log("[D] " + msg);} }
function warning(msg) { console.warn("[!] " + msg);}
function p_status()   { exec_speed = total_execs/((t_now()-start_time)/1000);
                        console.log('[#' + total_execs +'] Time: ['+ total_time_from_start() +'] cov: [' + accumulated_coverage.length + 
                        '] exec/sec: ['+ Math.round(exec_speed) + '] stage: [' + stage_name + '] corp: ['+ queue_id +'/'+ queue.length +
                        '] craches: ['+ total_crashes +']');}
function t_now()      {return (new Date()).getTime();}

function create_queue(){

    for (var i = 0; i < corpus.length; i++) {
        
        var buf = corpus[i];     
         
        debug("Queue: Adding new corpus ["+ i + ']['+ buf + '][' + buf.length +']');
        queue.push({
            "buf"   : buf,          // string
            "len"   : buf.length,
            "used"  : false ,
        });
    } 
}

function run_fuzzer(){

    // Create mapping of all modules for coverage 
    maps = make_maps();
    create_queue(); // From initial corpus

    watch_modules = watch_modules.concat(target_module);

    // initialize the address of the target function to be hooked and
    // attach the function to the Interceptor
    Interceptor_attach(Module.findExportByName(target_module, target_function));

    // Create the function handle (specify type and number of arguments)
    native_function_handler = new NativeFunction(Module.findExportByName(target_module, target_function), target_function_ret_type, target_function_arg_types);
    
    start_time = t_now();

    for(var i = 0; i < queue.length; i++){

        queue_id = i+1;
        if(target_function == undefined) {
            error("Fuzzing: Target function not defined!");
        }
        
        // Accepted types of corpus are:
        // Uint8Array, ArrayBuffer, String
        // Place in queue.buf only Arraybuffer data

        var buf = queue[i]['buf'];
        if (Array.isArray(buf) || (buf instanceof ArrayBuffer))
            buf = new Uint8Array(buf);
        else if (typeof buf === 'string' || (buf instanceof String))
            buf = str_to_uint8array(buf); 
        else if (!(buf instanceof Uint8Array))
            error("Queue: Invalid type of buf (Creation)");       

        if (queue[i]['used'] == false){    
            
            var payload = payload_trimming(buf);
            
             debug("Fuzzer: Current payload ["+ bufferarray_to_str(payload) + "]"); 
    
            if (deterministic_stage_enabled == true)
                deterministic_stage(payload);
                queue[i]['used'] = true;    
        }else{
            var accumulated_coverage_save = accumulated_coverage; 
            if (havoc_stage_enabled == true)
                havoc_stage(payload, false);
            if(JSON.stringify(accumulated_coverage_save) == JSON.stringify(accumulated_coverage))
                splice_stage_enabled = true;
        }
    }

    if (splice_stage_enabled == true){

        for (var i = 0; i < queue.length; i++){
            splice_stage(queue[i]['buf']);
        }
    }
    p_status();
}

// Call target function with the current payload
function fuzz_one(buf) {
    
    debug('');
    total_execs++;
    debug("Fuzzing: Total executions [" + total_execs + ']');
    debug("Fuzzing: Input [" + bufferarray_to_str(buf)+"]");

    clear_coverage();

    // Convert 
    payload = new Uint8Array(buf);
    var t0 = t_now();
    
    try {
        fuzzer_Test_One_Input(payload, payload.length);   
    }catch(e) {
        total_crashes++;
        if (e.type === 'abort'){
            warning("Exception found! Type: [abort] Corpus: [" + payload + '] [' + bufferarray_to_str(payload) +']');
        } else if (e.type === 'access-violation'){
            warning("Exception found! Type: [access-violation] Corpus: [" + payload + '] [' + bufferarray_to_str(payload) +']');
        }else{
            warning('Exception found! Type: [message] Corpus: [' + payload +'] [' + bufferarray_to_str(payload) +'] Message: [' + JSON.stringify(e) + ']');
        }
    }
 
    var t0 = t_now();
    while(t_now() - t0 < COVERAGE_TIMEOUT && stalker_attached == undefined){  
    }

    t0 = t_now();
    while(t_now - t0 < STALKER_TIMEOUT && stalker_finished == -1){
    }

    if (stalker_finished == -1)
        debug("Get coverage: Stalker did not finish after 1 second!");
    
    var t1 = t_now();
    var exec_ms = t1 - t0;
    
    
    var coverage = undefined;
    coverage = get_coverage(); // [{ 'start' : '0x4546...' , 'end': '0x4547...', 'name' : 'lib...'}

    if (coverage == undefined || coverage.length == 0)
        debug("Coverage: No coverage returned");

    if (coverage_last != undefined && JSON.stringify(coverage_last) != JSON.stringify(coverage))
        debug("Coverage: Inconsistent");    
    
    if(coverage != undefined)
        new_path_check(coverage, buf);

    coverage_last = coverage;

    if (exec_ms > CRASH_TIMEOUT){
        warning("Crash found! Input: [" + bufferarray_to_str(payload)+"]");
    }
    
    if ((t_now() - last_status_ts) > UPDATE_TIME) {
        last_status_ts = t_now();
        p_status();
    } 
}

function new_path_check(coverage, buf){

    if(accumulated_coverage == undefined){

        accumulated_coverage = [];
        accumulated_coverage.push(coverage)

    }else{

        var found = false;
        for (var i = 0; i < accumulated_coverage.length; i++) {              
            if (JSON.stringify(accumulated_coverage[i]) === JSON.stringify(coverage)) {
                found = true;
                break;
            }
        }
        
        if (found == false){
             debug("Coverage: NEW PATH Corpus ["+ bufferarray_to_str(buf)+"]");
            p_status();
            queue.push({
                "buf"   : bufferarray_to_str(buf),
                "len"   : buf.byteLength,
                "used"  : false,
            });
            accumulated_coverage.push(coverage);
        }
    }
}

function payload_trimming(buf){
    if (buf.length > paylod_max_length)
        buf = buf.slice(0, paylod_max_length);
    return buf.buffer;
}

function get_coverage() {

    debug("Get coverage: len(stalker_events) = " + stalker_events.length)   
    
    if(stalker_events.length == 0)
        return undefined;
    
    var accumulated_events = []
    for(var i = 0; i < stalker_events.length; i++) {
        var parsed = Stalker.parse(stalker_events[i], {stringify: false, annotate: false})
        
        accumulated_events = accumulated_events.concat(parsed);
    }
    
    return parse_coverage(accumulated_events);
}

function parse_coverage(coverage){
    
    // Input [["0x4754...", "0x54666..."], ["0x4878...", "0x4787..."]]

    var blocks = []; 
    for (var i = 0; i < coverage.length; i++){
        var start = coverage[i][0]; 
        var end = coverage[i][1];
        var module_name = undefined;
        
        for (var m = 0; m < maps.length; m++) {
            if (start > maps[m]['base'] && end < maps[m]['end']){
                module_name = maps[m]['name'];
                for(var j = 0; j < watch_modules.length; j++){
                    if(module_name == watch_modules[j]){
                        blocks.push({"start" : start, 
                                "end"   : end,
                                "name"  : module_name});
                    }
                }
            }
            if (module_name == undefined)
                //debug("Parse coverage: Block does not belong to any module");
            continue;
        }
    }
    return blocks;
}

function clear_coverage() {

    debug("Coverage: Clear()");
    stalker_events = [];
    stalker_attached = false;
    stalker_finished = false;
}

function Interceptor_attach(target_function_ptr){

    Interceptor.attach(target_function_ptr, {
        onEnter: function (args) {
            
            debug('Interceptor: Entered');
            //debug("Stalker: queueCapacity = " + Stalker.queueCapacity);
            //debug("Stalker: queueDrainInterval = " + Stalker.queueDrainInterval);
            
            stalker_attached = true;
            stalker_finished = false;
            Stalker.queueCapacity = stalker_queueCapacity;
            Stalker.queueDrainInterval = stalker_queueDrainInterval;
    
            Stalker.follow(Process.getCurrentThreadId(), {
                events: {
                    call: false,
                    ret: false,
                    exec: false,
                    block: false,
                    compile: true
                },
                onReceive: function (events) {
                    debug("Stalker: onReceive events length [" + stalker_events.length +']');
                    stalker_events.push(events)
                }
            });
        },
        onLeave: function (retval) {
            debug('Interceptor: Leaved');
            Stalker.unfollow(Process.getCurrentThreadId())
            Stalker.flush();
            if(gc_cnt % 100 == 0){
                Stalker.garbageCollect();
            }
            gc_cnt++;
            stalker_finished = true
        }
    });
}

function make_maps() {

    // Per Module: id, path, base, end, size, 
    var maps = Process.enumerateModulesSync();
    var i = 0;
    maps.map(function(o) { o.id = i++; });
    maps.map(function(o) { o.end = o.base.add(o.size); });
    maps.map(function(o) { module_ids[o.path] = {id: o.id, start: o.base}; });

    // Example maps
    // [ {"name" : "app_process64",
    //    "base" : "0x6415a401b000",
    //    "size" : 20480,
    //    "path" : "/system/bin/app_process64",
    //    "id"   : 0,
    //    "end"  : "0x6415a4020000"}, .... ]
    return maps;
}

function hex_to_unit8array(hexstr) {
    var buf = [];
    for(var i = 0; i < hexstr.length; i+=2)
        buf.push(parseInt(hexstr.substring(i, i + 2), 16));
  
    buf = new Uint8Array(buf);
    return buf.buffer;  
}

function str_to_uint8array(str) {
    var utf8 = [];
    for (var i = 0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
            utf8.push(0xc0 | (charcode >> 6),
                      0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
            utf8.push(0xe0 | (charcode >> 12),
                      0x80 | ((charcode>>6) & 0x3f),
                      0x80 | (charcode & 0x3f));
        }
        else {
            i++;
            charcode = 0x10000 + (((charcode & 0x3ff)<<10)
                      | (str.charCodeAt(i) & 0x3ff));
            utf8.push(0xf0 | (charcode >>18),
                      0x80 | ((charcode>>12) & 0x3f),
                      0x80 | ((charcode>>6) & 0x3f),
                      0x80 | (charcode & 0x3f));
        }
    }
    return new Uint8Array(utf8);
}


function uint8array_to_str(array) {
    return String.fromCharCode.apply(null, array);
}
// function uint8array_to_str(array) {
//         var char_cache = new Array(128);
//         var char_from_codept = String.fromCharCode;
//         var result = [];
//         var codept, byte1;
//         var buff_len = array.length;

//         result.length = 0;

//         for (var i = 0; i < buff_len;) {
//             byte1 = array[i++];

//             if (byte1 <= 0x7F) {
//                 codept = byte1;
//             } else if (byte1 <= 0xDF) {
//                 codept = ((byte1 & 0x1F) << 6) | (array[i++] & 0x3F);
//             } else if (byte1 <= 0xEF) {
//                 codept = ((byte1 & 0x0F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F);
//             } else if (String.fromCodePoint) {
//                 codept = ((byte1 & 0x07) << 18) | ((array[i++] & 0x3F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F);
//             } else {
//                 codept = 63;    // Cannot convert four byte code points, so use "?" instead
//                 i += 3;
//             }

//             result.push(char_cache[codept] || (char_cache[codept] = char_from_codept(codept)));
//         }

//         return result.join('');
// };

function bufferarray_to_str(buf){
    return uint8array_to_str(new Uint8Array(buf));
}

function UR(n) {
    return Math.floor(Math.random() * n);
}

function deterministic_stage(buf){

    // Input: Arraybuffer
    
    var out_buf = new DataView(buf);
    var len = out_buf.byteLength;
    
    stage_name = "init";

    fuzz_one(buf);

    stage_name = "bitflip 1/1";
    stage_short = "flip1";
    stage_max = len << 3;

    for(var stage_cur = 0; stage_cur < stage_max; stage_cur++){
        out_buf.setUint8(stage_cur >> 3, out_buf.getUint8(stage_cur >> 3) ^ (128 >> (stage_cur & 7)));
        if (len != buf.byteLength)
            buf.slice(0, len);
        fuzz_one(buf);
        out_buf.setUint8(stage_cur >> 3, out_buf.getUint8(stage_cur >> 3) ^ (128 >> (stage_cur & 7)));    
    }

    //p_status();
    stage_name = "bitflip 2/1";
    stage_short = "flip2";
    stage_max = (len << 3) - 1;

    for(var stage_cur = 0; stage_cur < stage_max; stage_cur++){
        out_buf.setUint8(stage_cur >> 3, out_buf.getUint8(stage_cur >> 3) ^ (128 >> (stage_cur & 7))); // pos
        out_buf.setUint8((stage_cur + 1) >> 3, out_buf.getUint8((stage_cur + 1) >> 3) ^ (128 >> ((stage_cur + 1) & 7))); // pos+1
    

        if (len != buf.byteLength)
            buf.slice(0, len);
        fuzz_one(buf);
        
        out_buf.setUint8(stage_cur >> 3, out_buf.getUint8(stage_cur >> 3) ^ (128 >> (stage_cur & 7))); // pos
        out_buf.setUint8((stage_cur + 1) >> 3, out_buf.getUint8((stage_cur + 1) >> 3) ^ (128 >> ((stage_cur + 1) & 7))); // pos+1
    }
        
    //p_status();

    stage_name = "bitflip 4/1";
    stage_short = "flip4";
    stage_max = (len << 3) - 3;

    for(var stage_cur = 0; stage_cur < stage_max; stage_cur++){
        out_buf.setUint8(stage_cur >> 3, out_buf.getUint8(stage_cur >> 3) ^ (128 >> (stage_cur & 7))); // pos
        out_buf.setUint8((stage_cur + 1) >> 3, out_buf.getUint8((stage_cur + 1) >> 3) ^ (128 >> ((stage_cur + 1) & 7))); // pos+1
        out_buf.setUint8((stage_cur + 2) >> 3, out_buf.getUint8((stage_cur + 2) >> 3) ^ (128 >> ((stage_cur + 2) & 7))); // pos+2
        out_buf.setUint8((stage_cur + 3) >> 3, out_buf.getUint8((stage_cur + 3) >> 3) ^ (128 >> ((stage_cur + 3) & 7))); // pos+3
        
        if (len != buf.byteLength)
            buf.slice(0, len);
        fuzz_one(buf);
        
        out_buf.setUint8(stage_cur >> 3, out_buf.getUint8(stage_cur >> 3) ^ (128 >> (stage_cur & 7))); // pos
        out_buf.setUint8((stage_cur + 1) >> 3, out_buf.getUint8((stage_cur + 1) >> 3) ^ (128 >> ((stage_cur + 1) & 7))); // pos+1
        out_buf.setUint8((stage_cur + 2) >> 3, out_buf.getUint8((stage_cur + 2) >> 3) ^ (128 >> ((stage_cur + 2) & 7))); // pos+2
        out_buf.setUint8((stage_cur + 3) >> 3, out_buf.getUint8((stage_cur + 3) >> 3) ^ (128 >> ((stage_cur + 3) & 7))); // pos+3
    }

    //p_status();

    stage_name  = "bitflip 8/8";
    stage_short = "flip8";
    stage_max   = len;

    for(var stage_cur = 0; stage_cur < stage_max; stage_cur++){
        out_buf.setUint8(stage_cur, out_buf.getUint8(stage_cur)^ 0xFF);
        
        if (len != buf.byteLength)
            buf.slice(0, len);
        fuzz_one(buf);

        out_buf.setUint8(stage_cur, out_buf.getUint8(stage_cur)^ 0xFF);
    }

    //p_status();

    stage_name  = "arith 8/8";
    stage_short = "arith8";
    stage_cur   = 0;
    stage_max   = 2 * len * ARITH_MAX;

    for (var i = 0; i < len; i++) {
        var orig = out_buf.getUint8(i);
        for (var j = 1; j <= ARITH_MAX; j++) {
            var r = orig ^ (orig + j);
            out_buf.setUint8(i, orig + j);

            if (len != buf.byteLength)
                buf.slice(0, len);
            fuzz_one(buf);
            
            stage_cur++;

            r = orig ^ (orig - j);
            out_buf.setUint8(i, orig - j);

            if (len != buf.byteLength)
                buf.slice(0, len);
            fuzz_one(buf);

            out_buf.setUint8(i, orig);

            if (len != buf.byteLength)
                buf.slice(0, len);
            fuzz_one(buf);
        }
    }

    //p_status();

    stage_name  = "arith 16/8";
    stage_cur   = 0;
    stage_max   = 4 * (len - 1) * ARITH_MAX;

    if(len>2){
        for (var i = 0; i < len-1; i++) {
            var orig = out_buf.getUint16(i);
            for (var j = 1; j <= ARITH_MAX; j++) {
    
                stage_short = "arith16 LE";
    
                var r1 = orig ^ (orig + j);
                var r2 = orig ^ (orig - j);
                var r3 = orig ^ SWAP16(SWAP16(orig) + j);
                var r4 = orig ^ SWAP16(SWAP16(orig) - j);
    
                if ((orig & 0xff) + j > 0xff){
                    
                    out_buf.setUint16(i, orig + j);
    
                    if (len != buf.byteLength)
                        buf.slice(0, len);
                    fuzz_one(buf);
                    stage_cur++;
                }
    
                if ((orig & 0xff) < j){
    
                    out_buf.setUint16(i, orig - j);
    
                    if (len != buf.byteLength)
                        buf.slice(0, len);
                    fuzz_one(buf);
                    stage_cur++;
                }
            
                stage_short = "arith16 BE";
                
                if ((orig >> 8) + j > 0xff){
    
                    out_buf.setUint16(i, SWAP16(SWAP16(orig) + j));
    
                    if (len != buf.byteLength)
                        buf.slice(0, len);
                    fuzz_one(buf);
                    stage_cur++;
                }
    
                if ((orig >> 8) < j){
    
                    out_buf.setUint16(i, SWAP16(SWAP16(orig) - j));
    
                    if (len != buf.byteLength)
                        buf.slice(0, len);
                    fuzz_one(buf);
                    stage_cur++;
                }
    
                out_buf.setUint16(i, orig);
            }
        }
    }
    
    
    //p_status();

    stage_name  = "interest 8/8";
    stage_short = "int8";
    stage_cur   = 0;
    stage_max   = len * INTERESTING_8.length;

    for (var i = 0; i < len; i++) {
        var orig = out_buf.getUint8(i);
        for (var j = 0; j < INTERESTING_8.length; j++) {
            out_buf.setUint8(i, INTERESTING_8[j]);
            
            if (len != buf.byteLength)
                buf.slice(0, len);
            fuzz_one(buf);
            stage_cur++
            out_buf.setUint8(i, INTERESTING_8[j]);
        }
    }

    //p_status();

    stage_name  = "interest 16/8";
    stage_short = "int16";
    stage_cur   = 0;
    stage_max   = 2 * (len - 1) * (INTERESTING_16.length) >> 1;

    for (var i = 0; i < len-1; i++) {
        var orig = out_buf.getUint16(i);
        for (var j = 0; j < INTERESTING_16.length; j++) {
            out_buf.setUint16(i, INTERESTING_16[j]);
            
            if (len != buf.byteLength)
                buf.slice(0, len);
            fuzz_one(buf);
            stage_cur++
            out_buf.setUint16(i, INTERESTING_16[j]);
        }
    }
}

function havoc_stage(buf, is_splice){     
    if (!is_splice)  {
        stage_name = "havoc";
        stage_max = HAVOC_CYCLES * 40;
        //p_status();
    } else {
        stage_name = "splice-" + splice_cycle;
        stage_max = SPLICE_HAVOC * 40;
        //p_status();
    }
    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
        var muted = havoc_mutation(buf.slice(0));
        fuzz_one(muted);
    }    
}

function choose_block_len(limit) {

    var min_value;
    var max_value;
    var rlim = 3; 

    switch (UR(rlim)) {
  
      case 0:  min_value = 1;
               max_value = HAVOC_BLK_SMALL;
               break;
  
      case 1:  min_value = HAVOC_BLK_SMALL;
               max_value = HAVOC_BLK_MEDIUM;
               break;
  
      default: 
               if (UR(10)) {
                 min_value = HAVOC_BLK_MEDIUM;
                 max_value = HAVOC_BLK_LARGE;
               } else {
                 min_value = HAVOC_BLK_LARGE;
                 max_value = HAVOC_BLK_XL;
               }
    }
  
    if (min_value >= limit) min_value = 1;
  
    return min_value + UR(Math.min(max_value, limit) - min_value + 1);
}

function havoc_mutation(buf){
    
    // Input: ArrayBuffer
    // Output: ArrayBuffer

    var out_buf = new DataView(buf);
    var temp_len = out_buf.byteLength;

    var pos = undefined;
    var endian = true;
    var use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    for (var i = 0; i < use_stacking; i++) {

        switch (UR(13 + ((corpus.length > 0) ? 2 : 0))) {

        case 0:
            /* Flip a single bit somewhere. Spooky! */
            pos = UR(temp_len << 3);
            out_buf.setUint8(pos >> 3, out_buf.getUint8(pos >> 3) ^ (128 >> (pos & 7)));
            break;

        case 1: 
            /* Set byte to interesting value. */
            out_buf.setUint8(UR(temp_len), INTERESTING_8[UR(INTERESTING_8.length)]);
            break;

        case 2:
            /* Set word to interesting value, randomly choosing endian. */
            if (temp_len < 2) break;
            out_buf.setUint16(UR(temp_len - 1), INTERESTING_16[UR(INTERESTING_16.length >> 1)], UR(2) == 0);
            break;

        case 3:
            /* Set dword to interesting value, randomly choosing endian. */
            if (temp_len < 4) break;
            out_buf.setUint32(UR(temp_len - 3), INTERESTING_32[UR(INTERESTING_32.length >> 1)], UR(2) == 0);
            break;

        case 4:
            /* Randomly subtract from byte. */
            pos = UR(temp_len);
            out_buf.setUint8(pos, out_buf.getUint8(pos) - 1 - UR(ARITH_MAX));
            break;

        case 5:
            /* Randomly add to byte. */
            pos = UR(temp_len);
            out_buf.setUint8(pos, out_buf.getUint8(pos) + 1 + UR(ARITH_MAX));          
            break;

        case 6:
            /* Randomly subtract from word, random endian. */
            if (temp_len < 2) break;
            endian = UR(2) == 0;
            pos = UR(temp_len - 1);
            out_buf.setUint16(pos, out_buf.getUint16(pos, endian) - 1 - UR(ARITH_MAX), endian);
            break;

        case 7:
            /* Randomly add to word, random endian. */
            if (temp_len < 2) break;            
            endian = UR(2) == 0;
            pos = UR(temp_len - 1);
            out_buf.setUint16(pos, out_buf.getUint16(pos, endian) + 1 + UR(ARITH_MAX), endian);
            break;

        case 8:
            /* Randomly subtract from dword, random endian. */
            if (temp_len < 4) break;
            endian = UR(2) == 0;
            pos = UR(temp_len - 3);
            out_buf.setUint32(pos, out_buf.getUint32(pos, endian) - 1 - UR(ARITH_MAX), endian);
            break;

        case 9:
            /* Randomly add to dword, random endian. */
            if (temp_len < 4) break;            
            endian = UR(2) == 0;
            pos = UR(temp_len - 3);
            out_buf.setUint32(pos, out_buf.getUint32(pos, endian) + 1 + UR(ARITH_MAX), endian);
            break;

        case 10:
            /* Just set a random byte to a random value. Because,
            why not. We use XOR with 1-255 to eliminate the
            possibility of a no-op. */
            pos = UR(temp_len);
            out_buf.setUint8(pos, out_buf.getUint8(pos) ^ (1 + UR(255)));
            break;

        case 11: case 12: {
            /* Delete bytes. We're making this a bit more likely
                than insertion (the next option) in hopes of keeping
                files reasonably small. */
            var del_from;
            var del_len;
            if (temp_len < 2) break
            /* Don't delete too much. */
            del_len = choose_block_len(temp_len - 1);
            del_from = UR(temp_len - del_len + 1);
            for (var j = del_from; j < (temp_len - del_len); ++j)
                out_buf.setUint8(j, out_buf.getUint8(j + del_len));
            temp_len -= del_len;
            break;
        }

        case 13:
            if (temp_len + HAVOC_BLK_XL < paylod_max_length) {
            /* Clone bytes (75%) or insert a block of constant bytes (25%). */
            var actually_clone = UR(4);
            var clone_from;
            var clone_len;
            if (actually_clone) {
                clone_len  = choose_block_len(temp_len);
                clone_from = UR(temp_len - clone_len + 1);
            } else {
                clone_len = choose_block_len(HAVOC_BLK_XL);
                clone_from = 0;
            }
            var clone_to = UR(temp_len);
            buf = new ArrayBuffer(temp_len + clone_len);
            var new_buf = new DataView(buf);
            /* Head */
            for (var j = 0; j < clone_to; ++j)
                new_buf.setUint8(j, out_buf.getUint8(j));
            /* Inserted part */
            if (actually_clone)
                for (var j = 0; j < clone_len; ++j)
                new_buf.setUint8(clone_to + j, out_buf.getUint8(clone_from + j));
            else
                for (var j = 0; j < clone_len; ++j)
                new_buf.setUint8(clone_to + j, UR(2) ? UR(256) : out_buf.getUint8(UR(temp_len)));
            /* Tail */
            for (var j = clone_to; j < temp_len; ++j)
                new_buf.setUint8(j + clone_len, out_buf.getUint8(j));
            out_buf = new_buf;
            temp_len += clone_len;
        }
        break;
        case 14: {
            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                bytes (25%). */
            var copy_from;
            var copy_to;
            var copy_len;
            if (temp_len < 2) break;
            copy_len  = choose_block_len(temp_len - 1);
            copy_from = UR(temp_len - copy_len + 1);
            copy_to   = UR(temp_len - copy_len + 1);
            if (UR(4)) {
                if (copy_from != copy_to) {               
                var sl = new Uint8Array(buf.slice(copy_from, copy_from + copy_len));
                for (var j = 0; j < copy_len; ++j)
                    out_buf.setUint8(copy_to + j, sl[j]);                   
                }               
            } else {           
                var b = UR(2) ? UR(256) : out_buf.getUint8(UR(temp_len));
                for (var j = 0; j < copy_len; ++j)
                out_buf.setUint8(copy_to + j, b);
            }
            break;
        }
        /* Values 15 and 16 can be selected only if there are any extras
            present in the dictionaries. */
        case 15: {
            /* Overwrite bytes with an extra. */
            var use_extra = UR(corpus.length);
            var extra_len = corpus[use_extra].byteLength;
            if (extra_len > temp_len) break;
            var insert_at = UR(temp_len - extra_len + 1);
            for (var j = 0; j < extra_len; ++j)
                out_buf.setUint8(insert_at + j, corpus[use_extra][j]);
            break;
            }
        case 16: {
            var insert_at = UR(temp_len);
            /* Insert an extra. */
            var use_extra = UR(corpus.length);
            var extra_len = corpus[use_extra].byteLength;
            if (temp_len + extra_len >= paylod_max_length) break;
            buf = new ArrayBuffer(temp_len + extra_len);
            var new_buf = new DataView(buf);
            /* Head */
            for (var j = 0; j < insert_at; ++j)
                new_buf.setUint8(j, out_buf.getUint8(j));
            /* Inserted part */
            for (var j = 0; j < extra_len; ++j)
                new_buf.setUint8(insert_at + j, corpus[use_extra][j]);
            /* Tail */
            for (var j = insert_at; j < temp_len; ++j)
                new_buf.setUint8(extra_len + j, out_buf.getUint8(j));
            out_buf   = new_buf;
            temp_len += extra_len;
            break;
            }
        default: error('Havoc switch');
        }
    }    
    if (temp_len != buf.byteLength)
        return buf.slice(0, temp_len);
    return buf;
}

function splice_stage(buf) {
    
    if (buf.length > 1 || queue.length > 1){
        while (splice_cycle < SPLICE_CYCLES) {
            var new_buf = splice_target(buf);
            if (new_buf !== undefined)
              havoc_mutation(new_buf, true);
          }
    }  
}

function splice_target(buf) {

    var target_id = UR(queue.length);
    var t = queue[target_id];
    
    while (target_id < queue.length && queue[target_id].length < 2)
      ++target_id;
    
    if (target_id === queue.length)
        return;
    
    var target = queue[target_id];
    var new_buf = undefined;
    
    new_buf = ArrayBuffer.wrap(target['buf'], target['len']).slice(0);
    splice_cycle++; 

    var diff = locate_diffs(buf, new_buf);
    if (diff[0] === null || diff[1] < 2 || diff[0] === diff[1])
        return;
  
    var split_at = diff[0] + UR(diff[1] - diff[0]);
    new Uint8Array(new_buf).set(new Uint8Array(buf.slice(0, split_at)), 0);
    return new_buf;
}

function locate_diffs(buf1, buf2) {

    var a = new Uint8Array(buf1);
    var b = new Uint8Array(buf2);

    var f_loc = null;
    var l_loc = null;
    var range = Math.min(a.byteLength, b.byteLength);

    for (var i = 0; i < range; i++) {
        if (a[i] !== b[i]) {
            if (f_loc === null) f_loc = i;
            l_loc = i;
        }
    }

    return [f_loc, l_loc];
}

function total_time_from_start() {
    var diff = new Date(t_now() - start_time);
    return diff.getHours() + ':' + diff.getMinutes() + ':' + diff.getSeconds();
}

function SWAP16(x){                                              
    return (x << 8) | (x >> 8);
}