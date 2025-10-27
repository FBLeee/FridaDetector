#include <jni.h>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <android/log.h>
#include <sys/stat.h>   // for stat
#include <errno.h>      // for errno
#include <sys/mman.h>   // for memmem

// --- 辅助函数：用于创建 CheckResult Java 对象 ---
jobject createCheckResult(JNIEnv *env, jboolean result, const std::string& reason) {
    jclass resultClass = env->FindClass("com/example/fridadetector/CheckResult");
    if (resultClass == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, "FridaDetector", "Could not find CheckResult class");
        return NULL;
    }
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZLjava/lang/String;)V");
    if (constructor == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, "FridaDetector", "Could not find CheckResult constructor");
        return NULL;
    }
    jstring reason_jstring = env->NewStringUTF(reason.c_str());
    return env->NewObject(resultClass, constructor, result, reason_jstring);
}


/*
 * 1. 端口检测 (portCheck)
 */
extern "C" JNIEXPORT jobject JNICALL
Java_com_example_fridadetector_FridaChecker_portCheck(
        JNIEnv *env, jclass clazz) {

    unsigned int v2 = 1; // 1 = PASS
    std::string reason_str = "";

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return createCheckResult(env, JNI_TRUE, "PASS: Socket creation failed");
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = 2; // AF_INET
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(27042); // 0xA269 (41577 小端) -> 27042

    struct timeval timeout = {0, 10000};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        reason_str = "FAIL: Connection to 127.0.0.1:27042 succeeded";
        close(sock);
        v2 = 0; // 0 = FAIL
    }
    close(sock);

    return createCheckResult(env, (v2 == 1) ? JNI_TRUE : JNI_FALSE, reason_str);
}


/*
 * 2. 线程检测 (threadCheck)
 */
extern "C" JNIEXPORT jobject JNICALL
Java_com_example_fridadetector_FridaChecker_threadCheck(
        JNIEnv *env, jclass clazz) {

    unsigned int v7 = 1; // 1 = PASS
    std::string reason_str = "";
    char log_buffer[256] = {0}; // v17
    char path_buffer[256] = {0}; // name

    pid_t pid = getpid();
    snprintf(path_buffer, 200, "/proc/%d/task", pid); // 修正: 移除多余的 200

    DIR *dir = opendir(path_buffer);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

            pid_t pid_inner = getpid();
            // 修正: 移除多余的 200
            snprintf(path_buffer, 200, "/proc/%d/task/%s/status", pid_inner, entry->d_name);

            FILE *status_file = fopen(path_buffer, "r");
            if (status_file) {
                char line_buffer[256];
                while (fgets(line_buffer, 200, status_file)) {
                    bool found = false;
                    const char* found_sig = NULL;

                    if (strstr(line_buffer, "Name:\tgmain")) {
                        found_sig = "found gmain thread: %s";
                        found = true;
                    } else if (strstr(line_buffer, "Name:\tgdbus")) {
                        found_sig = "found gdbus thread: %s";
                        found = true;
                    } else if (strstr(line_buffer, "Name:\tpool-frida")) {
                        found_sig = "found pool-frida thread: %s";
                        found = true;
                    } else if (strstr(line_buffer, "Name:\tgum-js-loop")) {
                        found_sig = "found gum-js-loop thread: %s";
                        found = true;
                    } else if (strstr(line_buffer, "SigBlk:\tffffffe0fffbfaff")) {
                        found_sig = "found exceptional sigblk thread: %s";
                        found = true;
                    }

                    if (found) {
                        // 修正: 移除多余的 200
                        snprintf(log_buffer, 200, found_sig, line_buffer);
                        v7 = 0; // 0 = FAIL
                        log_buffer[strcspn(log_buffer, "\n")] = 0;
                        reason_str = log_buffer;
                        break; // goto LABEL_21
                    }
                }
                fclose(status_file);
            } else {
                __android_log_print(6, "envcheck-native", "checkThreads failed to open file %s", path_buffer);
            }
            if (v7 == 0) break;
        }
        closedir(dir);
    } else {
        __android_log_print(6, "envcheck-native", "checkThreads failed to opendir %s", path_buffer);
        return createCheckResult(env, JNI_TRUE, "PASS: checkThreads failed to opendir");
    }

    return createCheckResult(env, (v7 == 1) ? JNI_TRUE : JNI_FALSE, reason_str);
}


/*
 * 3. Maps 检测 (mapsCheck)
 */
extern "C" JNIEXPORT jobject JNICALL
Java_com_example_fridadetector_FridaChecker_mapsCheck(
        JNIEnv *env, jclass clazz) {

    unsigned int v6 = 1; // 1 = PASS
    std::string reason_str = "";
    char log_buffer[256] = {0}; // v14
    char path_buffer[256] = {0}; // filename

    pid_t pid = getpid();
    snprintf(path_buffer, 200, "/proc/%d/maps", pid); // 修正

    FILE *maps_file = fopen(path_buffer, "r");
    if (maps_file) {
        char line_buffer[256];
        const char *v5;
        while (fgets(line_buffer, 200, maps_file)) {
            bool found = false;
            if (strstr(line_buffer, "agent")) {
                v5 = "found maps record with agent: %s";
                found = true;
            } else if (strstr(line_buffer, "/data/local/tmp")) {
                v5 = "found maps record with /data/local/tmp path: %s";
                found = true;
            }

            if (found) {
                line_buffer[strcspn(line_buffer, "\n")] = 0;
                snprintf(log_buffer, 200, v5, line_buffer); // 修正
                reason_str = log_buffer;
                v6 = 0; // FAIL
                fclose(maps_file);
                goto end_maps_check;
            }
        }
        fclose(maps_file);

        // 修正
        snprintf(path_buffer, 200, "/data/local/tmp/re.frida.server/frida-agent-32.so");
        struct stat stat_buf;
        if (stat(path_buffer, &stat_buf) == 0) {
            // 修正
            snprintf(log_buffer, 200, "found /data/local/tmp/re.frida.server/frida-agent-32.so");
            reason_str = log_buffer;
            v6 = 0; // FAIL
        } else {
            v6 = 1; // PASS
        }
    } else {
        __android_log_print(6, "envcheck-native", "failed to open maps, error: %s", strerror(errno));
        return createCheckResult(env, JNI_TRUE, "PASS: failed to open maps");
    }

    end_maps_check:
    return createCheckResult(env, (v6 == 1) ? JNI_TRUE : JNI_FALSE, reason_str);
}

/*
 * 4. fd 检测 (sub_1940 -> fdCheck)
 */
extern "C" JNIEXPORT jobject JNICALL
Java_com_example_fridadetector_FridaChecker_fdCheck(
        JNIEnv *env, jclass clazz) {

    unsigned int v9 = 1; // 1 = PASS
    std::string reason_str = "";
    char log_buffer[256] = {0}; // buf
    char path_buffer[256] = {0}; // name

    pid_t pid = getpid();
    snprintf(path_buffer, 200, "/proc/%d/fd", pid); // 修正

    DIR *dir = opendir(path_buffer);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0 && entry->d_type == DT_LNK) {

                char fd_path[256];
                snprintf(fd_path, 200, "/proc/%d/fd/%s", pid, entry->d_name); // 修正

                ssize_t len = readlink(fd_path, log_buffer, 199); // 0xC7u = 199

                if (len < 0) {
                    __android_log_print(6, "envcheck-native", "checkFd failed to readlink, error: %s", strerror(errno));
                    closedir(dir);
                    return createCheckResult(env, JNI_TRUE, "PASS: checkFd failed to readlink");
                }
                log_buffer[len] = 0;

                bool found = false;
                if (strstr(log_buffer, "linjector")) {
                    // 修正
                    snprintf(log_buffer, 200, "found fd path with linjector: %s", entry->d_name);
                    found = true;
                } else if (strstr(log_buffer, "/data/local/tmp")) {
                    // 修正
                    snprintf(log_buffer, 200, "found fd path with /data/local/tmp: %s", entry->d_name);
                    found = true;
                }

                if (found) {
                    v9 = 0; // FAIL
                    reason_str = log_buffer;
                    break;
                }
            }
        } // end while
        closedir(dir);

        if (v9 == 1) {
            snprintf(path_buffer, 200, "/data/local/tmp/re.frida.server"); // 修正
            struct stat stat_buf;
            if (stat(path_buffer, &stat_buf) == 0) {
                // 修正
                snprintf(log_buffer, 200, "found /data/local/tmp/re.frida.server dir");
                reason_str = log_buffer;
                v9 = 0; // FAIL
            } else {
                v9 = 1; // PASS
            }
        }
    } else {
        __android_log_print(6, "envcheck-native", "checkFd failed to opendir %s", path_buffer);
        return createCheckResult(env, JNI_TRUE, "PASS: checkFd failed to opendir");
    }

    return createCheckResult(env, (v9 == 1) ? JNI_TRUE : JNI_FALSE, reason_str);
}



/*
 * 5. 内存特征检测 (sub_1C20 -> memoryCheck)
 * [严格模仿汇编的逐字节循环和空终止符检查]，不包含了空终止符检查
 */
extern "C" JNIEXPORT jobject JNICALL
Java_com_example_fridadetector_FridaChecker_memoryCheck(
        JNIEnv *env, jclass clazz) {

    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        __android_log_print(6, "envcheck-native", "checkMemory failed to open maps: %s", strerror(errno));
        // 汇编在 fopen 失败时返回 0 (NULL) (loc_2244)
        return NULL;
    }

    // --- 动态构建特征字符串以避免自检 (保持这个修复) ---
    char s_rpc[10];
    s_rpc[0] = 'f'; s_rpc[1] = 'r'; s_rpc[2] = 'i'; s_rpc[3] = 'd'; s_rpc[4] = 'a';
    s_rpc[5] = ':'; s_rpc[6] = 'r'; s_rpc[7] = 'p'; s_rpc[8] = 'c'; s_rpc[9] = 0; // 9 字节 + null

    char s_engine[18];
    s_engine[0] = 'F'; s_engine[1] = 'r'; s_engine[2] = 'i'; s_engine[3] = 'd'; s_engine[4] = 'a';
    s_engine[5] = 'S'; s_engine[6] = 'c'; s_engine[7] = 'r'; s_engine[8] = 'i'; s_engine[9] = 'p';
    s_engine[10] = 't'; s_engine[11] = 'E'; s_engine[12] = 'n'; s_engine[13] = 'g'; s_engine[14] = 'i';
    s_engine[15] = 'n'; s_engine[16] = 'e'; s_engine[17] = 0; // 17 字节 + null

    char s_gio[9];
    s_gio[0] = 'G'; s_gio[1] = 'L'; s_gio[2] = 'i'; s_gio[3] = 'b'; s_gio[4] = '-';
    s_gio[5] = 'G'; s_gio[6] = 'I'; s_gio[7] = 'O'; s_gio[8] = 0; // 8 字节 + null

    char s_gdbus[11];
    s_gdbus[0] = 'G'; s_gdbus[1] = 'D'; s_gdbus[2] = 'B'; s_gdbus[3] = 'u'; s_gdbus[4] = 's';
    s_gdbus[5] = 'P'; s_gdbus[6] = 'r'; s_gdbus[7] = 'o'; s_gdbus[8] = 'x'; s_gdbus[9] = 'y';
    s_gdbus[10] = 0; // 10 字节 + null

    char s_gum[10];
    s_gum[0] = 'G'; s_gum[1] = 'u'; s_gum[2] = 'm'; s_gum[3] = 'S'; s_gum[4] = 'c';
    s_gum[5] = 'r'; s_gum[6] = 'i'; s_gum[7] = 'p'; s_gum[8] = 't'; s_gum[9] = 0; // 9 字节 + null
    // --- 动态构建结束 ---


    char line_buffer[512]; // s
    unsigned long long start, end; // v29, v28 (X3, X9 in assembly loops)
    char perms[5]; // v30 (X4 + var_3A8)
    char path[256]; // s1 (X0 + s1 offset)

    while (fgets(line_buffer, 512, maps_file)) { // loc_1CC0
        path[0] = '\0';
        perms[0] = '\0';

        // 汇编: "%llx-%llx %4s %*x %*s %*d %[^\n]"
        int sscanf_res = sscanf(line_buffer, "%llx-%llx %4s %*x %*s %*d %255[^\n]", &start, &end, perms, path);

        // --- 严格过滤 ---
        // 汇编: CMP W0, #3; B.EQ loc_1CC0 (如果 sscanf 返回 3，跳回 fgets)
        // 意味着只有 sscanf 返回 4 或更多 (即 path 被读取) 才继续
        if (sscanf_res <= 3) continue; // loc_1CF0

        // 汇编: LDRB W8, [SP,#0x3E0+var_3A5]; CMP W8, #0x73 ('s'); B.EQ loc_1CC0
        // 检查权限第三位是否为 's' (共享)
        if (perms[2] == 's') continue; // loc_1CFC

        // 汇编: LDRB W8, [SP,#0x3E0+var_3A8]; CMP W8, #0x72 ('r'); B.NE loc_1CC0
        // 检查权限第一位是否为 'r' (可读)
        if (perms[0] != 'r') continue; // loc_1D08

        // 汇编: LDRB W8, [SP,#0x3E0+s1]; CMP W8, #0x2F ('/'); B.NE loc_1CC0
        // 检查路径是否以 '/' 开头
        if (path[0] != '/') continue; // loc_1D14 (sscanf_res > 3 保证 path 有内容)

        // 汇编: BL .memcmp; CBZ W0, loc_1CC0 (比较前 5 字节是否为 "/dev/")
        if (strncmp(path, "/dev/", 5) == 0) continue; // loc_1D28
        // --- 过滤结束 ---

        // --- 开始逐字节扫描 ---
        // 指向当前检查的内存地址的指针
        unsigned char* current_ptr = (unsigned char*)start; // X3, X4 in assembly loops

        // 1. 检查 "frida:rpc" (9 字节 + null 检查)
        // 汇编: SUB X8, X9, #0xA; CMP X8, X3; B.LS loc_1DD0
        unsigned char* limit_rpc = (unsigned char*)(end - 10); // X8
        unsigned char* p_rpc = current_ptr; // X4
        while (p_rpc <= limit_rpc) { // loc_1D50: CMP X8, X4
            if (p_rpc[0] == s_rpc[0] && // loc_1D5C: CMP W10, #0x66 ('f')
                p_rpc[1] == s_rpc[1] && // loc_1D68: CMP W10, #0x72 ('r')
                p_rpc[2] == s_rpc[2] && // ...
                p_rpc[3] == s_rpc[3] &&
                p_rpc[4] == s_rpc[4] &&
                p_rpc[5] == s_rpc[5] &&
                p_rpc[6] == s_rpc[6] &&
                p_rpc[7] == s_rpc[7] &&
                p_rpc[8] == s_rpc[8]  // loc_1DBC: CMP W10, #0x63 ('c')
//                &&p_rpc[9] == 0          // loc_1DC8: CBNZ W10, loc_1D4C (检查 null 终止符)
                    ) {
                // 找到了！(loc_22AC)
                __android_log_print(ANDROID_LOG_WARN, "envcheck-native", "found %s in memory at address %llx", s_rpc, (unsigned long long)p_rpc);
                char log_buffer[512];
                snprintf(log_buffer, 512, "found %s in memory", s_rpc);
                fclose(maps_file);
                return createCheckResult(env, JNI_FALSE, log_buffer); // FAIL
            }
            p_rpc++; // loc_1D4C: ADD X4, X4, #1
        }
        // 未找到 "frida:rpc" (loc_1DD0)

        // 2. 检查 "FridaScriptEngine" (17 字节 + null 检查)
        // 汇编: SUB X10, X9, #0x12; CMP X10, X3; B.LS loc_1ED4
        unsigned char* limit_engine = (unsigned char*)(end - 18); // X10
        unsigned char* p_engine = current_ptr; // X4
        while (p_engine <= limit_engine) { // loc_1DF4: CMP X10, X4
            if (p_engine[0] == s_engine[0] && // loc_1E00: CMP W11, #0x46 ('F')
                p_engine[1] == s_engine[1] && // loc_1E0C: CMP W11, #0x72 ('r')
                p_engine[2] == s_engine[2] && // ...
                p_engine[3] == s_engine[3] &&
                p_engine[4] == s_engine[4] &&
                p_engine[5] == s_engine[5] &&
                p_engine[6] == s_engine[6] &&
                p_engine[7] == s_engine[7] &&
                p_engine[8] == s_engine[8] &&
                p_engine[9] == s_engine[9] &&
                p_engine[10] == s_engine[10] &&
                p_engine[11] == s_engine[11] &&
                p_engine[12] == s_engine[12] &&
                p_engine[13] == s_engine[13] &&
                p_engine[14] == s_engine[14] &&
                p_engine[15] == s_engine[15] &&
                p_engine[16] == s_engine[16]  // loc_1EC0: CMP W11, #0x65 ('e')
//                &&p_engine[17] == 0             // loc_1ECC: CBNZ W11, loc_1DF0
                    ) {
                // 找到了！(loc_2354)
                __android_log_print(ANDROID_LOG_WARN, "envcheck-native", "found %s in memory at address %llx", s_engine, (unsigned long long)p_engine);
                char log_buffer[512];
                snprintf(log_buffer, 512, "found %s in memory", s_engine);
                fclose(maps_file);
                return createCheckResult(env, JNI_FALSE, log_buffer); // FAIL
            }
            p_engine++; // loc_1DF0: ADD X4, X4, #1
        }
        // 未找到 "FridaScriptEngine" (loc_1ED4)

        // 3. 检查 "GLib-GIO" (8 字节 + null 检查)
        // 汇编: SUB X10, X9, #9; CMP X10, X3; B.LS loc_1F8C
        unsigned char* limit_gio = (unsigned char*)(end - 9); // X10
        unsigned char* p_gio = current_ptr; // X4
        while (p_gio <= limit_gio) { // loc_1EF4: CMP X10, X4
            if (p_gio[0] == s_gio[0] && // loc_1F00: CMP W11, #0x47 ('G')
                p_gio[1] == s_gio[1] && // loc_1F0C: CMP W11, #0x4C ('L')
                p_gio[2] == s_gio[2] && // ...
                p_gio[3] == s_gio[3] &&
                p_gio[4] == s_gio[4] &&
                p_gio[5] == s_gio[5] &&
                p_gio[6] == s_gio[6] &&
                p_gio[7] == s_gio[7]  // loc_1F54: CMP W11, #0x4F ('O')
//                &&p_gio[8] == 0         // loc_1F60: CBNZ W11, loc_1EF0
                    ) {
                // 找到了！(loc_1F64)
                __android_log_print(ANDROID_LOG_WARN, "envcheck-native", "found %s in memory at address %llx", s_gio, (unsigned long long)p_gio);
                char log_buffer[512];
                // 汇编使用 X4 (p_gio) 作为格式化参数, 我们直接用 s_gio
                snprintf(log_buffer, 512, "found %s in memory", s_gio); // loc_2120
                fclose(maps_file);
                return createCheckResult(env, JNI_FALSE, log_buffer); // FAIL
            }
            p_gio++; // loc_1EF0: ADD X4, X4, #1
        }
        // 未找到 "GLib-GIO" (loc_1F8C)

        // 4. 检查 "GDBusProxy" (10 字节 + null 检查)
        // 汇编: SUB X9, X9, #0xB; CMP X9, X3; B.LS loc_2060
        unsigned char* limit_gdbus = (unsigned char*)(end - 11); // X9
        unsigned char* p_gdbus = current_ptr; // X4
        while (p_gdbus <= limit_gdbus) { // loc_1FB0: CMP X9, X4
            if (p_gdbus[0] == s_gdbus[0] && // loc_1FBC: CMP W10, #0x47 ('G')
                p_gdbus[1] == s_gdbus[1] && // loc_1FC8: CMP W10, #0x44 ('D')
                p_gdbus[2] == s_gdbus[2] && // ...
                p_gdbus[3] == s_gdbus[3] &&
                p_gdbus[4] == s_gdbus[4] &&
                p_gdbus[5] == s_gdbus[5] &&
                p_gdbus[6] == s_gdbus[6] &&
                p_gdbus[7] == s_gdbus[7] &&
                p_gdbus[8] == s_gdbus[8] &&
                p_gdbus[9] == s_gdbus[9]  // loc_2028: CMP W10, #0x79 ('y')
//                &&p_gdbus[10] == 0           // loc_2034: CBNZ W10, loc_1FAC
                    ) {
                // 找到了！(loc_2038)
                __android_log_print(ANDROID_LOG_WARN, "envcheck-native", "found %s in memory at address %llx", s_gdbus, (unsigned long long)p_gdbus);
                char log_buffer[512];
                snprintf(log_buffer, 512, "found %s in memory", s_gdbus); // loc_2120
                fclose(maps_file);
                return createCheckResult(env, JNI_FALSE, log_buffer); // FAIL
            }
            p_gdbus++; // loc_1FAC: ADD X4, X4, #1
        }
        // 未找到 "GDBusProxy" (loc_2060)

        // 5. 检查 "GumScript" (9 字节 + null 检查)
        // 汇编: CMP X8, X3 (X8 之前是 end - 0xA)
        unsigned char* limit_gum = (unsigned char*)(end - 10); // X8
        unsigned char* p_gum = current_ptr; // X3 (汇编这里复用了寄存器, C++ 用新变量)
        while (p_gum <= limit_gum) { // loc_2080: CMP X8, X3
            if (p_gum[0] == s_gum[0] && // loc_208C: CMP W9, #0x47 ('G')
                p_gum[1] == s_gum[1] && // loc_2098: CMP W9, #0x75 ('u')
                p_gum[2] == s_gum[2] && // ...
                p_gum[3] == s_gum[3] &&
                p_gum[4] == s_gum[4] &&
                p_gum[5] == s_gum[5] &&
                p_gum[6] == s_gum[6] &&
                p_gum[7] == s_gum[7] &&
                p_gum[8] == s_gum[8]  // loc_20EC: CMP W9, #0x74 ('t')
//                &&p_gum[9] == 0         // loc_20F8: CBNZ W9, loc_207C
                    ) {
                // 找到了！(loc_20FC)
                __android_log_print(ANDROID_LOG_WARN, "envcheck-native", "found %s in memory at address %llx", s_gum, (unsigned long long)p_gum);
                char log_buffer[512];
                snprintf(log_buffer, 512, "found %s in memory", s_gum); // loc_2120
                fclose(maps_file);
                return createCheckResult(env, JNI_FALSE, log_buffer); // FAIL
            }
            p_gum++; // loc_207C: ADD X3, X3, #1
        }
        // 未找到 "GumScript" (loc_21B4 -> loc_1CC0)
        // 如果所有字符串都没找到，继续下一个 maps 行

    } // end while(fgets)

    fclose(maps_file);
    // 循环结束, 未找到任何特征 (loc_21C0)
    return createCheckResult(env, JNI_TRUE, ""); // PASS (返回空字符串)
}


/*
 * 6. Trace 状态检查 (sub_2388 -> traceCheck)
 */

// 辅助函数: 对应 sub_27FC
int checkStatusForTrace(const char* path) {
    FILE *status_file = fopen(path, "r");
    if (!status_file) return 0;
    char line[256];
    int result = 0;
    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            if (atoi(line + 10) != 0) {
                result = 1; // FAIL
            }
            break;
        }
    }
    fclose(status_file);
    return result;
}

// 辅助函数: 对应 sub_2908
int checkStatForTrace(const char* path) {
    FILE *stat_file = fopen(path, "r");
    if (!stat_file) return 0;
    char line[256];
    if (fgets(line, sizeof(line), stat_file)) {
        char state = ' ';
        sscanf(line, "%*d (%*[^)]) %c", &state);
        if (state == 't') {
            fclose(stat_file);
            return 1; // FAIL
        }
    }
    fclose(stat_file);
    return 0;
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_example_fridadetector_FridaChecker_traceCheck(
        JNIEnv *env, jclass clazz) {

    unsigned int v22 = 1; // 1 = PASS
    std::string reason_str = "";
    char log_buffer[256] = {0}; // v25
    char path_buffer[256] = {0}; // name

    pid_t pid = getpid();

    snprintf(path_buffer, 200, "/proc/%d/status", pid); // 修正
    if (checkStatusForTrace(path_buffer) == 1) {
        snprintf(log_buffer, 200, "found trace state in /proc/%d/status", pid); // 修正
        reason_str = log_buffer;
        v22 = 0; // FAIL
        return createCheckResult(env, JNI_FALSE, reason_str);
    }

    snprintf(path_buffer, 200, "/proc/%d/stat", pid); // 修正
    if (checkStatForTrace(path_buffer) == 1) {
        snprintf(log_buffer, 200, "found trace state in /proc/%d/stat", pid); // 修正
        reason_str = log_buffer;
        v22 = 0; // FAIL
        return createCheckResult(env, JNI_FALSE, reason_str);
    }

    snprintf(path_buffer, 200, "/proc/%d/task", pid); // 修正
    DIR *dir = opendir(path_buffer);
    if (!dir) {
        __android_log_print(6, "envcheck-native", "checkTracerPid failed to opendir %s", path_buffer);
        return createCheckResult(env, JNI_TRUE, "PASS: checkTracerPid failed to opendir");
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        char task_path[256];

        snprintf(task_path, 200, "/proc/%d/task/%s/status", pid, entry->d_name); // 修正
        if (checkStatusForTrace(task_path) == 1) {
            snprintf(log_buffer, 200, "found trace status in %s", task_path); // 修正
            v22 = 0; // FAIL
            reason_str = log_buffer;
            break;
        }

        snprintf(task_path, 200, "/proc/%d/task/%s/stat", pid, entry->d_name); // 修正
        if (checkStatForTrace(task_path) == 1) {
            snprintf(log_buffer, 200, "found trace status in %s", task_path); // 修正
            v22 = 0; // FAIL
            reason_str = log_buffer;
            break;
        }
    }
    closedir(dir);

    return createCheckResult(env, (v22 == 1) ? JNI_TRUE : JNI_FALSE, reason_str);
}