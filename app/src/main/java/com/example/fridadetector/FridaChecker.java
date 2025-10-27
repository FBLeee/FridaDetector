package com.example.fridadetector;

public class FridaChecker {

    static {
        System.loadLibrary("native-lib");
    }

    // 对应 portCheck
    public static native CheckResult portCheck();

    // 对应 threadCheck
    public static native CheckResult threadCheck();

    // 对应 mapsCheck
    public static native CheckResult mapsCheck();

    // 对应 sub_1940 (fdCheck)
    public static native CheckResult fdCheck();

    // 对应 sub_2388 (traceCheck)
    public static native CheckResult traceCheck();

    // 对应 sub_1C20 (memoryCheck)
    public static native CheckResult memoryCheck();
}