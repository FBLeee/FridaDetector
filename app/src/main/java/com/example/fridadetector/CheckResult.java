package com.example.fridadetector;

// 模仿 sub_1418 返回的那个对象
public class CheckResult {
    private final boolean result; // true = PASS, false = FAIL
    private final String reason;

    // 这个构造函数将从 JNI (C++) 中被调用
    public CheckResult(boolean result, String reason) {
        this.result = result;
        this.reason = reason;
    }

    public boolean getResult() {
        return result;
    }

    public String getReason() {
        return reason;
    }
}