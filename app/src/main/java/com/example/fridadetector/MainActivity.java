package com.example.fridadetector;

import androidx.appcompat.app.AppCompatActivity;
import android.graphics.Color;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private TextView tvOverallResult, tvDetailsBox;
    private TextView tvResultPort, tvResultThread, tvResultMaps, tvResultFd, tvResultTrace, tvResultMemory;
    private LinearLayout btnCheck;

    private int colorRed;
    private int colorGreen;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        colorRed = Color.parseColor("#FF5555");
        colorGreen = Color.parseColor("#55FF55");

        // 查找所有 UI 元素 (ID 来自 activity_main.xml)
        btnCheck = findViewById(R.id.btn_check);
        tvOverallResult = findViewById(R.id.tv_overall_result);
        tvDetailsBox = findViewById(R.id.tv_details_box);

        tvResultPort = findViewById(R.id.tv_result_port);
        tvResultThread = findViewById(R.id.tv_result_thread);
        tvResultMaps = findViewById(R.id.tv_result_maps);
        tvResultFd = findViewById(R.id.tv_result_fd);
        tvResultTrace = findViewById(R.id.tv_result_trace);
        tvResultMemory = findViewById(R.id.tv_result_memory);

        btnCheck.setOnClickListener(v -> runAllChecks());
    }

    private void runAllChecks() {
        StringBuilder detailsLog = new StringBuilder();
        List<CheckResult> results = new ArrayList<>();

        // --- 严格按照你提供的顺序执行 ---

        // 1. 端口检测
        CheckResult portResult = FridaChecker.portCheck();
        results.add(portResult);
        updateCheckUI(tvResultPort, portResult);
        detailsLog.append("PortCheck: ").append(getReason(portResult)).append("\n");

        // 2. 线程检测
        CheckResult threadResult = FridaChecker.threadCheck();
        results.add(threadResult);
        updateCheckUI(tvResultThread, threadResult);
        detailsLog.append("ThreadCheck: ").append(getReason(threadResult)).append("\n");

        // 3. Maps 检测
        CheckResult mapsResult = FridaChecker.mapsCheck();
        results.add(mapsResult);
        updateCheckUI(tvResultMaps, mapsResult);
        detailsLog.append("MapsCheck: ").append(getReason(mapsResult)).append("\n");

        // 4. FD 检测
        CheckResult fdResult = FridaChecker.fdCheck();
        results.add(fdResult);
        updateCheckUI(tvResultFd, fdResult);
        detailsLog.append("FdCheck: ").append(getReason(fdResult)).append("\n");

        // 5. 内存检测
        CheckResult memoryResult = FridaChecker.memoryCheck();
        results.add(memoryResult);
        updateCheckUI(tvResultMemory, memoryResult);
        detailsLog.append("MemoryCheck: ").append(getReason(memoryResult)).append("\n");

        // 6. Trace 检测
        CheckResult traceResult = FridaChecker.traceCheck();
        results.add(traceResult);
        updateCheckUI(tvResultTrace, traceResult);
        detailsLog.append("TraceCheck: ").append(getReason(traceResult)).append("\n");


        // --- 更新总览 UI ---
        tvDetailsBox.setText(detailsLog.toString());

        boolean isFridaFound = false;
        for (CheckResult res : results) {
            if (!res.getResult()) { // getResult()=false 代表 FAIL (发现)
                isFridaFound = true;
                break;
            }
        }

        if (isFridaFound) {
            tvOverallResult.setText("发现Frida");
            tvOverallResult.setTextColor(colorRed);
        } else {
            tvOverallResult.setText("未发现Frida");
            tvOverallResult.setTextColor(colorGreen);
        }
    }

    // 辅助方法: 伪代码在 PASS 时返回空字符串
    private String getReason(CheckResult result) {
        if (result.getResult() || result.getReason() == null || result.getReason().isEmpty()) {
            return "PASS";
        }
        return result.getReason();
    }

    private void updateCheckUI(TextView textView, CheckResult result) {
        if (result.getResult()) {
            // PASS (未发现)
            textView.setText("未发现Frida");
            textView.setTextColor(colorGreen);
        } else {
            // FAIL (已发现)
            textView.setText("发现Frida");
            textView.setTextColor(colorRed);
        }
    }
}