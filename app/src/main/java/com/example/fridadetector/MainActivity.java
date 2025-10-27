package com.example.fridadetector;

import androidx.appcompat.app.AppCompatActivity;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler; // <-- 引入 Handler
import android.os.Looper; // <-- 引入 Looper
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService; // <-- 引入 ExecutorService
import java.util.concurrent.Executors;     // <-- 引入 Executors

public class MainActivity extends AppCompatActivity {

    private TextView tvOverallResult, tvDetailsBox;
    private TextView tvResultPort, tvResultThread, tvResultMaps, tvResultFd, tvResultTrace, tvResultMemory;
    private LinearLayout btnCheck;

    private int colorRed;
    private int colorGreen;

    // --- 新增: 后台执行器和主线程 Handler ---
    private ExecutorService executor;
    private Handler mainThreadHandler;
    // --- 新增结束 ---

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        colorRed = Color.parseColor("#FF5555");
        colorGreen = Color.parseColor("#55FF55");

        // --- 初始化执行器和 Handler ---
        executor = Executors.newSingleThreadExecutor(); // 创建单线程执行器
        mainThreadHandler = new Handler(Looper.getMainLooper()); // 获取主线程 Looper
        // --- 初始化结束 ---

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

        // --- 修改 OnClickListener ---
        btnCheck.setOnClickListener(v -> {
            // 1. (可选) 禁用按钮防止重复点击
            btnCheck.setEnabled(false);
            tvOverallResult.setText("检测中...");
            tvOverallResult.setTextColor(Color.WHITE);
            tvDetailsBox.setText("正在执行检测，请稍候...");
            // 清空旧结果
            clearPreviousResults();

            // 2. 将耗时任务提交到后台线程
            executor.execute(() -> {
                // --- 这部分代码将在后台线程执行 ---
                final StringBuilder detailsLog = new StringBuilder();
                final List<CheckResult> results = new ArrayList<>();
                boolean overallFound = false;

                try {
                    // 1. 端口检测
                    CheckResult portResult = FridaChecker.portCheck();
                    results.add(portResult);
                    detailsLog.append("PortCheck: ").append(getReason(portResult)).append("\n");
                    if (portResult != null && !portResult.getResult()) overallFound = true;

                    // 2. 线程检测
                    CheckResult threadResult = FridaChecker.threadCheck();
                    results.add(threadResult);
                    detailsLog.append("ThreadCheck: ").append(getReason(threadResult)).append("\n");
                    if (threadResult != null && !threadResult.getResult()) overallFound = true;

                    // 3. Maps 检测
                    CheckResult mapsResult = FridaChecker.mapsCheck();
                    results.add(mapsResult);
                    detailsLog.append("MapsCheck: ").append(getReason(mapsResult)).append("\n");
                    if (mapsResult != null && !mapsResult.getResult()) overallFound = true;

                    // 4. FD 检测
                    CheckResult fdResult = FridaChecker.fdCheck();
                    results.add(fdResult);
                    detailsLog.append("FdCheck: ").append(getReason(fdResult)).append("\n");
                    if (fdResult != null && !fdResult.getResult()) overallFound = true;

                    // 5. 内存检测 (最耗时)
                    CheckResult memoryResult = FridaChecker.memoryCheck();
                    results.add(memoryResult);
                    detailsLog.append("MemoryCheck: ").append(getReason(memoryResult)).append("\n");
                    if (memoryResult != null && !memoryResult.getResult()) overallFound = true;

                    // 6. Trace 检测
                    CheckResult traceResult = FridaChecker.traceCheck();
                    results.add(traceResult);
                    detailsLog.append("TraceCheck: ").append(getReason(traceResult)).append("\n");
                    if (traceResult != null && !traceResult.getResult()) overallFound = true;

                } catch (UnsatisfiedLinkError e) {
                    // 处理 JNI 调用失败 (例如 .so 加载问题)
                    detailsLog.append("\n\nError: JNI call failed. Check native library.\n").append(e.getMessage());
                    overallFound = true; // 标记为失败状态
                } catch (Exception e) {
                    // 处理其他潜在异常
                    detailsLog.append("\n\nError: An exception occurred during checks.\n").append(e.getMessage());
                    overallFound = true; // 标记为失败状态
                }


                // --- 后台任务完成 ---
                final boolean finalIsFridaFound = overallFound; // 在 lambda 中使用需要 final

                // 3. 将 UI 更新任务发送回主线程
                mainThreadHandler.post(() -> {
                    // --- 这部分代码将在主线程执行 ---
                    if (results.size() >= 6) { // 确保所有结果都回来了
                        updateCheckUI(tvResultPort, results.get(0));
                        updateCheckUI(tvResultThread, results.get(1));
                        updateCheckUI(tvResultMaps, results.get(2));
                        updateCheckUI(tvResultFd, results.get(3));
                        updateCheckUI(tvResultMemory, results.get(4));
                        updateCheckUI(tvResultTrace, results.get(5));
                    } else {
                        // 如果因为异常导致结果不全，显示错误信息
                        tvDetailsBox.setText("检测过程中发生错误:\n" + detailsLog.toString());
                    }


                    tvDetailsBox.setText(detailsLog.toString());

                    if (finalIsFridaFound) {
                        tvOverallResult.setText("发现Frida");
                        tvOverallResult.setTextColor(colorRed);
                    } else {
                        tvOverallResult.setText("未发现Frida");
                        tvOverallResult.setTextColor(colorGreen);
                    }

                    // 4. 重新启用按钮
                    btnCheck.setEnabled(true);
                    // --- UI 更新结束 ---
                });
                // --- 主线程任务发送结束 ---
            });
            // --- 后台任务提交结束 ---
        });
        // --- OnClickListener 修改结束 ---
    }

    // --- 新增: 清理旧结果的辅助方法 ---
    private void clearPreviousResults() {
        tvResultPort.setText("-");
        tvResultPort.setTextColor(Color.WHITE);
        tvResultThread.setText("-");
        tvResultThread.setTextColor(Color.WHITE);
        tvResultMaps.setText("-");
        tvResultMaps.setTextColor(Color.WHITE);
        tvResultFd.setText("-");
        tvResultFd.setTextColor(Color.WHITE);
        tvResultMemory.setText("-");
        tvResultMemory.setTextColor(Color.WHITE);
        tvResultTrace.setText("-");
        tvResultTrace.setTextColor(Color.WHITE);
    }
    // --- 新增结束 ---


    // 辅助方法: 伪代码在 PASS 时返回空字符串
    private String getReason(CheckResult result) {
        // 添加 null 检查
        if (result == null) {
            return "ERROR: CheckResult is null";
        }
        if (result.getResult() || result.getReason() == null || result.getReason().isEmpty()) {
            return "PASS";
        }
        return result.getReason();
    }

    private void updateCheckUI(TextView textView, CheckResult result) {
        // 添加 null 检查
        if (result == null) {
            textView.setText("错误");
            textView.setTextColor(colorRed);
            return;
        }

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

    // --- 新增: 在 Activity 销毁时关闭线程池 ---
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (executor != null && !executor.isShutdown()) {
            executor.shutdown(); // 请求关闭
        }
    }
    // --- 新增结束 ---
}