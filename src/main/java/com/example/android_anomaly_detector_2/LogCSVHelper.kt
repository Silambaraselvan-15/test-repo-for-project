package com.example.android_anomaly_detector_2

import android.content.Context
import android.os.Environment
import java.io.File
import java.io.FileOutputStream
import java.io.PrintWriter

class LogCSVHelper(private val context: Context) {

    // Get a directory that is accessible via PC (Android/data/com.example.android_anomaly_detector_2/files)
    private fun getLogDir(): File? = context.getExternalFilesDir(null)

    fun appendSystemLog(features: DoubleArray) {
        val dir = getLogDir() ?: return
        val file = File(dir, "system_logs.csv")
        val isNew = !file.exists()
        
        PrintWriter(FileOutputStream(file, true)).use { out ->
            if (isNew) {
                out.println("mem_usage,battery_pct,battery_temp,process_count")
            }
            out.println(features.joinToString(","))
        }
    }

    fun appendNetworkLog(features: DoubleArray) {
        val dir = getLogDir() ?: return
        val file = File(dir, "network_logs.csv")
        val isNew = !file.exists()
        
        PrintWriter(FileOutputStream(file, true)).use { out ->
            if (isNew) {
                out.println("rx_delta,tx_delta,mob_rx_delta,mob_tx_delta")
            }
            out.println(features.joinToString(","))
        }
    }

    fun getLogCount(): Int {
        val dir = getLogDir() ?: return 0
        val file = File(dir, "system_logs.csv")
        if (!file.exists()) return 0
        return file.readLines().size - 1
    }

    fun clearLogs() {
        val dir = getLogDir() ?: return
        File(dir, "system_logs.csv").delete()
        File(dir, "network_logs.csv").delete()
    }

    fun getFiles(): List<File> {
        val dir = getLogDir() ?: return emptyList()
        return listOf(File(dir, "system_logs.csv"), File(dir, "network_logs.csv")).filter { it.exists() }
    }
}
