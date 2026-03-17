package com.example.android_anomaly_detector_2

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import com.google.gson.Gson
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.net.HttpURLConnection
import java.net.URL

class ThreatIntelligenceUploader(private val context: Context) {

    private val executor = Executors.newSingleThreadExecutor()
    private var isServerConnected = false
    private var serverBaseUrl = "http://10.0.2.2:5000" // Default for Emulator to PC Localhost

    data class ThreatReport(
        val packageName: String,
        val appHash: String,
        val anomalyType: String,
        val timestamp: Long = System.currentTimeMillis(),
        val deviceModel: String = android.os.Build.MODEL
    )

    fun setServerConnection(enabled: Boolean, url: String = "http://10.0.2.2:5000") {
        this.isServerConnected = enabled
        this.serverBaseUrl = url
        Log.d("ThreatUploader", "Server connection set to: $enabled at $url")
    }

    fun reportThreat(packageName: String, appHash: String, anomalyType: String) {
        if (!isServerConnected) {
            Log.i("ThreatUploader", "Central server not connected. Skipping upload.")
            return
        }

        executor.execute {
            try {
                val report = ThreatReport(packageName, appHash, anomalyType)
                val jsonReport = Gson().toJson(report)
                
                val url = URL("$serverBaseUrl/report")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.doOutput = true
                
                conn.outputStream.use { os ->
                    os.write(jsonReport.toByteArray())
                }

                val responseCode = conn.responseCode
                if (responseCode == 200) {
                    Log.i("ThreatUploader", "✅ Successfully uploaded threat intel to Flask server.")
                } else {
                    Log.e("ThreatUploader", "❌ Server returned error: $responseCode")
                }
                conn.disconnect()
            } catch (e: Exception) {
                Log.e("ThreatUploader", "❌ Flask Upload Failed: ${e.message}")
            }
        }
    }

    fun calculateAppHash(packageName: String): String {
        return try {
            val packageManager = context.packageManager
            val packageInfo = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(packageName, 0)
            }
            
            val apkPath = packageInfo.applicationInfo?.sourceDir ?: return "ERROR: SourceDir Null"
            val file = File(apkPath)
            
            val digest = MessageDigest.getInstance("SHA-256")
            FileInputStream(file).use { fis ->
                val buffer = ByteArray(8192)
                var bytesRead = fis.read(buffer)
                while (bytesRead != -1) {
                    digest.update(buffer, 0, bytesRead)
                    bytesRead = fis.read(buffer)
                }
            }
            
            val hashBytes = digest.digest()
            hashBytes.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            "HASH_ERROR: ${e.message}"
        }
    }
}
