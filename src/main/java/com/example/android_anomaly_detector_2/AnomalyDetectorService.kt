package com.example.android_anomaly_detector_2

import android.app.ActivityManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.net.TrafficStats
import android.os.BatteryManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import java.util.Locale
import kotlin.math.abs
import kotlin.math.max

class AnomalyDetectorService : Service() {

    companion object {
        const val ACTION_DETECTION_UPDATE = "com.example.android_anomaly_detector_2.DETECTION_UPDATE"
        const val EXTRA_SYS_SCORE = "extra_sys_score"
        const val EXTRA_NET_SCORE = "extra_net_score"
        const val EXTRA_DETECTED_APP = "extra_detected_app"
        const val EXTRA_APP_HASH = "extra_app_hash"
        const val EXTRA_ANOMALY_TYPE = "extra_anomaly_type"
    }

    private val handler = Handler(Looper.getMainLooper())
    private val INTERVAL = 5000L 

    private val systemAnomalyDetector = IsolationForestDetector()
    private val networkAnomalyDetector = IsolationForestDetector()
    private lateinit var threatUploader: ThreatIntelligenceUploader

    private var lastTotalRx = 0L
    private var lastTotalTx = 0L
    private var lastAlertTime = 0L
    
    private var currentDetectedApp: String = ""
    private var currentAppHash: String = ""
    private var currentAnomalyType: String = ""
    private var isServerConnectionEnabled = false

    private var sysBaseline = 0.0
    private var netBaseline = 0.0
    private var memBaseline = 0.0
    private var maxSysNoise = 0.0
    private var maxNetNoise = 0.0
    
    private var calibrationSamplesCollected = 0
    private val REQUIRED_CALIBRATION_SAMPLES = 6 // 30 seconds of quiet time

    override fun onCreate() {
        super.onCreate()
        threatUploader = ThreatIntelligenceUploader(this)
        createNotificationChannel()
        startForeground(1, createNotification("Security Dashboard: Active"))
        
        lastTotalRx = TrafficStats.getTotalRxBytes()
        lastTotalTx = TrafficStats.getTotalTxBytes()
        
        loadModelsFromAssets()
    }

    private fun loadModelsFromAssets() {
        try {
            val sysJson = assets.open("system_model.json").bufferedReader().use { it.readText() }
            val netJson = assets.open("network_model.json").bufferedReader().use { it.readText() }
            systemAnomalyDetector.deserialize(sysJson)
            networkAnomalyDetector.deserialize(netJson)
        } catch (e: Exception) {
            Log.e("AnomalyDetector", "❌ Models missing in assets!")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent != null && intent.hasExtra("SERVER_CONNECTION")) {
            isServerConnectionEnabled = intent.getBooleanExtra("SERVER_CONNECTION", false)
            threatUploader.setServerConnection(isServerConnectionEnabled)
        }
        calibrationSamplesCollected = 0
        sysBaseline = 0.0
        netBaseline = 0.0
        memBaseline = 0.0
        maxSysNoise = 0.0
        maxNetNoise = 0.0
        startDetectionLoop()
        return START_STICKY
    }

    private fun startDetectionLoop() {
        handler.removeCallbacksAndMessages(null)
        handler.post(object : Runnable {
            override fun run() {
                val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
                val memInfo = ActivityManager.MemoryInfo()
                am.getMemoryInfo(memInfo)
                val curMem = (memInfo.totalMem - memInfo.availMem).toDouble() / memInfo.totalMem.toDouble()

                val sysFeats = collectSystemFeatures(curMem)
                val netFeats = collectNetworkFeatures()

                val rawSys = systemAnomalyDetector.getAnomalyScore(sysFeats)
                val rawNet = networkAnomalyDetector.getAnomalyScore(netFeats)

                if (calibrationSamplesCollected < REQUIRED_CALIBRATION_SAMPLES) {
                    if (calibrationSamplesCollected > 0) {
                        maxSysNoise = max(maxSysNoise, abs(rawSys - (sysBaseline/calibrationSamplesCollected)))
                        maxNetNoise = max(maxNetNoise, abs(rawNet - (netBaseline/calibrationSamplesCollected)))
                    }
                    sysBaseline += rawSys
                    netBaseline += rawNet
                    memBaseline += curMem
                    calibrationSamplesCollected++
                    updateNotification("Calibrating sensors... ($calibrationSamplesCollected/$REQUIRED_CALIBRATION_SAMPLES)")
                    
                    if (calibrationSamplesCollected == REQUIRED_CALIBRATION_SAMPLES) {
                        sysBaseline /= REQUIRED_CALIBRATION_SAMPLES
                        netBaseline /= REQUIRED_CALIBRATION_SAMPLES
                        memBaseline /= REQUIRED_CALIBRATION_SAMPLES
                        // Safety buffer
                        maxSysNoise = max(0.05, maxSysNoise * 1.5)
                        maxNetNoise = max(0.15, maxNetNoise * 1.5)
                    }
                } else {
                    val sysDiff = abs(rawSys - sysBaseline)
                    val netDiff = abs(rawNet - netBaseline)
                    val memDiff = max(0.0, curMem - memBaseline)

                    // INCREASED SYSTEM SENSITIVITY: 25x multiplier
                    var uiSys = if (sysDiff > 0.01 || memDiff > 0.02) Math.min(0.98, 0.40 + (sysDiff * 25.0) + (memDiff * 15.0)) else 0.20 + (sysDiff * 2.0)
                    val uiNet = if (netDiff > maxNetNoise) Math.min(0.98, 0.30 + (netDiff * 4.0)) else 0.15 + (netDiff * 1.0)

                    // FAIL-SAFE: Real system hang
                    if (memInfo.lowMemory || curMem > 0.85) uiSys = 0.96

                    Log.d("AnomalyDetector", String.format(Locale.US, "RAW DIFF: S=%.4f, M=%.4f | UI: Sys=%.2f, Net=%.2f", sysDiff, memDiff, uiSys, uiNet))

                    if ((uiSys > 0.65 || uiNet > 0.65) && System.currentTimeMillis() - lastAlertTime > 15000) {
                        val suspect = findSuspectApp()
                        if (suspect != null && suspect != packageName) {
                            currentDetectedApp = suspect
                            currentAnomalyType = if (uiSys > uiNet) "System Behavior Anomaly" else "Network Traffic Anomaly"
                            currentAppHash = threatUploader.calculateAppHash(suspect)
                            threatUploader.reportThreat(suspect, currentAppHash, currentAnomalyType)
                            notifyUser(currentAnomalyType, "Observation: Abnormal activity ($suspect)", suspect)
                            lastAlertTime = System.currentTimeMillis()
                        }
                    } else if (uiSys < 0.55 && uiNet < 0.55) {
                        currentDetectedApp = ""
                        currentAppHash = ""
                        currentAnomalyType = ""
                    }
                    updateNotification("System Protected - Normal Activity")
                    sendDetectionBroadcast(uiSys, uiNet, currentDetectedApp, currentAppHash, currentAnomalyType)
                }
                handler.postDelayed(this, INTERVAL)
            }
        })
    }

    private fun sendDetectionBroadcast(sysScore: Double, netScore: Double, detectedApp: String, hash: String, type: String) {
        val intent = Intent(ACTION_DETECTION_UPDATE)
        intent.putExtra(EXTRA_SYS_SCORE, sysScore)
        intent.putExtra(EXTRA_NET_SCORE, netScore)
        intent.putExtra(EXTRA_DETECTED_APP, detectedApp)
        intent.putExtra(EXTRA_APP_HASH, hash)
        intent.putExtra(EXTRA_ANOMALY_TYPE, type)
        intent.setPackage(packageName)
        sendBroadcast(intent)
    }

    private fun findSuspectApp(): String? {
        val usm = getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val time = System.currentTimeMillis()
        val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, time - 15000, time)
        return stats?.filter { it.packageName != packageName && !isSystemApp(it.packageName) }
                    ?.maxByOrNull { it.lastTimeUsed }?.packageName
    }

    private fun isSystemApp(packageName: String): Boolean {
        val pkg = packageName.lowercase()
        if (pkg.startsWith("com.android.") || pkg.startsWith("com.google.android.") || 
            pkg.startsWith("com.samsung.") || pkg.startsWith("com.sec.") ||
            pkg.contains("whatsapp") || pkg.contains("spotify") || pkg.contains("amazon") ||
            pkg.contains(".launcher") || pkg.contains(".browser")) return true
        return try {
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        } catch (e: Exception) { false }
    }

    private fun collectSystemFeatures(m: Double): DoubleArray {
        val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        val bat = registerReceiver(null, filter)
        val pct = (bat?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: 50).toDouble()
        val temp = (bat?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) ?: 0) / 10.0
        val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val proc = (am.runningAppProcesses?.size?.toDouble() ?: 100.0)
        return doubleArrayOf(m, pct, temp, proc)
    }

    private fun collectNetworkFeatures(): DoubleArray {
        val curRx = TrafficStats.getTotalRxBytes()
        val curTx = TrafficStats.getTotalTxBytes()
        val rx = (curRx - lastTotalRx).coerceAtLeast(0)
        val tx = (curTx - lastTotalTx).coerceAtLeast(0)
        // 100KB noise floor
        val fRx = if (rx < 102400) 0.0 else rx.toDouble()
        val fTx = if (tx < 102400) 0.0 else tx.toDouble()
        lastTotalRx = curRx
        lastTotalTx = curTx
        return doubleArrayOf(fRx, fTx, 0.0, 0.0)
    }

    private fun notifyUser(title: String, message: String, suspect: String) {
        val intent = Intent(this, MainActivity::class.java).apply {
            putExtra("KILL_TARGET", suspect)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pi = android.app.PendingIntent.getActivity(this, 0, intent, android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(this, "ShieldChannel")
            .setContentTitle(title).setContentText(message).setSmallIcon(android.R.drawable.stat_sys_warning)
            .setPriority(NotificationCompat.PRIORITY_HIGH).setContentIntent(pi).setAutoCancel(true).build()
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(101, notification)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel("ShieldChannel", "Security Alerts", NotificationManager.IMPORTANCE_HIGH)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun createNotification(content: String): Notification {
        return NotificationCompat.Builder(this, "ShieldChannel").setContentTitle("Anomaly Dashboard").setContentText(content)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock).setOngoing(true).build()
    }

    private fun updateNotification(content: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(1, createNotification(content))
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
