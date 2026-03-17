package com.example.android_anomaly_detector_2

import android.Manifest
import android.app.ActivityManager
import android.app.AppOpsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var sysScoreText: TextView
    private lateinit var netScoreText: TextView
    private lateinit var statusText: TextView
    private lateinit var detectedAppNameText: TextView
    private lateinit var anomalyTypeText: TextView
    private lateinit var hashValueText: TextView
    private lateinit var threatInfoContainer: View
    private lateinit var btnStart: Button
    private lateinit var btnKill: Button
    private lateinit var btnConnectServer: Button
    
    private var currentSuspect: String? = null
    private var isServerConnected = false

    private val detectionReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            intent?.let {
                val sysScore = it.getDoubleExtra(AnomalyDetectorService.EXTRA_SYS_SCORE, 0.0)
                val netScore = it.getDoubleExtra(AnomalyDetectorService.EXTRA_NET_SCORE, 0.0)
                val detectedApp = it.getStringExtra(AnomalyDetectorService.EXTRA_DETECTED_APP) ?: ""
                val appHash = it.getStringExtra(AnomalyDetectorService.EXTRA_APP_HASH) ?: ""
                val anomalyType = it.getStringExtra(AnomalyDetectorService.EXTRA_ANOMALY_TYPE) ?: ""

                sysScoreText.text = "${(sysScore * 100).toInt()}%"
                netScoreText.text = "${(netScore * 100).toInt()}%"

                updateScoreColor(sysScoreText, sysScore)
                updateScoreColor(netScoreText, netScore)
                
                if (detectedApp.isNotEmpty() && (sysScore > 0.65 || netScore > 0.65)) {
                    statusText.text = "ANOMALY DETECTED"
                    statusText.setTextColor(Color.parseColor("#D32F2F"))
                    
                    currentSuspect = detectedApp
                    detectedAppNameText.text = detectedApp
                    anomalyTypeText.text = anomalyType
                    hashValueText.text = appHash
                    
                    threatInfoContainer.visibility = View.VISIBLE
                } else {
                    statusText.text = "SYSTEM SECURE"
                    statusText.setTextColor(Color.parseColor("#2E7D32"))
                    threatInfoContainer.visibility = View.GONE
                    currentSuspect = null
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        sysScoreText = findViewById(R.id.sysScoreText)
        netScoreText = findViewById(R.id.netScoreText)
        statusText = findViewById(R.id.statusText)
        detectedAppNameText = findViewById(R.id.detectedAppNameText)
        anomalyTypeText = findViewById(R.id.anomalyTypeText)
        hashValueText = findViewById(R.id.hashValueText)
        threatInfoContainer = findViewById(R.id.threatInfoContainer)
        btnStart = findViewById(R.id.btnStart)
        btnKill = findViewById(R.id.btnKill)
        btnConnectServer = findViewById(R.id.btnConnectServer)

        btnStart.setOnClickListener { checkPermissionsAndStart() }
        
        btnKill.setOnClickListener {
            currentSuspect?.let { showKillDialog(it) }
        }

        btnConnectServer.setOnClickListener {
            isServerConnected = !isServerConnected
            if (isServerConnected) {
                btnConnectServer.text = "SERVER CONNECTED (DISCONNECT)"
                btnConnectServer.setTextColor(Color.parseColor("#2E7D32"))
                Toast.makeText(this, "Upload to Central Server Enabled", Toast.LENGTH_SHORT).show()
            } else {
                btnConnectServer.text = "CONNECT TO CENTRAL SERVER"
                btnConnectServer.setTextColor(Color.parseColor("#888888"))
                Toast.makeText(this, "Upload Disabled", Toast.LENGTH_SHORT).show()
            }
            
            val intent = Intent(this, AnomalyDetectorService::class.java)
            intent.putExtra("SERVER_CONNECTION", isServerConnected)
            startService(intent)
        }
        
        handleIntent(intent)
    }

    private fun updateScoreColor(textView: TextView, score: Double) {
        when {
            score > 0.75 -> textView.setTextColor(Color.parseColor("#D32F2F"))
            score > 0.50 -> textView.setTextColor(Color.parseColor("#FF6D00"))
            else -> textView.setTextColor(Color.parseColor("#000000"))
        }
    }

    private fun killApp(packageName: String) {
        try {
            val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            am.killBackgroundProcesses(packageName)
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.fromParts("package", packageName, null)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(this, "Action failed", Toast.LENGTH_SHORT).show()
        }
    }

    private fun showKillDialog(packageName: String) {
        AlertDialog.Builder(this)
            .setTitle("Threat Mitigation")
            .setMessage("Application '$packageName' is exhibiting malicious behavior. Terminate process now?")
            .setPositiveButton("STOP PROCESS") { _, _ -> killApp(packageName) }
            .setNegativeButton("IGNORE", null)
            .show()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(AnomalyDetectorService.ACTION_DETECTION_UPDATE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(detectionReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(detectionReceiver, filter)
        }
    }

    override fun onStop() {
        super.onStop()
        unregisterReceiver(detectionReceiver)
    }

    private fun checkPermissionsAndStart() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            } else {
                checkUsageStatsAndStart()
            }
        } else {
            checkUsageStatsAndStart()
        }
    }

    private fun checkUsageStatsAndStart() {
        if (!hasUsageStatsPermission()) {
            startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
        } else {
            startDetectionService()
        }
    }

    private fun hasUsageStatsPermission(): Boolean {
        val appOps = getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), packageName)
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    private fun startDetectionService() {
        val intent = Intent(this, AnomalyDetectorService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        btnStart.text = "PROTECTION ACTIVE"
        btnStart.isEnabled = false
        btnStart.alpha = 0.5f
    }

    private val requestNotificationPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted: Boolean ->
        if (isGranted) checkUsageStatsAndStart()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        intent?.getStringExtra("KILL_TARGET")?.let { packageName -> showKillDialog(packageName) }
    }
}
