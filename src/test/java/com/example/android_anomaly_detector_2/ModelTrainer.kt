package com.example.android_anomaly_detector_2

import org.junit.Test
import java.io.File

class ModelTrainer {

    @Test
    fun trainAndExportModels() {
        // 1. Path to your collected CSV files on your PC
        // Update these paths to where you saved the files from your phone
        val systemCsvPath = "C:/Users/HP/Videos/mov/system_logs.csv"
        val networkCsvPath = "C:/Users/HP/Videos/mov/network_logs.csv"

        println("Starting training...")

        // 2. Train System Model
        val sysData = loadCsv(systemCsvPath)
        val sysDetector = IsolationForestDetector(numTrees = 100)
        sysDetector.train(sysData)
        val sysJson = sysDetector.serialize()
        File("system_model.json").writeText(sysJson)
        println("System model trained with ${sysData.size} samples.")

        // 3. Train Network Model
        val netData = loadCsv(networkCsvPath)
        val netDetector = IsolationForestDetector(numTrees = 100)
        netDetector.train(netData)
        val netJson = netDetector.serialize()
        File("network_model.json").writeText(netJson)
        println("Network model trained with ${netData.size} samples.")

        println("Training Complete! JSON files generated in project root.")
    }

    private fun loadCsv(path: String): List<DoubleArray> {
        val file = File(path)
        if (!file.exists()) throw Exception("File not found at $path")

        return file.readLines().drop(1).map { line ->
            line.split(",").map { it.toDouble() }.toDoubleArray()
        }
    }
}
