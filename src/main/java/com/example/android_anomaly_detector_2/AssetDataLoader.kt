package com.example.android_anomaly_detector_2

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader

class AssetDataLoader(private val context: Context) {

    fun loadCsvFromAssets(fileName: String): List<DoubleArray> {
        val data = mutableListOf<DoubleArray>()
        try {
            val inputStream = context.assets.open(fileName)
            val reader = BufferedReader(InputStreamReader(inputStream))
            
            // Skip header
            reader.readLine() 
            
            var line: String? = reader.readLine()
            while (line != null) {
                val values = line.split(",").map { it.toDouble() }.toDoubleArray()
                data.add(values)
                line = reader.readLine()
            }
            reader.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return data
    }
}
