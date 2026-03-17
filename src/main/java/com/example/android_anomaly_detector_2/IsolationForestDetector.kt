package com.example.android_anomaly_detector_2

import com.google.gson.*
import java.lang.reflect.Type
import java.util.Random

class IsolationForestDetector(private val numTrees: Int = 100, private val sampleLimit: Int = 256) {

    private var forest: List<ITree>? = null
    private val random = Random()
    private var internalSampleSize: Int = 0

    fun train(data: List<DoubleArray>) {
        if (data.isEmpty()) return
        internalSampleSize = minOf(sampleLimit, data.size)
        val trees = mutableListOf<ITree>()
        val maxHeight = Math.ceil(Math.log(internalSampleSize.toDouble()) / Math.log(2.0)).toInt()

        for (i in 0 until numTrees) {
            val sampledData = data.shuffled(random).take(internalSampleSize)
            trees.add(buildTree(sampledData, 0, maxHeight))
        }
        forest = trees
    }

    fun getAnomalyScore(point: DoubleArray): Double {
        val forest = forest ?: return 0.0
        if (internalSampleSize <= 1) return 0.0
        val averagePathLength = forest.map { pathLength(point, it, 0) }.average()
        return Math.pow(2.0, - (averagePathLength / c(internalSampleSize.toDouble())))
    }

    private fun pathLength(point: DoubleArray, tree: ITree, currentPathLength: Int): Double {
        return when (tree) {
            is ExternalNode -> currentPathLength + c(tree.size.toDouble())
            is InternalNode -> {
                if (tree.splitAttribute >= point.size) return currentPathLength.toDouble()
                if (point[tree.splitAttribute] < tree.splitValue) {
                    pathLength(point, tree.left, currentPathLength + 1)
                } else {
                    pathLength(point, tree.right, currentPathLength + 1)
                }
            }
        }
    }

    private fun buildTree(data: List<DoubleArray>, currentHeight: Int, maxHeight: Int): ITree {
        if (currentHeight >= maxHeight || data.size <= 1) {
            return ExternalNode(data.size)
        }
        val numAttributes = data[0].size
        val splitAttribute = random.nextInt(numAttributes)
        val min = data.minOf { it[splitAttribute] }
        val max = data.maxOf { it[splitAttribute] }
        if (min == max) return ExternalNode(data.size)

        val splitValue = min + random.nextDouble() * (max - min)
        val leftData = data.filter { it[splitAttribute] < splitValue }
        val rightData = data.filter { it[splitAttribute] >= splitValue }

        return InternalNode(
            splitAttribute,
            splitValue,
            buildTree(leftData, currentHeight + 1, maxHeight),
            buildTree(rightData, currentHeight + 1, maxHeight)
        )
    }

    private fun c(n: Double): Double {
        if (n <= 1.0) return 0.0
        if (n == 2.0) return 1.0
        val eulerGamma = 0.5772156649
        val h = Math.log(n - 1) + eulerGamma
        return 2.0 * h - (2.0 * (n - 1) / n)
    }

    fun serialize(): String {
        val gson = GsonBuilder().registerTypeAdapter(ITree::class.java, ITreeAdapter()).create()
        val wrapper = ForestWrapper(forest ?: emptyList(), internalSampleSize)
        return gson.toJson(wrapper)
    }

    fun deserialize(json: String) {
        try {
            val gson = GsonBuilder().registerTypeAdapter(ITree::class.java, ITreeAdapter()).create()
            val wrapper = gson.fromJson(json, ForestWrapper::class.java)
            if (wrapper != null) {
                this.forest = wrapper.forest
                this.internalSampleSize = wrapper.internalSampleSize
            }
        } catch (e: Exception) {
            throw Exception("Deserialization failed: ${e.message}")
        }
    }

    data class ForestWrapper(val forest: List<ITree>, val internalSampleSize: Int)

    sealed interface ITree
    class InternalNode(val splitAttribute: Int, val splitValue: Double, val left: ITree, val right: ITree) : ITree
    class ExternalNode(val size: Int) : ITree

    class ITreeAdapter : JsonSerializer<ITree>, JsonDeserializer<ITree> {
        override fun serialize(src: ITree, typeOfSrc: Type, context: JsonSerializationContext): JsonElement {
            val jsonObject = JsonObject()
            when (src) {
                is InternalNode -> {
                    jsonObject.addProperty("type", "internal")
                    jsonObject.addProperty("splitAttribute", src.splitAttribute)
                    jsonObject.addProperty("splitValue", src.splitValue)
                    jsonObject.add("left", context.serialize(src.left, ITree::class.java))
                    jsonObject.add("right", context.serialize(src.right, ITree::class.java))
                }
                is ExternalNode -> {
                    jsonObject.addProperty("type", "external")
                    jsonObject.addProperty("size", src.size)
                }
            }
            return jsonObject
        }

        override fun deserialize(json: JsonElement, typeOfT: Type, context: JsonDeserializationContext): ITree {
            val obj = json.asJsonObject
            
            // BULLETPROOF LOGIC: Infer type if the field is missing
            val typeElement = obj.get("type") ?: obj.get("nodeType") ?: obj.get("t")
            val typeStr = typeElement?.asString

            return if (typeStr == "internal" || typeStr == "i" || obj.has("splitAttribute") || obj.has("a")) {
                InternalNode(
                    (obj.get("splitAttribute") ?: obj.get("a")).asInt,
                    (obj.get("splitValue") ?: obj.get("v")).asDouble,
                    context.deserialize(obj.get("left") ?: obj.get("l"), ITree::class.java),
                    context.deserialize(obj.get("right") ?: obj.get("r"), ITree::class.java)
                )
            } else {
                ExternalNode((obj.get("size") ?: obj.get("s") ?: obj.get("size") ?: JsonPrimitive(0)).asInt)
            }
        }
    }
}
