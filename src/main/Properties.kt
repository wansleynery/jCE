package main

import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import kotlin.collections.iterator

object Properties {

    private val props = java.util.Properties()

    init {
        load ("locale/ptBR.properties")
    }

    private fun load (
        resourcePath: String
    ) {
        val stream = Properties::class.java.classLoader.getResourceAsStream (resourcePath)
            ?: error ("Resource '$resourcePath' not found on classpath (move to src/main/resources).")

        InputStreamReader (stream, StandardCharsets.UTF_8).use { reader ->
            props.load (reader)
        }
    }

    fun get (
        key: String,
        vars: Map <String, String> = emptyMap ()
    ): String {

        val raw = props.getProperty (key) ?: return "!!$key!!"
        var out = raw

        for ((k, v) in vars) {
            out = out.replace ("$$k", v) // substitui $processName, etc.
        }

        return out

    }

}