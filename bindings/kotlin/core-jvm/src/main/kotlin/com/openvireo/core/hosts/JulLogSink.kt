package com.openvireo.core.hosts

import com.openvireo.core.Level
import com.openvireo.core.LogSink
import java.util.logging.Logger
import java.util.logging.Level as JulLevel

/**
 * A [LogSink] that forwards the core's log lines to `java.util.logging`, on the logger
 * `<baseName>.<target>` (`openvireo.ov_sync`, ...), so they can be filtered per module or bridged to
 * SLF4J/Log4j with the usual JUL bridges. Levels: error → SEVERE, warn → WARNING, info → INFO,
 * debug → FINE, trace → FINER. The core never logs secrets.
 */
public class JulLogSink @JvmOverloads constructor(private val baseName: String = "openvireo") : LogSink {
    override fun log(level: Level, target: String, msg: String) {
        val logger = Logger.getLogger("$baseName.${target.replace("::", ".")}")
        val jul = when (level) {
            Level.ERROR -> JulLevel.SEVERE
            Level.WARN -> JulLevel.WARNING
            Level.INFO -> JulLevel.INFO
            Level.DEBUG -> JulLevel.FINE
            Level.TRACE -> JulLevel.FINER
        }
        if (logger.isLoggable(jul)) logger.logp(jul, target, null, msg)
    }
}
