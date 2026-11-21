package com.openvireo.core.hosts

import android.util.Log
import com.openvireo.core.Level
import com.openvireo.core.LogSink

/**
 * A [LogSink] that writes the core's log lines to logcat (`android.util.Log`) under one [tag], with
 * the core module first: `[ov_sync] pulled 3 changes`. Filter with `adb logcat -s OpenVireo`. Levels:
 * error → ERROR, warn → WARN, info → INFO, debug → DEBUG, trace → VERBOSE; lines below [minLevel] are
 * dropped (default: everything). The core never logs secrets.
 */
public class AndroidLogSink @JvmOverloads constructor(
    private val tag: String = "OpenVireo",
    private val minLevel: Level = Level.TRACE,
) : LogSink {
    override fun log(level: Level, target: String, msg: String) {
        if (level.ordinal > minLevel.ordinal) return
        val priority = when (level) {
            Level.ERROR -> Log.ERROR
            Level.WARN -> Log.WARN
            Level.INFO -> Log.INFO
            Level.DEBUG -> Log.DEBUG
            Level.TRACE -> Log.VERBOSE
        }
        Log.println(priority, tag, "[$target] $msg")
    }
}
