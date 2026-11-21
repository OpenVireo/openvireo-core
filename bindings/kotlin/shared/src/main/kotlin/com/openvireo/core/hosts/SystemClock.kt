package com.openvireo.core.hosts

import com.openvireo.core.Clock

/** Wall-clock time from `System.currentTimeMillis()`. */
public object SystemClock : Clock {
    override fun nowUnixMs(): Long = System.currentTimeMillis()
}
